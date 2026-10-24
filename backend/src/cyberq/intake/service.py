"""Intake Pipeline Service: End-to-end ingestion, PII stripping, dead-letter routing,

Tool Compliance Passport validation, and statutory CERT-In incident binding.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from cyberq.audit.chain import AuditService
from cyberq.clocks.worker import emit_clock_wakeup
from cyberq.core.pii_guard import scan_and_redact
from cyberq.incidents.models import Incident
from cyberq.incidents.service import create_incident
from cyberq.intake.certin_mapping import correlate_certin_reportability
from cyberq.intake.models import (
    IntakeDeadLetter,
    NormalizedSecurityEvent,
    ToolCompliancePassport,
)
from cyberq.intake.parser import parse_cef_syslog, parse_json_event
from cyberq.intake.verifier import verify_webhook_hmac


class IntakePipelineService:
    def __init__(self, audit: AuditService) -> None:
        self.audit = audit

    def _check_json_depth(self, obj: object, depth: int = 0, max_depth: int = 32) -> None:
        """Guard against deeply nested JSON payloads that could exhaust stack."""
        if depth > max_depth:
            raise ValueError(f"JSON nesting depth exceeds maximum of {max_depth}")
        if isinstance(obj, dict):
            for v in obj.values():
                self._check_json_depth(v, depth + 1, max_depth)
        elif isinstance(obj, list):
            for item in obj:
                self._check_json_depth(item, depth + 1, max_depth)

    def ingest_webhook(
        self,
        session: Session,
        tool_identifier: str,
        raw_body: bytes,
        headers: dict[str, str],
        client_ip: str | None = None,
        secret_key: str | None = None,
        system_user_id: str = "system-intake-agent",
    ) -> tuple[NormalizedSecurityEvent, Incident | None]:
        """Ingests, authenticates, normalizes, and routes an incoming bank security webhook."""
        now = datetime.now(UTC)

        # 1. HMAC-SHA256 signature verification if secret is configured
        if secret_key:
            sig = headers.get("x-cyberq-signature", "")
            ts = headers.get("x-cyberq-timestamp", "")
            nonce = headers.get("x-cyberq-nonce")
            valid_hmac, hmac_reason = verify_webhook_hmac(
                payload_bytes=raw_body,
                secret_key=secret_key,
                signature_header=sig,
                timestamp_header=ts,
                nonce_header=nonce,
                now=now,
            )
            if not valid_hmac:
                # Write to Dead-Letter Queue
                redacted_body = str(scan_and_redact(raw_body.decode("utf-8", errors="replace"))["clean_text"])
                dl = IntakeDeadLetter(
                    id=str(uuid.uuid4()),
                    received_at=now,
                    source_tool=tool_identifier,
                    source_ip=client_ip,
                    headers=headers,
                    raw_payload_redacted=redacted_body,
                    error_reason=f"HMAC Authentication Failure: {hmac_reason}",
                    status="unresolved",
                )
                session.add(dl)
                session.flush()
                raise PermissionError(f"Intake rejected: {hmac_reason}")

        # 2. PII Ingestion Guard: Strip Aadhaar, PAN, and Cards before memory parsing
        body_text = raw_body.decode("utf-8", errors="replace")
        pii_res = scan_and_redact(body_text)
        redacted_text = str(pii_res["clean_text"])

        # 3. Payload Parsing & Dead-Letter Routing
        normalized_event: NormalizedSecurityEvent
        try:
            if body_text.strip().startswith("CEF:"):
                normalized_event = parse_cef_syslog(redacted_text)
            else:
                parsed_json = json.loads(redacted_text)
                if not isinstance(parsed_json, dict):
                    raise ValueError("JSON webhook payload must be an object")
                # Guard against deeply nested JSON DoS
                self._check_json_depth(parsed_json)
                normalized_event = parse_json_event(tool_identifier, parsed_json)
        except Exception as parse_err:
            # Dead-Letter routing on malformed payloads
            dl = IntakeDeadLetter(
                id=str(uuid.uuid4()),
                received_at=now,
                source_tool=tool_identifier,
                source_ip=client_ip,
                headers=headers,
                raw_payload_redacted=redacted_text,
                error_reason=f"Parser Error: {str(parse_err)}",
                status="unresolved",
            )
            session.add(dl)
            session.flush()
            raise ValueError(f"Malformed intake payload routed to Dead-Letter Queue: {parse_err}") from parse_err

        # 4. Tool Compliance Passport Validation (RBI Paras 90, 92, 126-135)
        passport = session.scalar(
            select(ToolCompliancePassport).where(ToolCompliancePassport.tool_id == tool_identifier)
        )
        is_unverified = False
        if passport:
            if passport.vapt_valid_until < now:
                passport.trust_status = "DEGRADED"
                passport.para59_exception_ref = f"EXC-VAPT-EXPIRED-{tool_identifier}-{now.strftime('%Y%m%d')}"
                is_unverified = True
                session.flush()

        # Update event with unverified flag if applicable
        if is_unverified:
            normalized_event = normalized_event.model_copy(update={"is_telemetry_unverified": True})

        # 5. Primary CERT-In Advisory Correlation
        is_reportable, matched_advisories, recommended_sev = correlate_certin_reportability(
            raw_text=normalized_event.raw_message,
            cve_ids=normalized_event.cve_ids,
            signature_name=normalized_event.event_name,
        )
        if matched_advisories:
            normalized_event = normalized_event.model_copy(
                update={"certin_advisories": matched_advisories}
            )

        # 6. Automatic Incident Creation under Provisional Triage for high/critical threats
        created_incident: Incident | None = None
        if is_reportable or normalized_event.severity in ("high", "critical"):
            summary_text = (
                f"Automated Alert from {normalized_event.source_tool} ({normalized_event.event_name}). "
                f"Message: {normalized_event.raw_message}."
            )
            if matched_advisories:
                summary_text += f" Matched CERT-In Advisories: {', '.join(matched_advisories)}."
            if is_unverified:
                summary_text += " [UNVERIFIED_TELEMETRY: Source tool VAPT certificate expired under RBI Para 90]."

            created_incident = create_incident(
                session=session,
                audit=self.audit,
                title=f"Intake Alert: {normalized_event.event_name} ({normalized_event.vendor})",
                summary=summary_text,
                severity=recommended_sev if recommended_sev in ("high", "critical") else normalized_event.severity,
                actor_id=system_user_id,
                actor_role="analyst",
                client_ip=client_ip,
                request_id=headers.get("x-request-id"),
            )
            created_incident.status = "new"

            # Record infrastructure IPs and Hostnames in incident
            server_ips: list[str] = []
            if normalized_event.source_ip:
                server_ips.append(normalized_event.source_ip)
            if normalized_event.destination_ip:
                server_ips.append(normalized_event.destination_ip)

            # Wake up regulatory clocks worker immediately via sub-5ms NOTIFY
            emit_clock_wakeup(session)

        # 7. Audit Logging
        self.audit.record_event(
            session=session,
            actor_id=system_user_id,
            actor_role="analyst",
            action="intake:event_ingested",
            entity_type="intake_event",
            entity_id=normalized_event.event_id,
            client_ip=client_ip,
            request_id=headers.get("x-request-id"),
            after_state={
                "event_id": normalized_event.event_id,
                "tool": normalized_event.source_tool,
                "severity": normalized_event.severity,
                "is_reportable": is_reportable,
                "certin_advisories": matched_advisories,
                "is_unverified": is_unverified,
                "incident_id": created_incident.id if created_incident else None,
            },
            stream_id=created_incident.id if created_incident else None,
        )

        return normalized_event, created_incident
