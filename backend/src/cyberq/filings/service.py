"""Statutory Filing Service: Generation, Maker-Checker Approvals, Step-Up MFA, Break-Glass, and Portal Acknowledgements."""

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from cyberq.audit.chain import AuditService, compute_event_hash
from cyberq.audit.crypto import KeyProvider
from cyberq.clocks.models import ObligationInstance
from cyberq.filings.generator import (
    generate_certin_packet,
    generate_dpdp_packet,
    generate_rbi_daksh_packet,
)
from cyberq.filings.mfa import validate_break_glass_eligibility, verify_totp_code
from cyberq.filings.models import FilingPacket
from cyberq.iam.policy import Action, PolicyEngine, Role
from cyberq.incidents.models import Incident, IncidentTrigger


class FilingService:
    def __init__(self, audit: AuditService, key_provider: KeyProvider | None = None) -> None:
        self.audit = audit
        self.key_provider = key_provider or audit._key_provider

    def prepare_packet(
        self,
        session: Session,
        incident_id: str,
        pack_id: str,
        regulator: str,
        prepared_by_id: str,
        prepared_by_role: str,
        client_ip: str | None = None,
        request_id: str | None = None,
        custom_fields: dict[str, Any] | None = None,
    ) -> FilingPacket:
        """Prepares a statutory filing packet (Maker action)."""
        if not PolicyEngine.is_allowed(prepared_by_role, Action.PACKET_PREPARE):
            raise PermissionError(f"Role '{prepared_by_role}' is not authorized to prepare filing packets")

        incident = session.scalar(select(Incident).where(Incident.id == incident_id))
        if incident is None:
            raise ValueError(f"Incident {incident_id} not found")

        trigger = session.scalar(
            select(IncidentTrigger)
            .where(IncidentTrigger.incident_id == incident_id)
            .order_by(IncidentTrigger.occurred_at.asc())
        )
        occurred_at = trigger.occurred_at if trigger else incident.created_at

        # Generate structured statutory packet data
        packet_data: dict[str, Any]
        if regulator.upper() == "CERT-IN":
            packet_data = generate_certin_packet(
                incident_number=incident.incident_number,
                title=incident.title,
                summary=incident.summary,
                severity=incident.severity,
                occurred_at=occurred_at,
            )
        elif regulator.upper() == "RBI":
            packet_data = generate_rbi_daksh_packet(
                incident_number=incident.incident_number,
                title=incident.title,
                summary=incident.summary,
                severity=incident.severity,
                occurred_at=occurred_at,
            )
        elif regulator.upper() == "DPDP":
            packet_data = generate_dpdp_packet(
                incident_number=incident.incident_number,
                summary=incident.summary,
                occurred_at=occurred_at,
            )
        else:
            packet_data = {"regulator": regulator, "incident_number": incident.incident_number, "summary": incident.summary}

        if custom_fields:
            packet_data.update(custom_fields)

        # Canonical hash
        packet_hash = compute_event_hash(packet_data, "0" * 64)

        # Get existing version number
        existing_count = session.scalar(
            select(FilingPacket).where(
                FilingPacket.incident_id == incident_id,
                FilingPacket.regulator == regulator,
            )
        )
        version_num = 1 if existing_count is None else 2

        packet = FilingPacket(
            id=str(uuid.uuid4()),
            incident_id=incident_id,
            pack_id=pack_id,
            regulator=regulator,
            version=version_num,
            status="draft",
            packet_data=packet_data,
            packet_hash=packet_hash,
            prepared_by_id=prepared_by_id,
            prepared_at=datetime.now(UTC),
        )
        session.add(packet)
        session.flush()

        self.audit.record_event(
            session=session,
            actor_id=prepared_by_id,
            actor_role=prepared_by_role,
            action="packet:prepare",
            entity_type="filing_packet",
            entity_id=packet.id,
            client_ip=client_ip,
            request_id=request_id,
            after_state={"packet_id": packet.id, "regulator": regulator, "hash": packet_hash},
            stream_id=incident_id,
        )
        return packet

    def approve_packet(
        self,
        session: Session,
        packet_id: str,
        approver_id: str,
        approver_role: str,
        approver_dept: str = "Compliance & Regulatory Affairs",
        otp_code: str | None = None,
        totp_secret: str | None = None,
        is_break_glass: bool = False,
        break_glass_reason: str | None = None,
        elapsed_minutes: float = 45.0,
        remaining_minutes: float = 60.0,
        client_ip: str | None = None,
        request_id: str | None = None,
    ) -> FilingPacket:
        """Approves a statutory filing packet under strict Maker-Checker and Step-Up MFA."""
        if not PolicyEngine.is_allowed(approver_role, Action.PACKET_APPROVE):
            raise PermissionError(f"Role '{approver_role}' is not authorized to approve filing packets")

        packet = session.scalar(select(FilingPacket).where(FilingPacket.id == packet_id))
        if packet is None:
            raise ValueError(f"Filing packet {packet_id} not found")

        if packet.status != "draft":
            raise ValueError(f"Cannot approve packet with status '{packet.status}'. Only 'draft' packets can be approved.")

        # 1. Maker-Checker validation
        if not PolicyEngine.check_maker_checker(packet.prepared_by_id, approver_id):
            raise ValueError(
                f"Maker-Checker violation: Preparer ({packet.prepared_by_id}) cannot approve their own statutory filing packet"
            )

        # 2. Tamper check: Re-verify packet_hash against packet_data
        computed_hash = compute_event_hash(packet.packet_data, "0" * 64)
        if computed_hash != packet.packet_hash:
            raise ValueError("Integrity failure: Filing packet data has been modified since preparation")

        now = datetime.now(UTC)

        # 3. Step-Up MFA & Break-Glass validation
        if is_break_glass:
            if not break_glass_reason:
                raise ValueError("Break-Glass protocol requires a mandatory justification")
            eligible, reason_msg = validate_break_glass_eligibility(
                elapsed_minutes=elapsed_minutes,
                remaining_minutes=remaining_minutes,
                reason=break_glass_reason,
            )
            if not eligible:
                raise ValueError(f"Break-Glass rejected: {reason_msg}")

            packet.is_break_glass = True
            packet.break_glass_reason = break_glass_reason
            packet.break_glass_countersignature_required_by = now + timedelta(hours=24)
        else:
            # Standard Step-Up MFA verification
            if not otp_code or not totp_secret:
                raise ValueError("Step-up MFA TOTP code and secret are required for standard statutory packet approval")
            if not verify_totp_code(totp_secret, otp_code):
                raise PermissionError("Step-up MFA authentication failed: Invalid TOTP verification code")

        # 4. Cryptographic signature binding packet hash
        sig_bytes = self.key_provider.sign(packet.packet_hash.encode("ascii"))
        packet.approval_signature = sig_bytes.hex()
        packet.approved_by_id = approver_id
        packet.approved_at = now
        packet.status = "approved"
        session.flush()

        self.audit.record_event(
            session=session,
            actor_id=approver_id,
            actor_role=approver_role,
            action="packet:approve",
            entity_type="filing_packet",
            entity_id=packet.id,
            client_ip=client_ip,
            request_id=request_id,
            after_state={
                "packet_id": packet.id,
                "approver_id": approver_id,
                "is_break_glass": is_break_glass,
                "approval_signature": packet.approval_signature[:32] + "...",
            },
            stream_id=packet.incident_id,
        )
        return packet

    def countersign_break_glass(
        self,
        session: Session,
        packet_id: str,
        countersigner_id: str,
        countersigner_role: str,
        countersigner_dept: str,
        approver_dept: str = "Compliance & Regulatory Affairs",
        client_ip: str | None = None,
        request_id: str | None = None,
    ) -> FilingPacket:
        """Executes the mandatory 24-hour retrospective countersignature for a Break-Glass approval."""
        if countersigner_role not in (Role.CISO.value, Role.COMPLIANCE_APPROVER.value):
            raise PermissionError(f"Role '{countersigner_role}' cannot countersign Break-Glass approvals")

        packet = session.scalar(select(FilingPacket).where(FilingPacket.id == packet_id))
        if packet is None:
            raise ValueError(f"Filing packet {packet_id} not found")

        if not packet.is_break_glass:
            raise ValueError(f"Packet {packet_id} was not approved under the Break-Glass protocol")

        if packet.break_glass_countersigned_by_id is not None:
            raise ValueError(f"Packet {packet_id} has already been countersigned")

        # Independent countersigner check
        if not PolicyEngine.check_maker_checker(packet.approved_by_id or "", countersigner_id):
            raise ValueError("Countersignature violation: The Break-Glass approver cannot countersign their own override")

        # Department separation
        if countersigner_dept.strip().lower() == approver_dept.strip().lower():
            raise ValueError("Department separation violation: Countersigner must belong to an independent department")

        now = datetime.now(UTC)
        if packet.break_glass_countersignature_required_by and now > packet.break_glass_countersignature_required_by:
            raise ValueError("Countersignature window expired: Retrospective countersignature must occur within 24 hours")

        packet.break_glass_countersigned_by_id = countersigner_id
        packet.break_glass_countersigned_at = now
        session.flush()

        self.audit.record_event(
            session=session,
            actor_id=countersigner_id,
            actor_role=countersigner_role,
            action="packet:break_glass_countersigned",
            entity_type="filing_packet",
            entity_id=packet.id,
            client_ip=client_ip,
            request_id=request_id,
            after_state={
                "packet_id": packet.id,
                "countersigner_id": countersigner_id,
                "countersigned_at": now.isoformat(),
            },
            stream_id=packet.incident_id,
        )
        return packet

    def record_portal_outage(
        self,
        session: Session,
        packet_id: str,
        filer_id: str,
        filer_role: str,
        outage_notes: str,
        client_ip: str | None = None,
        request_id: str | None = None,
    ) -> FilingPacket:
        """Records regulator portal downtime (504/timeout) and HSM-seals timely statutory readiness."""
        if not PolicyEngine.is_allowed(filer_role, Action.PACKET_RECORD_FILED):
            raise PermissionError(f"Role '{filer_role}' cannot record portal outage fallback")

        packet = session.scalar(select(FilingPacket).where(FilingPacket.id == packet_id))
        if packet is None:
            raise ValueError(f"Filing packet {packet_id} not found")

        if packet.status != "approved":
            raise ValueError(f"Only approved packets can enter portal outage fallback (current: {packet.status})")

        packet.status = "portal_outage_fallback"
        packet.portal_outage_sealed = True
        packet.portal_outage_notes = outage_notes
        session.flush()

        self.audit.record_event(
            session=session,
            actor_id=filer_id,
            actor_role=filer_role,
            action="packet:portal_outage_sealed",
            entity_type="filing_packet",
            entity_id=packet.id,
            client_ip=client_ip,
            request_id=request_id,
            after_state={
                "packet_id": packet.id,
                "regulator": packet.regulator,
                "outage_notes": outage_notes,
                "sealed_at": datetime.now(UTC).isoformat(),
            },
            stream_id=packet.incident_id,
        )
        return packet

    def record_acknowledgement(
        self,
        session: Session,
        packet_id: str,
        filer_id: str,
        filer_role: str,
        acknowledgement_ref: str,
        portal_name: str = "Regulator Portal",
        client_ip: str | None = None,
        request_id: str | None = None,
    ) -> FilingPacket:
        """Records official portal submission acknowledgment receipt (Human-in-the-loop filing)."""
        if not PolicyEngine.is_allowed(filer_role, Action.PACKET_RECORD_FILED):
            raise PermissionError(f"Role '{filer_role}' cannot record portal acknowledgements")

        clean_ref = acknowledgement_ref.strip()
        if not clean_ref:
            raise ValueError("Acknowledgement reference cannot be empty")

        packet = session.scalar(select(FilingPacket).where(FilingPacket.id == packet_id))
        if packet is None:
            raise ValueError(f"Filing packet {packet_id} not found")

        if packet.status not in ("approved", "portal_outage_fallback"):
            raise ValueError(f"Cannot file packet with status '{packet.status}'. Must be 'approved' or 'portal_outage_fallback'.")

        now = datetime.now(UTC)

        # Enforce Break-Glass 24-hour retrospective countersignature rule
        if packet.is_break_glass and packet.break_glass_countersigned_by_id is None:
            if packet.break_glass_countersignature_required_by and now > packet.break_glass_countersignature_required_by:
                raise ValueError(
                    "Statutory breach: Emergency Break-Glass approval expired without required 24-hour retrospective countersignature"
                )

        packet.status = "filed"
        packet.filed_at = now
        packet.filed_by_id = filer_id
        packet.acknowledgement_ref = clean_ref

        # Update obligation instance status to filed
        obl = session.scalar(
            select(ObligationInstance).where(
                ObligationInstance.incident_id == packet.incident_id,
                ObligationInstance.pack_id == packet.pack_id,
            )
        )
        if obl:
            obl.status = "filed"
            obl.next_due_at = None

        session.flush()

        self.audit.record_event(
            session=session,
            actor_id=filer_id,
            actor_role=filer_role,
            action="packet:record_filed",
            entity_type="filing_packet",
            entity_id=packet.id,
            client_ip=client_ip,
            request_id=request_id,
            after_state={
                "packet_id": packet.id,
                "regulator": packet.regulator,
                "acknowledgement_ref": clean_ref,
                "portal_name": portal_name,
                "filed_at": now.isoformat(),
            },
            stream_id=packet.incident_id,
        )
        return packet
