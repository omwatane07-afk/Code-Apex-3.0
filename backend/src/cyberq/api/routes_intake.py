"""FastAPI routes for High-Throughput Ingestion, Dead-Letter Queue, and Tool Compliance Passports."""

from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from cyberq.api.deps import get_audit_service, require_permission
from cyberq.audit.chain import AuditService
from cyberq.core.database import get_db
from cyberq.intake.models import IntakeDeadLetter, ToolCompliancePassport
from cyberq.intake.service import IntakePipelineService
from cyberq.iam.policy import Action, AuthContext

router = APIRouter(prefix="/intake", tags=["High-Throughput Intake"])


class ToolPassportCreateRequest(BaseModel):
    tool_id: str
    tool_name: str
    vendor: str
    category: str
    stqc_certificate_ref: str
    auditor_name: str
    vapt_valid_from: datetime
    vapt_valid_until: datetime
    pades_signature_hash: str
    cyclonedx_sbom_digest: str


@router.post("/webhook", status_code=status.HTTP_201_CREATED)
async def ingest_tool_webhook_query(
    request: Request,
    tool_id: str = Query(default="tool-siem-splunk"),
    session: Session = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
    x_cyberq_signature: str | None = Header(None, alias="X-CyberQ-Signature"),
    x_cyberq_timestamp: str | None = Header(None, alias="X-CyberQ-Timestamp"),
    x_cyberq_nonce: str | None = Header(None, alias="X-CyberQ-Nonce"),
) -> dict[str, Any]:
    """Ingests security alert webhooks with tool_id passed as query parameter."""
    return await ingest_tool_webhook(
        tool_id=tool_id,
        request=request,
        session=session,
        audit=audit,
        x_cyberq_signature=x_cyberq_signature,
        x_cyberq_timestamp=x_cyberq_timestamp,
        x_cyberq_nonce=x_cyberq_nonce,
    )


@router.post("/webhook/{tool_id}", status_code=status.HTTP_201_CREATED)
async def ingest_tool_webhook(
    tool_id: str,
    request: Request,
    session: Session = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
    x_cyberq_signature: str | None = Header(None, alias="X-CyberQ-Signature"),
    x_cyberq_timestamp: str | None = Header(None, alias="X-CyberQ-Timestamp"),
    x_cyberq_nonce: str | None = Header(None, alias="X-CyberQ-Nonce"),
) -> dict[str, Any]:
    """Ingests security alert webhooks or Syslog CEF streams for 20+ enterprise banking tools."""
    raw_body = await request.body()
    if len(raw_body) > 2 * 1024 * 1024:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Webhook payload exceeds maximum allowable limit of 2MB",
        )

    headers: dict[str, str] = dict(request.headers)
    if x_cyberq_signature:
        headers["x-cyberq-signature"] = x_cyberq_signature
    if x_cyberq_timestamp:
        headers["x-cyberq-timestamp"] = x_cyberq_timestamp
    if x_cyberq_nonce:
        headers["x-cyberq-nonce"] = x_cyberq_nonce

    client_ip = request.client.host if request.client else "127.0.0.1"

    pipeline = IntakePipelineService(audit)
    try:
        event, incident = pipeline.ingest_webhook(
            session=session,
            tool_identifier=tool_id,
            raw_body=raw_body,
            headers=headers,
            client_ip=client_ip,
        )
        session.commit()
    except PermissionError as pe:
        session.commit()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(pe)) from pe
    except ValueError as ve:
        session.commit()
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(ve)) from ve

    return {
        "status": "ACCEPTED",
        "event_id": event.event_id,
        "source_tool": event.source_tool,
        "category": event.category,
        "severity": event.severity,
        "cve_ids": event.cve_ids,
        "certin_advisories": event.certin_advisories,
        "is_telemetry_unverified": event.is_telemetry_unverified,
        "incident_id": incident.id if incident else None,
        "incident_number": incident.incident_number if incident else None,
    }


@router.get("/dead-letter")
def list_dead_letters(
    session: Session = Depends(get_db),
    auth_ctx: AuthContext = Depends(require_permission(Action.AUDIT_READ)),
) -> list[dict[str, Any]]:
    """Lists dead-letter queue records for observation and red-team review."""
    records = list(
        session.scalars(select(IntakeDeadLetter).order_by(IntakeDeadLetter.received_at.desc()).limit(50)).all()
    )
    return [
        {
            "id": r.id,
            "received_at": r.received_at.isoformat(),
            "source_tool": r.source_tool,
            "source_ip": r.source_ip,
            "error_reason": r.error_reason,
            "status": r.status,
            "raw_payload_preview": r.raw_payload_redacted[:200],
        }
        for r in records
    ]


@router.get("/compliance-passports")
def list_compliance_passports(
    session: Session = Depends(get_db),
    auth_ctx: AuthContext = Depends(require_permission(Action.INCIDENT_READ)),
) -> list[dict[str, Any]]:
    """Returns all registered third-party tool compliance passports and VAPT validity status."""
    passports = list(
        session.scalars(select(ToolCompliancePassport).order_by(ToolCompliancePassport.tool_name.asc())).all()
    )
    return [
        {
            "tool_id": p.tool_id,
            "tool_name": p.tool_name,
            "vendor": p.vendor,
            "category": p.category,
            "stqc_certificate_ref": p.stqc_certificate_ref,
            "auditor_name": p.auditor_name,
            "vapt_valid_until": p.vapt_valid_until.isoformat(),
            "pades_signature_hash": p.pades_signature_hash,
            "cyclonedx_sbom_digest": p.cyclonedx_sbom_digest,
            "trust_status": p.trust_status,
            "para59_exception_ref": p.para59_exception_ref,
        }
        for p in passports
    ]


@router.post("/compliance-passports", status_code=status.HTTP_201_CREATED)
def register_tool_passport(
    payload: ToolPassportCreateRequest,
    session: Session = Depends(get_db),
    auth_ctx: AuthContext = Depends(require_permission(Action.ADMIN_CONFIG)),
) -> dict[str, Any]:
    """Registers or updates a tool compliance passport."""
    now = datetime.now(UTC)
    status_str = "VALID" if payload.vapt_valid_until >= now else "EXPIRED"

    passport = session.scalar(
        select(ToolCompliancePassport).where(ToolCompliancePassport.tool_id == payload.tool_id)
    )
    if passport is None:
        passport = ToolCompliancePassport(
            tool_id=payload.tool_id,
            tool_name=payload.tool_name,
            vendor=payload.vendor,
            category=payload.category,
            stqc_certificate_ref=payload.stqc_certificate_ref,
            auditor_name=payload.auditor_name,
            vapt_valid_from=payload.vapt_valid_from,
            vapt_valid_until=payload.vapt_valid_until,
            pades_signature_hash=payload.pades_signature_hash,
            cyclonedx_sbom_digest=payload.cyclonedx_sbom_digest,
            trust_status=status_str,
        )
        session.add(passport)
    else:
        passport.tool_name = payload.tool_name
        passport.vendor = payload.vendor
        passport.category = payload.category
        passport.stqc_certificate_ref = payload.stqc_certificate_ref
        passport.auditor_name = payload.auditor_name
        passport.vapt_valid_from = payload.vapt_valid_from
        passport.vapt_valid_until = payload.vapt_valid_until
        passport.pades_signature_hash = payload.pades_signature_hash
        passport.cyclonedx_sbom_digest = payload.cyclonedx_sbom_digest
        passport.trust_status = status_str

    session.commit()
    return {"status": "REGISTERED", "tool_id": passport.tool_id, "trust_status": passport.trust_status}
