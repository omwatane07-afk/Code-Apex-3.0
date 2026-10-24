"""FastAPI routes for Statutory Filing Packets, Maker-Checker Approvals, Break-Glass, and PDF Export."""

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from cyberq.api.deps import get_audit_service, get_current_session, require_permission
from cyberq.audit.chain import AuditService
from cyberq.core.database import get_db
from cyberq.filings.models import FilingPacket
from cyberq.filings.pdf import generate_filing_pdf
from cyberq.filings.service import FilingService
from cyberq.iam.models import UserSession
from cyberq.iam.policy import Action, AuthContext

router = APIRouter(prefix="/filings", tags=["Statutory Filings"])


class PreparePacketRequest(BaseModel):
    incident_id: str
    pack_id: str
    regulator: str
    custom_fields: dict[str, Any] | None = None


class ApprovePacketRequest(BaseModel):
    otp_code: str | None = None
    totp_secret: str | None = None
    is_break_glass: bool = False
    break_glass_reason: str | None = None
    elapsed_minutes: float = 45.0
    remaining_minutes: float = 60.0
    approver_dept: str = "Compliance & Regulatory Affairs"


class CountersignRequest(BaseModel):
    countersigner_dept: str
    approver_dept: str = "Compliance & Regulatory Affairs"


class PortalOutageRequest(BaseModel):
    outage_notes: str


class RecordFiledRequest(BaseModel):
    acknowledgement_ref: str
    portal_name: str = "Regulator Portal"


@router.get("")
def list_filing_packets(
    incident_id: str | None = Query(None),
    session: Session = Depends(get_db),
    auth_ctx: AuthContext = Depends(require_permission(Action.PACKET_READ)),
) -> list[dict[str, Any]]:
    """Returns statutory filing packets, optionally filtered by incident."""
    stmt = select(FilingPacket).order_by(FilingPacket.created_at.desc())
    if incident_id:
        stmt = stmt.where(FilingPacket.incident_id == incident_id)
    packets = list(session.scalars(stmt).all())
    return [
        {
            "id": p.id,
            "incident_id": p.incident_id,
            "pack_id": p.pack_id,
            "regulator": p.regulator,
            "version": p.version,
            "status": p.status,
            "packet_hash": p.packet_hash,
            "prepared_by_id": p.prepared_by_id,
            "prepared_at": p.prepared_at.isoformat(),
            "approved_by_id": p.approved_by_id,
            "approved_at": p.approved_at.isoformat() if p.approved_at else None,
            "is_break_glass": p.is_break_glass,
            "break_glass_countersigned": p.break_glass_countersigned_by_id is not None,
            "filed_at": p.filed_at.isoformat() if p.filed_at else None,
            "acknowledgement_ref": p.acknowledgement_ref,
            "portal_outage_sealed": p.portal_outage_sealed,
        }
        for p in packets
    ]


@router.post("/prepare", status_code=status.HTTP_201_CREATED)
def prepare_filing_packet(
    payload: PreparePacketRequest,
    session: Session = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
    current_session: UserSession = Depends(get_current_session),
) -> dict[str, Any]:
    """Prepares a new statutory filing packet (Maker action)."""
    filing_svc = FilingService(audit)
    try:
        packet = filing_svc.prepare_packet(
            session=session,
            incident_id=payload.incident_id,
            pack_id=payload.pack_id,
            regulator=payload.regulator,
            prepared_by_id=current_session.user_id,
            prepared_by_role=current_session.active_role,
            custom_fields=payload.custom_fields,
        )
        session.commit()
    except (ValueError, PermissionError) as e:
        session.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e

    return {
        "status": "PREPARED",
        "packet_id": packet.id,
        "regulator": packet.regulator,
        "packet_hash": packet.packet_hash,
    }


@router.post("/{packet_id}/approve")
def approve_filing_packet(
    packet_id: str,
    payload: ApprovePacketRequest,
    session: Session = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
    current_session: UserSession = Depends(get_current_session),
) -> dict[str, Any]:
    """Approves a filing packet under Maker-Checker and Step-Up MFA / Break-Glass."""
    filing_svc = FilingService(audit)
    try:
        packet = filing_svc.approve_packet(
            session=session,
            packet_id=packet_id,
            approver_id=current_session.user_id,
            approver_role=current_session.active_role,
            approver_dept=payload.approver_dept,
            otp_code=payload.otp_code,
            totp_secret=payload.totp_secret,
            is_break_glass=payload.is_break_glass,
            break_glass_reason=payload.break_glass_reason,
            elapsed_minutes=payload.elapsed_minutes,
            remaining_minutes=payload.remaining_minutes,
        )
        session.commit()
    except PermissionError as pe:
        session.rollback()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(pe)) from pe
    except ValueError as ve:
        session.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve)) from ve

    return {
        "status": "APPROVED",
        "packet_id": packet.id,
        "is_break_glass": packet.is_break_glass,
        "approval_signature": packet.approval_signature,
    }


@router.post("/{packet_id}/countersign")
def countersign_break_glass(
    packet_id: str,
    payload: CountersignRequest,
    session: Session = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
    current_session: UserSession = Depends(get_current_session),
) -> dict[str, Any]:
    """Retrospective 24h countersignature for Break-Glass approvals."""
    filing_svc = FilingService(audit)
    try:
        packet = filing_svc.countersign_break_glass(
            session=session,
            packet_id=packet_id,
            countersigner_id=current_session.user_id,
            countersigner_role=current_session.active_role,
            countersigner_dept=payload.countersigner_dept,
            approver_dept=payload.approver_dept,
        )
        session.commit()
    except (ValueError, PermissionError) as e:
        session.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e

    return {
        "status": "COUNTERSIGNED",
        "packet_id": packet.id,
        "countersigned_by_id": packet.break_glass_countersigned_by_id,
    }


@router.post("/{packet_id}/outage")
def record_portal_outage(
    packet_id: str,
    payload: PortalOutageRequest,
    session: Session = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
    current_session: UserSession = Depends(get_current_session),
) -> dict[str, Any]:
    """Records regulator portal downtime (504/timeout) and HSM-seals timely readiness."""
    filing_svc = FilingService(audit)
    try:
        packet = filing_svc.record_portal_outage(
            session=session,
            packet_id=packet_id,
            filer_id=current_session.user_id,
            filer_role=current_session.active_role,
            outage_notes=payload.outage_notes,
        )
        session.commit()
    except (ValueError, PermissionError) as e:
        session.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e

    return {
        "status": "PORTAL_OUTAGE_SEALED",
        "packet_id": packet.id,
        "portal_outage_sealed": True,
    }


@router.post("/{packet_id}/filed")
def record_acknowledgement(
    packet_id: str,
    payload: RecordFiledRequest,
    session: Session = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
    current_session: UserSession = Depends(get_current_session),
) -> dict[str, Any]:
    """Records human portal submission acknowledgement reference ID."""
    filing_svc = FilingService(audit)
    try:
        packet = filing_svc.record_acknowledgement(
            session=session,
            packet_id=packet_id,
            filer_id=current_session.user_id,
            filer_role=current_session.active_role,
            acknowledgement_ref=payload.acknowledgement_ref,
            portal_name=payload.portal_name,
        )
        session.commit()
    except (ValueError, PermissionError) as e:
        session.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)) from e

    return {
        "status": "FILED",
        "packet_id": packet.id,
        "acknowledgement_ref": packet.acknowledgement_ref,
    }


@router.get("/{packet_id}/pdf")
def download_filing_pdf(
    packet_id: str,
    session: Session = Depends(get_db),
    auth_ctx: AuthContext = Depends(require_permission(Action.PACKET_READ)),
) -> Response:
    """Generates byte-reproducible A4 PDF of the filing packet with CRC32 check-code."""
    packet = session.scalar(select(FilingPacket).where(FilingPacket.id == packet_id))
    if packet is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Filing packet not found")

    pdf_bytes = generate_filing_pdf(
        packet_data=packet.packet_data,
        packet_hash=packet.packet_hash,
        incident_number=f"INC-{packet.incident_id[:8]}",
        approver_name=packet.approved_by_id or "Compliance Approver",
    )
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=cyberq_filing_{packet.regulator}_{packet.version}.pdf"},
    )
