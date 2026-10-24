"""Statutory Reports download API route enforcing banking-grade RBAC."""

from __future__ import annotations

import os
import tempfile
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from cyberq.api.deps import get_audit_service, require_permission
from cyberq.audit.chain import AuditService
from cyberq.core.database import get_db
from cyberq.filings.models import FilingPacket
from cyberq.governance.certin_report import CertInReportService
from cyberq.governance.dpdp import (
    AudienceType,
    DpdpReportService,
    EmergencyTriggerRequest,
    EmergencyTriggerResponse,
    evaluate_72h_timer,
)
from cyberq.iam.policy import Action, AuthContext
from cyberq.incidents.models import Incident, IncidentTrigger, StatutoryTriggerType

router = APIRouter(prefix="/incidents", tags=["Statutory Reports"])


@router.get("/{incident_id}/report/download")
def download_statutory_report(
    incident_id: str,
    db: Session = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
    auth_ctx: AuthContext = Depends(require_permission(Action.STATUTORY_REPORT_DOWNLOAD)),
) -> FileResponse:
    """Secure statutory filing report download endpoint.

    Strictly gated by RBAC: Only authorized banking roles (Compliance Approver, CISO, IS Auditor)
    can download the finalized statutory report. L1 Analysts receive HTTP 403 Forbidden.
    """
    incident = db.scalar(select(Incident).where(Incident.id == incident_id))
    if not incident:
        # Also allow lookup by incident_number (e.g. INC-2026-0001)
        incident = db.scalar(select(Incident).where(Incident.incident_number == incident_id))
        if not incident:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Incident '{incident_id}' not found",
            )

    # Locate associated CERT-In filing packet if available
    packet = db.scalar(
        select(FilingPacket)
        .where(FilingPacket.incident_id == incident.id)
        .where(FilingPacket.regulator == "CERT-In")
        .order_by(FilingPacket.version.desc())
    )

    # Generate byte-reproducible PDF and record cryptographic seal in audit_event
    pdf_bytes, pdf_sha256, verification_code = CertInReportService.generate_and_seal_certin_pdf(
        session=db,
        incident=incident,
        audit=audit,
        packet=packet,
        actor_id=auth_ctx.user_id,
        actor_role=auth_ctx.role.value,
    )
    db.commit()

    # Save to a deterministic file for FileResponse
    filename = f"CERT-In_Incident_Filing_Packet_{incident.incident_number or incident.id}.pdf"
    temp_dir = tempfile.gettempdir()
    file_path = os.path.join(temp_dir, f"cyberq_report_{incident.id}_{pdf_sha256[:12]}.pdf")

    with open(file_path, "wb") as f:
        f.write(pdf_bytes)

    return FileResponse(
        path=file_path,
        media_type="application/pdf",
        filename=filename,
        headers={
            "X-Statutory-Verification-Code": verification_code,
            "X-Packet-Hash": pdf_sha256,
        },
    )


@router.post("/{incident_id}/dpdp-report/trigger", response_model=EmergencyTriggerResponse)
def trigger_emergency_dpdp_report(
    incident_id: str,
    payload: EmergencyTriggerRequest = EmergencyTriggerRequest(),
    db: Session = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
    auth_ctx: AuthContext = Depends(require_permission(Action.DPDP_REPORT_TRIGGER)),
) -> EmergencyTriggerResponse:
    """On-demand Emergency Report Trigger for DPDP Rule 7 Personal Data Breach Notification.

    Allows authorized banking roles (CISO, DPO, Compliance Officer) to manually force immediate
    report compilation and cryptographic sealing prior to or during the 72-hour countdown.
    """
    incident = db.scalar(select(Incident).where(Incident.id == incident_id))
    if not incident:
        incident = db.scalar(select(Incident).where(Incident.incident_number == incident_id))
        if not incident:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Incident '{incident_id}' not found",
            )

    # Locate aware trigger for timer evaluation
    aware_trigger = db.scalar(
        select(IncidentTrigger)
        .where(IncidentTrigger.incident_id == incident.id)
        .where(IncidentTrigger.trigger_type == StatutoryTriggerType.AWARE.value)
        .order_by(IncidentTrigger.occurred_at.asc())
    )
    aware_utc = aware_trigger.occurred_at if aware_trigger else (incident.created_at or datetime.now(UTC))
    timer_status = evaluate_72h_timer(aware_utc)

    # Generate and cryptographically seal the report
    pdf_bytes, pdf_sha256, verification_code, _ = DpdpReportService.generate_and_seal_dpdp_report(
        session=db,
        incident=incident,
        audit=audit,
        actor_id=auth_ctx.user_id,
        actor_role=auth_ctx.role.value,
        target_audience=payload.target_audience,
        overrides={"notification_decision_reason": payload.reason or "Emergency manual trigger dispatched"},
    )

    # Record specific trigger event
    audit.record_event(
        session=db,
        actor_id=auth_ctx.user_id,
        actor_role=auth_ctx.role.value,
        action="report:dpdp_emergency_trigger",
        entity_type="dpdp_rule7_report",
        entity_id=incident.id,
        after_state={
            "incident_id": incident.id,
            "incident_number": incident.incident_number or incident.id,
            "reason": payload.reason,
            "target_audience": payload.target_audience.value,
            "verification_code": verification_code,
            "packet_hash": pdf_sha256,
            "hours_remaining": timer_status.hours_remaining,
            "timer_status": timer_status.status,
        },
        stream_id=incident.id,
    )
    db.commit()

    return EmergencyTriggerResponse(
        status="triggered",
        incident_id=incident.id,
        incident_number=incident.incident_number or incident.id,
        trigger_type="emergency_manual",
        triggered_by=auth_ctx.user_id,
        triggered_at=datetime.now(UTC).isoformat(),
        verification_code=verification_code,
        packet_hash=pdf_sha256,
        timer_status=timer_status.model_dump(),
    )


@router.get("/{incident_id}/dpdp-report/download")
def download_dpdp_report(
    incident_id: str,
    audience: AudienceType = Query(
        default=AudienceType.INTERNAL,
        description="Target audience: 'internal' (Sections 1-10 + checklist) or 'dpb' (Sections 1-6 only)",
    ),
    db: Session = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
    auth_ctx: AuthContext = Depends(require_permission(Action.DPDP_REPORT_DOWNLOAD)),
) -> FileResponse:
    """Secure DPDP Rule 7 Personal Data Breach Notification PDF download endpoint.

    Strictly gated by RBAC: Only authorized roles (CISO, DPO, Compliance Officer, IS Auditor)
    can download the statutory packet. L1 Analysts receive HTTP 403 Forbidden.
    Dynamically filters sections based on the audience ('internal' vs 'dpb').
    """
    incident = db.scalar(select(Incident).where(Incident.id == incident_id))
    if not incident:
        incident = db.scalar(select(Incident).where(Incident.incident_number == incident_id))
        if not incident:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Incident '{incident_id}' not found",
            )

    pdf_bytes, pdf_sha256, verification_code, report_data = DpdpReportService.generate_and_seal_dpdp_report(
        session=db,
        incident=incident,
        audit=audit,
        actor_id=auth_ctx.user_id,
        actor_role=auth_ctx.role.value,
        target_audience=audience,
    )
    db.commit()

    filename = (
        f"DPDP_Breach_Notification_Report_{incident.incident_number or incident.id}_{audience.value}.pdf"
    )
    temp_dir = tempfile.gettempdir()
    file_path = os.path.join(temp_dir, f"cyberq_dpdp_{incident.id}_{audience.value}_{pdf_sha256[:12]}.pdf")

    with open(file_path, "wb") as f:
        f.write(pdf_bytes)

    return FileResponse(
        path=file_path,
        media_type="application/pdf",
        filename=filename,
        headers={
            "X-Statutory-Verification-Code": verification_code,
            "X-Packet-Hash": pdf_sha256,
            "X-Audience": audience.value,
            "X-Internal-Sections-Included": str(report_data.include_internal_sections),
        },
    )
