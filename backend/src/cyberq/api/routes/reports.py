"""Statutory Reports download API route enforcing banking-grade RBAC."""

from __future__ import annotations

import io
import json
import os
import tempfile
import zipfile
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse, Response
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


def _get_or_seed_incident(db: Session, incident_id: str) -> Incident | None:
    """Locate incident by UUID or incident_number, falling back to idempotent demo seeding if missing."""
    inc = db.scalar(select(Incident).where(Incident.id == incident_id))
    if not inc:
        inc = db.scalar(select(Incident).where(Incident.incident_number == incident_id))
    if not inc:
        try:
            from cyberq.core.demo_seed import seed_demo_data

            seed_demo_data(db)
            inc = db.scalar(select(Incident).where(Incident.id == incident_id))
            if not inc:
                inc = db.scalar(select(Incident).where(Incident.incident_number == incident_id))
        except Exception:
            pass
    return inc


@router.get("/reports/incidents-summary")
def get_statutory_reports_incident_summary(
    db: Session = Depends(get_db),
    auth_ctx: AuthContext = Depends(require_permission(Action.INCIDENT_READ)),
) -> list[dict[str, Any]]:
    """Returns a list of all incidents with their statutory reporting readiness and download URLs."""
    incidents = db.scalars(select(Incident).order_by(Incident.created_at.desc())).all()
    if not incidents:
        try:
            from cyberq.core.demo_seed import seed_demo_data

            seed_demo_data(db)
            incidents = db.scalars(select(Incident).order_by(Incident.created_at.desc())).all()
        except Exception:
            pass

    results = []
    for inc in incidents:
        results.append({
            "id": inc.id,
            "incident_number": inc.incident_number,
            "title": inc.title,
            "severity": inc.severity,
            "status": inc.status,
            "created_at": inc.created_at.isoformat() if inc.created_at else None,
            "certin_download_url": f"/api/v1/incidents/{inc.id}/report/download",
            "dpdp_internal_download_url": f"/api/v1/incidents/{inc.id}/dpdp-report/download?audience=internal",
            "dpdp_dpb_download_url": f"/api/v1/incidents/{inc.id}/dpdp-report/download?audience=dpb",
            "bundle_zip_url": f"/api/v1/incidents/{inc.id}/reports/bundle-zip",
        })
    return results


@router.get("/reports/batch-zip")
def download_all_statutory_reports_zip(
    db: Session = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
    auth_ctx: AuthContext = Depends(require_permission(Action.STATUTORY_REPORT_DOWNLOAD)),
) -> Response:
    """Generates separate CERT-In and DPDP statutory reports for each incident and returns them in a single ZIP."""
    incidents = db.scalars(select(Incident).order_by(Incident.created_at.desc())).all()
    if not incidents:
        try:
            from cyberq.core.demo_seed import seed_demo_data

            seed_demo_data(db)
            incidents = db.scalars(select(Incident).order_by(Incident.created_at.desc())).all()
        except Exception:
            pass

    if not incidents:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No incidents found in system to generate reports for",
        )

    zip_buffer = io.BytesIO()
    manifest_entries = []

    with zipfile.ZipFile(zip_buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for inc in incidents:
            inc_code = inc.incident_number or inc.id[:8]

            # 1. Separate CERT-In PDF for this incident
            packet = db.scalar(
                select(FilingPacket)
                .where(FilingPacket.incident_id == inc.id)
                .where(FilingPacket.regulator == "CERT-In")
                .order_by(FilingPacket.version.desc())
            )
            certin_pdf, certin_hash, certin_code = CertInReportService.generate_and_seal_certin_pdf(
                session=db,
                incident=inc,
                audit=audit,
                packet=packet,
                actor_id=auth_ctx.user_id,
                actor_role=auth_ctx.role.value,
            )
            certin_filename = f"{inc_code}/CERT-In_Annexure1_{inc_code}.pdf"
            zf.writestr(certin_filename, certin_pdf)

            # 2. Separate DPDP Rule 7 Internal Report for this incident
            dpdp_int_pdf, dpdp_int_hash, dpdp_int_code, _ = DpdpReportService.generate_and_seal_dpdp_report(
                session=db,
                incident=inc,
                audit=audit,
                actor_id=auth_ctx.user_id,
                actor_role=auth_ctx.role.value,
                target_audience=AudienceType.INTERNAL,
            )
            dpdp_int_filename = f"{inc_code}/DPDP_Rule7_Breach_Notification_{inc_code}_internal.pdf"
            zf.writestr(dpdp_int_filename, dpdp_int_pdf)

            # 3. Separate DPDP Rule 7 DPB Authority Report for this incident
            dpdp_dpb_pdf, dpdp_dpb_hash, dpdp_dpb_code, _ = DpdpReportService.generate_and_seal_dpdp_report(
                session=db,
                incident=inc,
                audit=audit,
                actor_id=auth_ctx.user_id,
                actor_role=auth_ctx.role.value,
                target_audience=AudienceType.DPB,
            )
            dpdp_dpb_filename = f"{inc_code}/DPDP_Rule7_Breach_Notification_{inc_code}_dpb.pdf"
            zf.writestr(dpdp_dpb_filename, dpdp_dpb_pdf)

            manifest_entries.append({
                "incident_id": inc.id,
                "incident_number": inc_code,
                "title": inc.title,
                "severity": inc.severity,
                "reports": {
                    "certin": {
                        "filename": certin_filename,
                        "verification_code": certin_code,
                        "sha256": certin_hash,
                    },
                    "dpdp_internal": {
                        "filename": dpdp_int_filename,
                        "verification_code": dpdp_int_code,
                        "sha256": dpdp_int_hash,
                    },
                    "dpdp_dpb": {
                        "filename": dpdp_dpb_filename,
                        "verification_code": dpdp_dpb_code,
                        "sha256": dpdp_dpb_hash,
                    },
                },
            })

        # Cryptographic Audit Manifest inside ZIP
        manifest_doc = {
            "title": "CYBERQ Statutory Reporting Batch Ledger",
            "generated_at": datetime.now(UTC).isoformat(),
            "generated_by": auth_ctx.user_id,
            "role": auth_ctx.role.value,
            "total_incidents": len(incidents),
            "manifest": manifest_entries,
        }
        zf.writestr("manifest.json", json.dumps(manifest_doc, indent=2))

    db.commit()

    return Response(
        content=zip_buffer.getvalue(),
        media_type="application/zip",
        headers={
            "Content-Disposition": "attachment; filename=CYBERQ_All_Incidents_Statutory_Reports.zip",
            "X-Total-Incidents": str(len(incidents)),
        },
    )


@router.get("/{incident_id}/reports/bundle-zip")
def download_incident_reports_bundle_zip(
    incident_id: str,
    db: Session = Depends(get_db),
    audit: AuditService = Depends(get_audit_service),
    auth_ctx: AuthContext = Depends(require_permission(Action.STATUTORY_REPORT_DOWNLOAD)),
) -> Response:
    """Generates separate CERT-In and DPDP statutory reports for a specific incident and returns them in a ZIP."""
    incident = _get_or_seed_incident(db, incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{incident_id}' not found",
        )

    inc_code = incident.incident_number or incident.id[:8]
    zip_buffer = io.BytesIO()

    with zipfile.ZipFile(zip_buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        packet = db.scalar(
            select(FilingPacket)
            .where(FilingPacket.incident_id == incident.id)
            .where(FilingPacket.regulator == "CERT-In")
            .order_by(FilingPacket.version.desc())
        )
        certin_pdf, certin_hash, certin_code = CertInReportService.generate_and_seal_certin_pdf(
            session=db,
            incident=incident,
            audit=audit,
            packet=packet,
            actor_id=auth_ctx.user_id,
            actor_role=auth_ctx.role.value,
        )
        zf.writestr(f"CERT-In_Annexure1_{inc_code}.pdf", certin_pdf)

        dpdp_int_pdf, dpdp_int_hash, dpdp_int_code, _ = DpdpReportService.generate_and_seal_dpdp_report(
            session=db,
            incident=incident,
            audit=audit,
            actor_id=auth_ctx.user_id,
            actor_role=auth_ctx.role.value,
            target_audience=AudienceType.INTERNAL,
        )
        zf.writestr(f"DPDP_Rule7_Breach_Notification_{inc_code}_internal.pdf", dpdp_int_pdf)

        dpdp_dpb_pdf, dpdp_dpb_hash, dpdp_dpb_code, _ = DpdpReportService.generate_and_seal_dpdp_report(
            session=db,
            incident=incident,
            audit=audit,
            actor_id=auth_ctx.user_id,
            actor_role=auth_ctx.role.value,
            target_audience=AudienceType.DPB,
        )
        zf.writestr(f"DPDP_Rule7_Breach_Notification_{inc_code}_dpb.pdf", dpdp_dpb_pdf)

        manifest = {
            "incident_id": incident.id,
            "incident_number": inc_code,
            "generated_at": datetime.now(UTC).isoformat(),
            "generated_by": auth_ctx.user_id,
            "certin": {"verification_code": certin_code, "sha256": certin_hash},
            "dpdp_internal": {"verification_code": dpdp_int_code, "sha256": dpdp_int_hash},
            "dpdp_dpb": {"verification_code": dpdp_dpb_code, "sha256": dpdp_dpb_hash},
        }
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))

    db.commit()

    return Response(
        content=zip_buffer.getvalue(),
        media_type="application/zip",
        headers={
            "Content-Disposition": f"attachment; filename=CYBERQ_Reports_{inc_code}.zip",
        },
    )


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
    incident = _get_or_seed_incident(db, incident_id)
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
    incident = _get_or_seed_incident(db, incident_id)
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
    incident = _get_or_seed_incident(db, incident_id)
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
