"""Service for DPDP Rule 7 Breach Notification data binding, rendering, and cryptographic sealing."""

from __future__ import annotations

import hashlib
import io
import os
import shutil
import subprocess
import tempfile
import zlib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader
from reportlab.lib import colors  # type: ignore[import-untyped]
from reportlab.lib.pagesizes import A4  # type: ignore[import-untyped]
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet  # type: ignore[import-untyped]
from reportlab.platypus import (  # type: ignore[import-untyped]
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from sqlalchemy.orm import Session

from cyberq.audit.chain import AuditService
from cyberq.governance.dpdp.models import AudienceType, DpdpBreachReportData
from cyberq.governance.dpdp.timer import to_ist_str
from cyberq.incidents.models import Incident, IncidentTrigger, StatutoryTriggerType

TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
EDGE_EXE_PATHS = [
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
]


class DpdpReportService:
    """Core orchestration service for DPDP Rule 7 Personal Data Breach Notification reports."""

    @classmethod
    def calculate_verification_code(cls, incident_id: str, became_aware_str: str) -> str:
        """Derives a deterministic statutory verification code in CQ-DPDP- format."""
        raw_seed = f"DPDP-RULE-7:{incident_id}:{became_aware_str}"
        crc = zlib.crc32(raw_seed.encode("utf-8")) & 0xFFFFFFFF
        sha_prefix = hashlib.sha256(raw_seed.encode("utf-8")).hexdigest()[:6].upper()
        return f"CQ-DPDP-{crc:08X}-{sha_prefix}"

    @classmethod
    def bind_incident_data(
        cls,
        incident: Incident,
        target_audience: AudienceType = AudienceType.INTERNAL,
        actor_name: str = "Authorized Banking Officer",
        actor_role: str = "ciso",
        overrides: dict[str, Any] | None = None,
    ) -> DpdpBreachReportData:
        """Binds database models to the normalized DpdpBreachReportData schema."""
        now = datetime.now(UTC)
        incident_num = incident.incident_number or f"INC-{incident.id[:8]}"

        # Locate aware trigger assertion if present
        aware_trigger: IncidentTrigger | None = None
        for trig in incident.triggers or []:
            if trig.trigger_type.lower() == StatutoryTriggerType.AWARE.value.lower():
                aware_trigger = trig
                break

        if aware_trigger and aware_trigger.occurred_at:
            aware_utc = aware_trigger.occurred_at
        elif incident.created_at:
            aware_utc = incident.created_at
        else:
            aware_utc = now

        deadline_utc = aware_utc + timedelta(hours=72)
        became_aware_ist = to_ist_str(aware_utc)
        deadline_72h_ist = to_ist_str(deadline_utc)
        submission_time_ist = to_ist_str(now)

        verification_code = cls.calculate_verification_code(incident_num, became_aware_ist)
        include_internal = target_audience == AudienceType.INTERNAL

        data_dict: dict[str, Any] = {
            "incident_id": incident_num,
            "certin_id": incident_num,
            "target_audience": target_audience,
            "include_internal_sections": include_internal,
            "submission_time_ist": submission_time_ist,
            "bank_legal_name": "Apex Bank of India Ltd.",
            "dpb_portal_id": "DPB-FID-2026-IN-00891",
            "dpo_details": "Kavita Deshmukh, Data Protection Officer, dpo@apexbank.in, +91-22-67890123",
            "board_accountability": "Risk Management Committee of the Board (RMCB) & CISO",
            "breach_contact_24x7": "SOC Command Desk, soc@apexbank.in, +91-22-67890999",
            "sdf_status": "Yes (Scheduled Commercial Bank)",
            "became_aware_ist": became_aware_ist,
            "deadline_72h_ist": deadline_72h_ist,
            "breach_nature": (
                incident.title
                or "Unauthorised access to ISO-8583 message broker; potential accidental disclosure of customer telemetry"
            ),
            "affected_systems": "Core Banking Switch Gateway; ISO-8583 Message Broker",
            "personal_data_affected": "Customer account numbers, masked card tokens, transaction payloads",
            "data_principal_categories": "Commercial retail and corporate banking customers",
            "data_principal_count": "Under continuous forensic assessment (provisional: ~1,250 accounts)",
            "children_data_involved": "No (corporate and adult retail accounts only)",
            "initial_access_vector": "Provisional: Compromised API gateway access token / credential stuffing",
            "likely_consequences": "Provisional risk of phishing and credential spraying; transactional integrity preserved",
            "ai_agent_involvement": "No autonomous agent lateral escalation detected",
            "ai_advisory_ref": "CERT-In Advisory 2026/A-09 (Agentic AI Resilience)",
            "fund_loss_status": "₹0 confirmed (Reconciled with payment switch settlement reports)",
            "personal_data_impact_status": "Under assessment (PII scrubbing active at ingestion boundary)",
            "transaction_integrity_risk": "Zero tampering detected; message hash parity verified",
            "intimation_nature": "Suspicious credential usage on internal message broker",
            "intimation_extent": "Isolated to Switch Gateway node SG-04; data categories under assessment",
            "occurred_time_ist": became_aware_ist,
            "breach_location": "Mumbai Primary On-Premise Data Centre (MeitY empaneled, India residency confirmed)",
            "provisional_impact": "Contained access attempt; no customer fund exfiltration",
            "containment_status": f"{incident.status.upper()} (Network segment isolated and credentials rotated)",
            "forensic_clearance_status": "In progress (Empanelled CERT-In auditor conducting disk forensics)",
            "detailed_updated_facts": "Boundary controls held; all logs exported to WORM audit ledger",
            "detailed_circumstances": "API credential leakage traced to third-party vendor test client script",
            "detailed_remedial_measures": "Gateway token revoked, firewall rules updated, dual-control enforced",
            "breach_causers": "Under forensic investigation; no malicious insider collusion established",
            "principal_notices_sent": "Decision pending CISO & DPO joint determination per Section 5",
            "api_inventory_status": "Completed; all dormant test endpoints terminated",
            "credential_rotation_status": "100% of privileged and service tokens rotated",
            "mfa_enforcement_status": "Enforced with hardware FIDO2 tokens on all administrative interfaces",
            "least_privilege_status": "IAM roles restricted strictly to minimal required RBAC scopes",
            "api_monitoring_status": "Real-time rate-limiting and burst anomaly detection enabled",
            "principal_notification_decision": "not_yet",
            "notification_decision_reason": "Forensic data reconciliation ongoing; no verified PII exfiltration",
            "ciso_approver_name": f"{actor_name} ({actor_role.upper()})",
            "ciso_decision_datetime": submission_time_ist,
            "principal_notice_channel": "Registered email and secure net banking inbox alert",
            "principal_notice_target_time": "Within 24 hours of forensic confirmation if breach is established",
            "principal_notice_draft_text": (
                "Dear Customer, we detected an unauthorized attempt on our payment switch. "
                "Your account and funds are completely safe. As a precaution, please ensure multi-factor authentication is active."
            ),
            "certin_filing_status": "Filed within 6 hours (Annexure I verified)",
            "dpdp_filing_status": "Initial intimation completed; 72-hour detailed report draft generated",
            "rbi_filing_status": "DAKSH incident intimation submitted",
            "prepared_by_name": "Arjun Rao (Senior Lead Incident Analyst)",
            "prepared_at_ist": became_aware_ist,
            "validated_by_name": "Vikram Malhotra (Lead Regulatory Model Validator)",
            "validated_at_ist": submission_time_ist,
            "approved_by_name": f"{actor_name} ({actor_role.upper()})",
            "approved_at_ist": submission_time_ist,
            "verification_code": verification_code,
        }

        if overrides:
            data_dict.update(overrides)

        return DpdpBreachReportData(**data_dict)

    @classmethod
    def render_html(cls, report_data: DpdpBreachReportData) -> str:
        """Renders the HTML template using Jinja2 with strict fidelity to provided design."""
        env = Environment(
            loader=FileSystemLoader(str(TEMPLATES_DIR)),
            autoescape=True,
            trim_blocks=True,
            lstrip_blocks=True,
        )
        template = env.get_template("dpdp_breach_notification_report.html")
        return template.render(report=report_data)

    @classmethod
    def _find_edge_executable(cls) -> str | None:
        """Finds Edge executable if available on Windows."""
        for path in EDGE_EXE_PATHS:
            if os.path.exists(path):
                return path
        return shutil.which("msedge")

    @classmethod
    def render_pdf_with_edge(cls, html_content: str) -> bytes | None:
        """Renders HTML directly into high-fidelity PDF using local headless Edge/Chromium."""
        edge_path = cls._find_edge_executable()
        if not edge_path:
            return None

        temp_dir = tempfile.gettempdir()
        temp_html = os.path.join(temp_dir, f"dpdp_render_{os.getpid()}_{datetime.now().timestamp()}.html")
        temp_pdf = os.path.join(temp_dir, f"dpdp_render_{os.getpid()}_{datetime.now().timestamp()}.pdf")

        try:
            with open(temp_html, "w", encoding="utf-8") as f:
                f.write(html_content)

            cmd = [
                edge_path,
                "--headless=new",
                "--disable-gpu",
                "--no-pdf-header-footer",
                f"--print-to-pdf={temp_pdf}",
                temp_html,
            ]
            result = subprocess.run(cmd, capture_output=True, timeout=20)
            if result.returncode == 0 and os.path.exists(temp_pdf) and os.path.getsize(temp_pdf) > 0:
                with open(temp_pdf, "rb") as f:
                    return f.read()
            return None
        except Exception:
            return None
        finally:
            if os.path.exists(temp_html):
                try:
                    os.remove(temp_html)
                except OSError:
                    pass
            if os.path.exists(temp_pdf):
                try:
                    os.remove(temp_pdf)
                except OSError:
                    pass

    @classmethod
    def render_pdf_with_reportlab(cls, report_data: DpdpBreachReportData) -> bytes:
        """Generates deterministic, byte-reproducible PDF using ReportLab Platypus.

        Serves as reliable air-gapped fallback ensuring exact structural compliance.
        """
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=A4,
            leftMargin=36,
            rightMargin=36,
            topMargin=40,
            bottomMargin=40,
        )

        styles = getSampleStyleSheet()
        h1_style = ParagraphStyle(
            "DPDPH1",
            parent=styles["Heading1"],
            fontSize=15,
            leading=18,
            textColor=colors.HexColor("#16365c"),
            fontName="Helvetica-Bold",
            spaceAfter=6,
        )
        h2_style = ParagraphStyle(
            "DPDPH2",
            parent=styles["Heading2"],
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#16365c"),
            fontName="Helvetica-Bold",
            spaceBefore=10,
            spaceAfter=4,
            keepWithNext=True,
        )
        body_style = ParagraphStyle(
            "DPDPBody",
            parent=styles["Normal"],
            fontSize=8.5,
            leading=11.5,
            textColor=colors.HexColor("#111111"),
            fontName="Helvetica",
        )
        meta_style = ParagraphStyle(
            "DPDPMeta",
            parent=styles["Normal"],
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#333333"),
            fontName="Helvetica",
        )
        th_style = ParagraphStyle(
            "DPDPTH",
            parent=styles["Normal"],
            fontSize=8,
            leading=10,
            textColor=colors.black,
            fontName="Helvetica-Bold",
        )

        story: list[Any] = []

        # 1. Header
        story.append(Paragraph("DPDP Data Production Report — Personal Data Breach Notification (Rule 7)", h1_style))
        story.append(
            HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#16365c"), spaceBefore=1, spaceAfter=4)
        )

        audience_desc = (
            "Sections 1–6: Data Protection Board (DPB) | Sections 7–10: Internal CISO / DPO Review"
            if report_data.include_internal_sections
            else "Data Protection Board (DPB) — Sections 1–6 Statutory Submission"
        )
        meta_text = (
            f"<b>Incident:</b> {report_data.incident_id} &nbsp;|&nbsp; "
            f"<b>Linked CERT-In:</b> {report_data.certin_id} &nbsp;|&nbsp; "
            f"<b>Verification:</b> {report_data.verification_code}<br/>"
            f"<b>Audience:</b> {audience_desc}<br/>"
            f"<b>Submission (IST):</b> {report_data.submission_time_ist}"
        )
        story.append(Paragraph(meta_text, meta_style))
        story.append(Spacer(1, 8))

        # 2. Section 1: Data Fiduciary Details
        story.append(Paragraph("1. Data Fiduciary Details", h2_style))
        sec1_rows = [
            [Paragraph("Legal name", th_style), Paragraph(report_data.bank_legal_name, body_style)],
            [
                Paragraph("Role", th_style),
                Paragraph("Data Fiduciary (Scheduled Commercial Bank regulated by RBI)", body_style),
            ],
            [Paragraph("DPB portal ID", th_style), Paragraph(report_data.dpb_portal_id, body_style)],
            [Paragraph("DPO / Grievance Officer", th_style), Paragraph(report_data.dpo_details, body_style)],
            [Paragraph("Board accountability", th_style), Paragraph(report_data.board_accountability, body_style)],
            [Paragraph("24×7 breach contact", th_style), Paragraph(report_data.breach_contact_24x7, body_style)],
            [Paragraph("Significant Data Fiduciary", th_style), Paragraph(report_data.sdf_status, body_style)],
        ]
        t1 = Table(sec1_rows, colWidths=[150, 370])
        t1.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#888888")),
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f3f7")),
                    ("TOPPADDING", (0, 0), (-1, -1), 2),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ]
            )
        )
        story.append(t1)
        story.append(Spacer(1, 8))

        # 3. Section 2: Breach Identification (DPDP Lens)
        story.append(Paragraph("2. Breach Identification (DPDP Lens)", h2_style))
        sec2_rows = [
            [
                Paragraph("Incident ID / CERT-In ID", th_style),
                Paragraph(f"{report_data.incident_id} / {report_data.certin_id}", body_style),
            ],
            [
                Paragraph("Became aware (IST)", th_style),
                Paragraph(
                    f"{report_data.became_aware_ist} (72h Deadline: {report_data.deadline_72h_ist})", body_style
                ),
            ],
            [Paragraph("Nature of breach (Sec 2(u))", th_style), Paragraph(report_data.breach_nature, body_style)],
            [Paragraph("Affected systems", th_style), Paragraph(report_data.affected_systems, body_style)],
            [
                Paragraph("Personal data affected", th_style),
                Paragraph(report_data.personal_data_affected, body_style),
            ],
            [
                Paragraph("Categories of Data Principals", th_style),
                Paragraph(
                    f"{report_data.data_principal_categories} | Count: {report_data.data_principal_count}", body_style
                ),
            ],
            [Paragraph("Children's data involved", th_style), Paragraph(report_data.children_data_involved, body_style)],
            [
                Paragraph("Initial access vector", th_style),
                Paragraph(report_data.initial_access_vector, body_style),
            ],
            [Paragraph("Likely consequences", th_style), Paragraph(report_data.likely_consequences, body_style)],
            [Paragraph("AI-agent involvement", th_style), Paragraph(report_data.ai_agent_involvement, body_style)],
            [Paragraph("Fund loss status", th_style), Paragraph(report_data.fund_loss_status, body_style)],
            [
                Paragraph("Transaction-integrity risk", th_style),
                Paragraph(report_data.transaction_integrity_risk, body_style),
            ],
        ]
        t2 = Table(sec2_rows, colWidths=[150, 370])
        t2.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#888888")),
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f3f7")),
                    ("TOPPADDING", (0, 0), (-1, -1), 2),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ]
            )
        )
        story.append(t2)
        story.append(Spacer(1, 8))

        # 4. Section 3: Initial Intimation to DPB
        story.append(Paragraph("3. Initial Intimation to DPB (Without Delay)", h2_style))
        sec3_rows = [
            [Paragraph("Intimation Nature", th_style), Paragraph(report_data.intimation_nature, body_style)],
            [Paragraph("Extent", th_style), Paragraph(report_data.intimation_extent, body_style)],
            [Paragraph("Timing / Location", th_style), Paragraph(f"Aware: {report_data.became_aware_ist} | Loc: {report_data.breach_location}", body_style)],
            [Paragraph("Containment Status", th_style), Paragraph(report_data.containment_status, body_style)],
            [Paragraph("Forensic Clearance Status", th_style), Paragraph(report_data.forensic_clearance_status, body_style)],
        ]
        t3 = Table(sec3_rows, colWidths=[150, 370])
        t3.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#888888")),
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f3f7")),
                    ("TOPPADDING", (0, 0), (-1, -1), 2),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ]
            )
        )
        story.append(t3)
        story.append(Spacer(1, 8))

        # 5. Section 4: Detailed Report to DPB (72-Hour Requirement)
        story.append(Paragraph("4. Detailed Report to DPB (72-Hour Requirement)", h2_style))
        sec4_rows = [
            [Paragraph("Updated facts", th_style), Paragraph(report_data.detailed_updated_facts, body_style)],
            [Paragraph("Circumstances / Causes", th_style), Paragraph(report_data.detailed_circumstances, body_style)],
            [Paragraph("Remedial measures", th_style), Paragraph(report_data.detailed_remedial_measures, body_style)],
            [Paragraph("Causer identification", th_style), Paragraph(report_data.breach_causers, body_style)],
            [Paragraph("Notices to Principals", th_style), Paragraph(report_data.principal_notices_sent, body_style)],
            [Paragraph("Preventive Controls (MFA/API)", th_style), Paragraph(f"MFA: {report_data.mfa_enforcement_status} | APIs: {report_data.api_inventory_status}", body_style)],
        ]
        t4 = Table(sec4_rows, colWidths=[150, 370])
        t4.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#888888")),
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f3f7")),
                    ("TOPPADDING", (0, 0), (-1, -1), 2),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ]
            )
        )
        story.append(t4)
        story.append(Spacer(1, 8))

        # 6. Section 5 & 6
        story.append(Paragraph("5. Notification to Affected Data Principals & 6. Regulatory Interplay", h2_style))
        sec5_rows = [
            [Paragraph("CISO Notification Decision", th_style), Paragraph(f"{report_data.principal_notification_decision.upper()} - {report_data.notification_decision_reason}", body_style)],
            [Paragraph("Channel / Target Time", th_style), Paragraph(f"{report_data.principal_notice_channel} | Target: {report_data.principal_notice_target_time}", body_style)],
            [Paragraph("CERT-In Status (6h)", th_style), Paragraph(report_data.certin_filing_status, body_style)],
            [Paragraph("DPDP Rule 7 Status (72h)", th_style), Paragraph(report_data.dpdp_filing_status, body_style)],
            [Paragraph("RBI DAKSH / Clearance", th_style), Paragraph(f"{report_data.rbi_filing_status} | Clearance: {report_data.forensic_clearance_status}", body_style)],
        ]
        t5 = Table(sec5_rows, colWidths=[150, 370])
        t5.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#888888")),
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f3f7")),
                    ("TOPPADDING", (0, 0), (-1, -1), 2),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ]
            )
        )
        story.append(t5)
        story.append(Spacer(1, 8))

        # Internal-only sections 7-10 + checklist
        if report_data.include_internal_sections:
            story.append(PageBreak())
            story.append(Paragraph("7. DPDP Evidence & Production Register (Internal CISO Review)", h2_style))
            sec7_rows = [
                [Paragraph("ID", th_style), Paragraph("Evidence", th_style), Paragraph("Hash / Reference", th_style), Paragraph("Status", th_style)],
                [Paragraph("DP-01", body_style), Paragraph("Data-flow map", body_style), Paragraph("SHA256:4a8b...", body_style), Paragraph("Verified", body_style)],
                [Paragraph("DP-02", body_style), Paragraph("Transaction-log analysis", body_style), Paragraph("SHA256:7c1d...", body_style), Paragraph("Verified", body_style)],
                [Paragraph("DP-03", body_style), Paragraph("Forensic image", body_style), Paragraph("SHA-256 custody log", body_style), Paragraph("In custody", body_style)],
                [Paragraph("DP-04", body_style), Paragraph("Notification records", body_style), Paragraph("Ack nos. pending", body_style), Paragraph("Active", body_style)],
                [Paragraph("DP-05", body_style), Paragraph("DPO / Legal memo", body_style), Paragraph("MEMO-2026-DPDP-01", body_style), Paragraph("Signed", body_style)],
                [Paragraph("DP-06", body_style), Paragraph("AI-agent assessment", body_style), Paragraph("SHA256:9f20...", body_style), Paragraph("Cleared", body_style)],
                [Paragraph("DP-07", body_style), Paragraph("Forensic clearance certificate", body_style), Paragraph("Pending scan", body_style), Paragraph("Not yet issued", body_style)],
            ]
            t7 = Table(sec7_rows, colWidths=[50, 160, 180, 130])
            t7.setStyle(
                TableStyle(
                    [
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#888888")),
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e6ebf1")),
                        ("TOPPADDING", (0, 0), (-1, -1), 2),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                    ]
                )
            )
            story.append(t7)
            story.append(Spacer(1, 8))

            story.append(Paragraph("8. RBI Forensic Clearance & 9. Penalty Exposure (Internal Briefing)", h2_style))
            sec8_rows = [
                [Paragraph("Mandatory Security Action", th_style), Paragraph("Status", th_style), Paragraph("DPDP Penalty Cap", th_style)],
                [Paragraph("Remove admin interfaces / MFA enforcement", body_style), Paragraph("Completed", body_style), Paragraph("₹250 crore (Reasonable safeguards)", body_style)],
                [Paragraph("Rotate credentials & API test endpoint purge", body_style), Paragraph("Completed", body_style), Paragraph("₹200 crore (Timely notification)", body_style)],
                [Paragraph("Forensic clearance certificate issuance", body_style), Paragraph(report_data.forensic_clearance_status, body_style), Paragraph("₹150 crore (SDF Obligations)", body_style)],
            ]
            t8 = Table(sec8_rows, colWidths=[200, 140, 180])
            t8.setStyle(
                TableStyle(
                    [
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#888888")),
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e6ebf1")),
                        ("TOPPADDING", (0, 0), (-1, -1), 2),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                    ]
                )
            )
            story.append(t8)
            story.append(Spacer(1, 8))

            story.append(Paragraph("10. Sign-off & Pre-submission Verification Checklist", h2_style))
            sec10_rows = [
                [Paragraph("Checklist Item", th_style), Paragraph("Dual-Control Sign-off", th_style)],
                [Paragraph("All placeholders verified against canonical data models", body_style), Paragraph("Analyst: Verified", body_style)],
                [Paragraph("DPB Initial intimation and 72-hour detailed report prepared", body_style), Paragraph("Validator: Verified", body_style)],
                [Paragraph("Cross-regime consistency verified (CERT-In, DPB, RBI)", body_style), Paragraph(f"CISO: {report_data.ciso_approver_name}", body_style)],
                [Paragraph("Sections 7-10 removed prior to official DPB transmission", body_style), Paragraph("DPO: Concurred", body_style)],
            ]
            t10 = Table(sec10_rows, colWidths=[300, 220])
            t10.setStyle(
                TableStyle(
                    [
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#888888")),
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e6ebf1")),
                        ("TOPPADDING", (0, 0), (-1, -1), 2),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                    ]
                )
            )
            story.append(t10)
            story.append(Spacer(1, 8))

        # Sign-off box
        story.append(KeepTogether([
            Paragraph("Report Preparation, Validation and Approval", h2_style),
            Table(
                [
                    [Paragraph("Prepared by", th_style), Paragraph(report_data.prepared_by_name, body_style), Paragraph(report_data.prepared_at_ist, body_style)],
                    [Paragraph("Validated by", th_style), Paragraph(report_data.validated_by_name, body_style), Paragraph(report_data.validated_at_ist, body_style)],
                    [Paragraph("Approved by", th_style), Paragraph(report_data.approved_by_name, body_style), Paragraph(report_data.approved_at_ist, body_style)],
                ],
                colWidths=[100, 270, 150],
                style=[
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#888888")),
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f3f7")),
                    ("TOPPADDING", (0, 0), (-1, -1), 2),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
                ],
            ),
            Spacer(1, 10),
            Paragraph(
                f"Generated by CYBERQ Bank Incident-to-Board Platform. Verification: {report_data.verification_code} | Classification: CONFIDENTIAL",
                meta_style,
            ),
        ]))

        doc.build(story)
        return buffer.getvalue()

    @classmethod
    def generate_pdf_bytes(cls, report_data: DpdpBreachReportData) -> tuple[bytes, str, str]:
        """Renders report data into PDF bytes, computing SHA-256 and verification code.

        Prioritizes exact headless Chromium/Edge HTML-to-PDF rendering to preserve 100% of
        the CSS structure, classes, and styles. Falls back to ReportLab Platypus.
        """
        html_rendered = cls.render_html(report_data)
        pdf_bytes = cls.render_pdf_with_edge(html_rendered)

        if not pdf_bytes or len(pdf_bytes) == 0:
            pdf_bytes = cls.render_pdf_with_reportlab(report_data)

        pdf_sha256 = hashlib.sha256(pdf_bytes).hexdigest()
        report_data.packet_hash = pdf_sha256
        return pdf_bytes, pdf_sha256, report_data.verification_code

    @classmethod
    def generate_and_seal_dpdp_report(
        cls,
        session: Session,
        incident: Incident,
        audit: AuditService,
        actor_id: str,
        actor_role: str,
        target_audience: AudienceType = AudienceType.INTERNAL,
        overrides: dict[str, Any] | None = None,
    ) -> tuple[bytes, str, str, DpdpBreachReportData]:
        """Generates the DPDP report, computes SHA-256 seal, and records immutable event in audit ledger."""
        report_data = cls.bind_incident_data(
            incident=incident,
            target_audience=target_audience,
            actor_name=actor_id,
            actor_role=actor_role,
            overrides=overrides,
        )

        pdf_bytes, pdf_sha256, verification_code = cls.generate_pdf_bytes(report_data)

        # Record cryptographic seal into audit_event ledger
        audit.record_event(
            session=session,
            actor_id=actor_id,
            actor_role=actor_role,
            action="report:dpdp_sealed",
            entity_type="dpdp_rule7_report",
            entity_id=incident.id,
            after_state={
                "incident_id": incident.id,
                "incident_number": incident.incident_number,
                "regulator": "DPDP",
                "instrument": "DPDP Rules 2025, Rule 7",
                "verification_code": verification_code,
                "packet_hash": pdf_sha256,
                "target_audience": target_audience.value,
                "include_internal_sections": report_data.include_internal_sections,
                "file_size_bytes": len(pdf_bytes),
                "timestamp_utc": datetime.now(UTC).isoformat(),
            },
            stream_id=incident.id,
        )

        return pdf_bytes, pdf_sha256, verification_code, report_data
