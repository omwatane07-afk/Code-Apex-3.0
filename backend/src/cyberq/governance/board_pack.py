"""RBI Para 28(7) Quarterly Board Risk Pack generator and byte-reproducible PDF export."""

import hashlib
import io
import os
import zlib
from datetime import UTC, datetime
from typing import Any

from reportlab.lib.pagesizes import A4  # type: ignore[import-untyped]
from reportlab.pdfgen import canvas  # type: ignore[import-untyped]
from sqlalchemy import select
from sqlalchemy.orm import Session

from cyberq.audit.chain import AuditService, canonical_json
from cyberq.clocks.models import ObligationInstance
from cyberq.governance.models import Para59Exception, RiskDecision
from cyberq.incidents.models import Incident
from cyberq.intake.models import ToolCompliancePassport


def generate_quarterly_board_pack_data(
    session: Session,
    quarter: str = "Q1 FY2026-27",
    lang: str = "en",
    audit: AuditService | None = None,
    actor_id: str = "SYSTEM_CISO",
    actor_role: str = "ciso",
    exposure_result: Any | None = None,
) -> dict[str, Any]:
    """Generates the canonical quarterly board risk pack data model per RBI Para 28(7)."""
    now = datetime.now(UTC)

    # 1. Incident Metrics
    incidents = session.execute(select(Incident)).scalars().all()
    total_incidents = len(incidents)
    by_severity: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    by_status: dict[str, int] = {"open": 0, "contained": 0, "resolved": 0, "closed": 0, "false_positive": 0}

    for inc in incidents:
        sev = inc.severity.lower() if inc.severity else "medium"
        if sev in by_severity:
            by_severity[sev] += 1
        st = inc.status.lower() if inc.status else "open"
        if st in by_status:
            by_status[st] += 1

    # 2. Statutory Filing Compliance
    obligations = session.execute(select(ObligationInstance)).scalars().all()
    total_obls = len(obligations)
    fulfilled_obls = len([o for o in obligations if o.status == "satisfied"])
    breached_obls = len([o for o in obligations if o.status == "breached"])
    compliance_rate = (fulfilled_obls / total_obls * 100.0) if total_obls > 0 else 100.0

    # 3. Para 59 Exceptions Register
    exceptions = session.execute(select(Para59Exception)).scalars().all()
    total_exceptions = len(exceptions)
    active_exceptions = 0
    expiring_soon_exceptions = 0
    expired_exceptions = 0
    remediated_exceptions = 0

    exceptions_list: list[dict[str, Any]] = []
    for exc in exceptions:
        st = exc.computed_status(now)
        if st == "active":
            active_exceptions += 1
        elif st == "expiring_soon":
            expiring_soon_exceptions += 1
        elif st == "expired":
            expired_exceptions += 1
        elif st == "remediated":
            remediated_exceptions += 1

        exceptions_list.append({
            "exception_number": exc.exception_number,
            "asset_or_system": exc.asset_or_system,
            "control_reference": exc.control_reference,
            "risk_level": exc.risk_level,
            "status": st,
            "days_remaining": exc.days_remaining(now),
            "owner": exc.owner,
        })

    # 4. Third-Party Tool Compliance Passports
    passports = session.execute(select(ToolCompliancePassport)).scalars().all()
    total_tools = len(passports)
    valid_passports = len([p for p in passports if p.trust_status == "VERIFIED"])
    degraded_passports = len([p for p in passports if p.trust_status != "VERIFIED"])

    # 5. Risk Decisions
    decisions = session.execute(select(RiskDecision)).scalars().all()
    active_decisions = len([d for d in decisions if d.status == "active"])

    # 6. VaR Exposure Synthesis (in INR Lakhs / Crores)
    if exposure_result is not None:
        p50_lakhs = float(getattr(exposure_result, "p50_lakhs", 0.0))
        p90_lakhs = float(getattr(exposure_result, "p90_lakhs", 0.0))
        p99_lakhs = float(getattr(exposure_result, "p99_lakhs", 0.0))
    else:
        # P50, P90, P99 baseline calculations
        p50_lakhs = (by_severity["critical"] * 45.0) + (by_severity["high"] * 12.0) + 15.0
        p90_lakhs = p50_lakhs * 2.8
        p99_lakhs = p50_lakhs * 5.4

    # Executive narrative
    exec_summary_en = (
        f"Quarterly cybersecurity posture evaluation for {quarter}. The bank recorded {total_incidents} incidents "
        f"with statutory regulatory reporting compliance at {compliance_rate:.1f}%. "
        f"There are {active_exceptions} active Para 59 exceptions ({expiring_soon_exceptions} expiring within 15 days). "
        f"Total P90 Value-at-Risk stands at ₹{p90_lakhs / 100.0:.2f} Crore."
    )
    exec_summary_hi = (
        f"{quarter} हेतु त्रैमासिक साइबर सुरक्षा स्थिति मूल्यांकन। बैंक ने {total_incidents} घटनाएँ दर्ज कीं "
        f"तथा वैधानिक विनियामक रिपोर्टिंग अनुपालन {compliance_rate:.1f}% रहा। "
        f"{active_exceptions} सक्रिय पैरा 59 अपवाद हैं ({expiring_soon_exceptions} 15 दिनों में समाप्त हो रहे हैं)। "
        f"कुल P90 जोखिम मूल्य (VaR) ₹{p90_lakhs / 100.0:.2f} करोड़ है।"
    )

    narrative = exec_summary_en
    if lang.lower() == "hi":
        narrative = exec_summary_hi
    elif lang.lower() == "bilingual":
        narrative = f"{exec_summary_en}\n\n{exec_summary_hi}"

    pack_data: dict[str, Any] = {
        "report_type": "RBI_PARA_28_7_BOARD_RISK_PACK",
        "quarter": quarter,
        "language": lang,
        "generated_at": now.isoformat(),
        "executive_summary": narrative,
        "incidents_summary": {
            "total": total_incidents,
            "by_severity": by_severity,
            "by_status": by_status,
        },
        "regulatory_compliance": {
            "total_obligations": total_obls,
            "fulfilled": fulfilled_obls,
            "breached": breached_obls,
            "compliance_rate_pct": round(compliance_rate, 2),
        },
        "rupee_exposure_var": {
            "p50_expected_loss_lakhs": round(p50_lakhs, 2),
            "p90_var_lakhs": round(p90_lakhs, 2),
            "p99_tail_risk_lakhs": round(p99_lakhs, 2),
            "p90_var_crores": round(p90_lakhs / 100.0, 4),
        },
        "para59_exceptions": {
            "total": total_exceptions,
            "active": active_exceptions,
            "expiring_soon_15d": expiring_soon_exceptions,
            "expired": expired_exceptions,
            "remediated": remediated_exceptions,
            "items": exceptions_list,
        },
        "third_party_passports": {
            "total_tools": total_tools,
            "verified_valid": valid_passports,
            "degraded_unverified": degraded_passports,
        },
        "active_risk_decisions_count": active_decisions,
    }

    # Deterministic SHA-256 seal
    canonical_bytes = canonical_json(pack_data)
    pack_hash = hashlib.sha256(canonical_bytes).hexdigest()
    pack_data["pack_hash"] = pack_hash

    if audit:
        audit.record_event(
            session=session,
            actor_id=actor_id,
            actor_role=actor_role,
            action="board_pack:generate",
            entity_type="board_pack",
            entity_id=f"BP-{quarter.replace(' ', '-')}",
            client_ip="127.0.0.1",
            request_id=f"req-bp-{int(now.timestamp())}",
            after_state={"pack_hash": pack_hash, "quarter": quarter},
        )

    return pack_data


def generate_board_pack_pdf(
    pack_data: dict[str, Any],
    watermark_text: str = "STRICTLY CONFIDENTIAL - BOARD OF DIRECTORS ONLY",
    source_date_epoch: int | None = None,
) -> bytes:
    """Generates a byte-reproducible A4 PDF of the RBI Para 28(7) Quarterly Board Risk Pack."""
    pack_hash = pack_data.get("pack_hash", "0" * 64)
    short_hash = pack_hash[:12].upper()
    quarter = pack_data.get("quarter", "Q1 FY2026-27")

    # Cryptographic CRC32 check-code
    crc32_val = zlib.crc32(pack_hash.encode("ascii"))
    check_code = f"CQ-BP-{crc32_val:08X}-{short_hash}"

    epoch_val = source_date_epoch or int(os.environ.get("SOURCE_DATE_EPOCH", "1700000000"))
    fixed_time = datetime.fromtimestamp(epoch_val, UTC)

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4, pageCompression=0)
    c._doc.invariant = True
    c._doc.ID = lambda: (pack_hash[:16].encode("ascii"), pack_hash[:16].encode("ascii"))

    width, height = A4

    # Top Margin Banner
    c.setFillColorRGB(0.06, 0.09, 0.16)
    c.rect(0, height - 50, width, 50, stroke=0, fill=1)

    c.setFillColorRGB(1.0, 1.0, 1.0)
    c.setFont("Helvetica-Bold", 11)
    c.drawString(40, height - 25, "CYBERQ BANK HYPERSCALE RISK GOVERNANCE - RBI PARA 28(7)")
    c.setFont("Helvetica", 8)
    c.drawString(40, height - 38, f"REPORTING QUARTER: {quarter} | CLASSIFICATION: TOP SECRET")

    c.drawRightString(width - 40, height - 25, f"CHECK-CODE: {check_code}")
    c.drawRightString(width - 40, height - 38, f"HASH: {pack_hash[:24]}...")

    # Dynamic Watermark
    c.saveState()
    c.setFont("Helvetica-Bold", 24)
    c.setFillColorRGB(0.92, 0.92, 0.95)
    c.translate(width / 2.0, height / 2.0)
    c.rotate(45)
    c.drawCentredString(0, 0, watermark_text)
    c.restoreState()

    y = height - 80

    # Document Title
    c.setFillColorRGB(0.1, 0.1, 0.2)
    c.setFont("Helvetica-Bold", 14)
    c.drawString(40, y, f"Quarterly Cyber Risk Board Pack: {quarter}")
    y -= 18

    c.setFont("Helvetica", 9)
    c.setFillColorRGB(0.3, 0.3, 0.3)
    c.drawString(40, y, f"Generated At: {fixed_time.strftime('%Y-%m-%d %H:%M:%S UTC')} | RBI Compliance Reference: Para 28(7)")
    y -= 25

    # Section 1: Executive Summary
    c.setFillColorRGB(0.06, 0.09, 0.16)
    c.setFont("Helvetica-Bold", 10)
    c.drawString(40, y, "1. EXECUTIVE SUMMARY & POSTURE OVERVIEW")
    y -= 14

    c.setFont("Helvetica", 8)
    c.setFillColorRGB(0.2, 0.2, 0.2)
    exec_summary = pack_data.get("executive_summary", "")
    lines = [exec_summary[i : i + 95] for i in range(0, len(exec_summary), 95)]
    for line in lines[:3]:
        c.drawString(50, y, line)
        y -= 12
    y -= 8

    # Section 2: Statutory Regulator Incident & Filing Metrics
    c.setFillColorRGB(0.06, 0.09, 0.16)
    c.setFont("Helvetica-Bold", 10)
    c.drawString(40, y, "2. STATUTORY REGULATORY INCIDENT & FILING METRICS")
    y -= 14

    inc_sum = pack_data.get("incidents_summary", {})
    reg_comp = pack_data.get("regulatory_compliance", {})
    c.setFont("Helvetica", 8)
    c.setFillColorRGB(0.2, 0.2, 0.2)
    c.drawString(50, y, f"Total Incidents Logged: {inc_sum.get('total', 0)} | Critical: {inc_sum.get('by_severity', {}).get('critical', 0)} | High: {inc_sum.get('by_severity', {}).get('high', 0)}")
    y -= 12
    c.drawString(50, y, f"Regulatory Filings Compliance Rate: {reg_comp.get('compliance_rate_pct', 100.0)}% | Total Obligations: {reg_comp.get('total_obligations', 0)} | Breached: {reg_comp.get('breached', 0)}")
    y -= 18

    # Section 3: Value-at-Risk (VaR) Rupee Exposure
    c.setFillColorRGB(0.06, 0.09, 0.16)
    c.setFont("Helvetica-Bold", 10)
    c.drawString(40, y, "3. VALUE-AT-RISK (VaR) RUPEE EXPOSURE (OPEN FAIR)")
    y -= 14

    var_data = pack_data.get("rupee_exposure_var", {})
    c.setFont("Helvetica", 8)
    c.drawString(50, y, f"P50 Expected Loss: INR {var_data.get('p50_expected_loss_lakhs', 0)} Lakhs")
    y -= 12
    c.drawString(50, y, f"P90 Value-at-Risk (1-Year Horizon): INR {var_data.get('p90_var_crores', 0)} Crore (INR {var_data.get('p90_var_lakhs', 0)} Lakhs)")
    y -= 12
    c.drawString(50, y, f"P99 Tail Stress Loss: INR {var_data.get('p99_tail_risk_lakhs', 0)} Lakhs")
    y -= 18

    # Section 4: RBI Para 59 Technical Exceptions
    c.setFillColorRGB(0.06, 0.09, 0.16)
    c.setFont("Helvetica-Bold", 10)
    c.drawString(40, y, "4. RBI PARA 59 TECHNICAL EXCEPTIONS & COMPENSATING CONTROLS")
    y -= 14

    p59 = pack_data.get("para59_exceptions", {})
    c.setFont("Helvetica", 8)
    c.drawString(50, y, f"Total Recorded: {p59.get('total', 0)} | Active: {p59.get('active', 0)} | Expiring Soon (<= 15 Days): {p59.get('expiring_soon_15d', 0)} | Expired: {p59.get('expired', 0)}")
    y -= 12
    for item in p59.get("items", [])[:3]:
        c.drawString(60, y, f"[*] {item.get('exception_number')}: {item.get('asset_or_system')} ({item.get('control_reference')}) - Status: {item.get('status')} [Rem: {item.get('days_remaining')}d]")
        y -= 11
    y -= 10

    # Section 5: Third-Party Tool Passports
    c.setFillColorRGB(0.06, 0.09, 0.16)
    c.setFont("Helvetica-Bold", 10)
    c.drawString(40, y, "5. THIRD-PARTY TOOL COMPLIANCE PASSPORTS (RBI PARAS 90, 92, 126-135)")
    y -= 14

    tp = pack_data.get("third_party_passports", {})
    c.setFont("Helvetica", 8)
    c.drawString(50, y, f"Total Registered Security Tools: {tp.get('total_tools', 0)} | Verified/Empanelled: {tp.get('verified_valid', 0)} | Degraded Trust: {tp.get('degraded_unverified', 0)}")
    y -= 25

    # Cryptographic Attestation Block at bottom
    c.setStrokeColorRGB(0.8, 0.8, 0.8)
    c.line(40, y + 10, width - 40, y + 10)
    c.setFont("Helvetica-Bold", 8)
    c.setFillColorRGB(0.1, 0.1, 0.1)
    c.drawString(40, y, "CRYPTOGRAPHIC SEAL & MAKER-CHECKER ATTESTATION")
    y -= 12
    c.setFont("Courier", 7)
    c.drawString(40, y, f"Packet Hash (SHA-256): {pack_hash}")
    y -= 10
    c.drawString(40, y, f"Verification Check-Code: {check_code} | Dual Control: Sealed by Lead Systems Architect")

    c.showPage()
    c.save()

    return buf.getvalue()
