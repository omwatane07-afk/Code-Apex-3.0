"""Idempotent 1-Click Live Hackathon Demo Crisis Seeder for Indian Commercial Banking Scenarios."""

import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from cyberq.audit.chain import AuditService, canonical_json
from cyberq.clocks.engine import ClockStatus
from cyberq.clocks.models import ObligationInstance
from cyberq.filings.generator import generate_certin_packet
from cyberq.filings.models import FilingPacket
from cyberq.governance.models import Para59Exception, RiskDecision
from cyberq.iam.models import RoleGrant, User
from cyberq.iam.policy import Role
from cyberq.incidents.models import Incident, IncidentTrigger, StatutoryTriggerType
from cyberq.intake.models import ToolCompliancePassport

SAMPLE_22_TOOLS: list[dict[str, Any]] = [
    # SIEM
    {"id": "tool-siem-splunk", "name": "Splunk Enterprise Security", "vendor": "Splunk", "category": "SIEM", "trust": "TRUSTED", "days": 180},
    {"id": "tool-siem-qradar", "name": "IBM QRadar SIEM", "vendor": "IBM", "category": "SIEM", "trust": "TRUSTED", "days": 210},
    {"id": "tool-siem-sentinel", "name": "Microsoft Sentinel", "vendor": "Microsoft", "category": "SIEM", "trust": "TRUSTED", "days": 90},
    # EDR / XDR
    {"id": "tool-edr-crowdstrike", "name": "CrowdStrike Falcon Enterprise", "vendor": "CrowdStrike", "category": "EDR", "trust": "TRUSTED", "days": 150},
    {"id": "tool-edr-sentinelone", "name": "SentinelOne Singularity Complete", "vendor": "SentinelOne", "category": "EDR", "trust": "TRUSTED", "days": 120},
    {"id": "tool-edr-defender", "name": "Microsoft Defender for Endpoint", "vendor": "Microsoft", "category": "EDR", "trust": "TRUSTED", "days": 300},
    # Network Firewalls
    {"id": "tool-fw-paloalto", "name": "Palo Alto Networks Strata NGFW", "vendor": "Palo Alto Networks", "category": "Firewall", "trust": "TRUSTED", "days": 140},
    {"id": "tool-fw-cisco", "name": "Cisco Secure Firewall ASA/FTD", "vendor": "Cisco", "category": "Firewall", "trust": "TRUSTED", "days": 110},
    {"id": "tool-fw-fortinet", "name": "Fortinet FortiGate Enterprise", "vendor": "Fortinet", "category": "Firewall", "trust": "TRUSTED", "days": 200},
    {"id": "tool-fw-checkpoint", "name": "Check Point Quantum Security Gateway", "vendor": "Check Point", "category": "Firewall", "trust": "TRUSTED", "days": 160},
    # WAF / ADC
    {"id": "tool-waf-f5", "name": "F5 BIG-IP Advanced WAF", "vendor": "F5 Networks", "category": "WAF", "trust": "TRUSTED", "days": 95},
    {"id": "tool-waf-cloudflare", "name": "Cloudflare Magic Transit & WAF", "vendor": "Cloudflare", "category": "WAF", "trust": "TRUSTED", "days": 85},
    # Database Activity Monitoring (DAM)
    {"id": "tool-dam-imperva", "name": "Imperva SecureSphere DAM", "vendor": "Imperva", "category": "Database Security", "trust": "TRUSTED", "days": 70},
    {"id": "tool-dam-guardium", "name": "IBM Security Guardium Data Protection", "vendor": "IBM", "category": "Database Security", "trust": "TRUSTED", "days": 190},
    # IAM / PAM
    {"id": "tool-pam-cyberark", "name": "CyberArk Privileged Access Manager", "vendor": "CyberArk", "category": "IAM/PAM", "trust": "TRUSTED", "days": 130},
    {"id": "tool-iam-okta", "name": "Okta Workforce Identity Cloud", "vendor": "Okta", "category": "IAM", "trust": "TRUSTED", "days": 220},
    {"id": "tool-iam-entra", "name": "Microsoft Entra ID Governance", "vendor": "Microsoft", "category": "IAM", "trust": "TRUSTED", "days": 175},
    # CSPM / CNAPP
    {"id": "tool-cspm-wiz", "name": "Wiz Cloud Security Platform", "vendor": "Wiz", "category": "Cloud Security", "trust": "TRUSTED", "days": 145},
    {"id": "tool-cspm-prisma", "name": "Palo Alto Prisma Cloud", "vendor": "Palo Alto Networks", "category": "Cloud Security", "trust": "TRUSTED", "days": 80},
    # EXPIRING SOON (VAPT Valid for <= 15 days)
    {"id": "tool-vpn-pulse", "name": "Ivanti Pulse Connect Secure VPN", "vendor": "Ivanti", "category": "VPN Gateway", "trust": "EXPIRING_SOON", "days": 6},
    {"id": "tool-dlp-symantec", "name": "Broadcom Symantec Endpoint DLP", "vendor": "Broadcom", "category": "DLP", "trust": "EXPIRING_SOON", "days": 9},
    # DEGRADED (VAPT Expired, unverified telemetry flagged under Para 90/92)
    {"id": "tool-legacy-ids-snort", "name": "Legacy Branch Perimeter NIDS (Snort v2)", "vendor": "OpenSource / In-House", "category": "NIDS", "trust": "DEGRADED", "days": -18},
]


def seed_demo_crisis_data(
    session: Session,
    audit: AuditService | None = None,
) -> dict[str, Any]:
    """Pre-populates an authentic Indian commercial banking cyber crisis scenario."""
    now = datetime.now(UTC)

    # 1. Ensure Standard Bank Staff Users Exist
    ciso = session.scalar(select(User).where(User.username == "ciso"))
    if not ciso:
        ciso = User(
            id=str(uuid.uuid4()),
            username="ciso",
            email="ciso@sbi-apex.bank.co.in",
            full_name="Rajeshwar V. Iyer (CISO)",
            is_active=True,
        )
        session.add(ciso)
        session.flush()
        session.add(RoleGrant(user_id=ciso.id, role=Role.CISO.value, granted_by="SYSTEM"))

    analyst = session.scalar(select(User).where(User.username == "analyst"))
    if not analyst:
        analyst = User(
            id=str(uuid.uuid4()),
            username="analyst",
            email="analyst@sbi-apex.bank.co.in",
            full_name="Ananya Sen (L2 Lead SOC Analyst)",
            is_active=True,
        )
        session.add(analyst)
        session.flush()
        session.add(RoleGrant(user_id=analyst.id, role=Role.ANALYST.value, granted_by="SYSTEM"))

    approver = session.scalar(select(User).where(User.username == "approver"))
    if not approver:
        approver = User(
            id=str(uuid.uuid4()),
            username="approver",
            email="approver@sbi-apex.bank.co.in",
            full_name="Sunil K. Mahapatra (Chief Compliance Officer)",
            is_active=True,
        )
        session.add(approver)
        session.flush()
        session.add(RoleGrant(user_id=approver.id, role=Role.COMPLIANCE_APPROVER.value, granted_by="SYSTEM"))

    session.flush()

    # 2. Seed 22 Tool Compliance Passports
    seeded_tool_count = 0
    for t in SAMPLE_22_TOOLS:
        existing = session.scalar(select(ToolCompliancePassport).where(ToolCompliancePassport.tool_id == t["id"]))
        expiry_dt = now + timedelta(days=t["days"])
        sbom_digest = hashlib.sha256(f"{t['id']}-cyclonedx-v1.5".encode()).hexdigest()
        pades_hash = hashlib.sha256(f"{t['id']}-certin-pades-audit".encode()).hexdigest()

        if not existing:
            passport = ToolCompliancePassport(
                tool_id=t["id"],
                tool_name=t["name"],
                vendor=t["vendor"],
                category=t["category"],
                stqc_certificate_ref=f"STQC-CERT-{abs(hash(t['id'])) % 100000:05d}",
                auditor_name="CERT-In Empanelled Auditor Consortium",
                vapt_valid_from=now - timedelta(days=180),
                vapt_valid_until=expiry_dt,
                pades_signature_hash=pades_hash,
                cyclonedx_sbom_digest=sbom_digest,
                trust_status=t["trust"],
                para59_exception_ref="EXC-2026-0001" if t["trust"] == "DEGRADED" else None,
            )
            session.add(passport)
            seeded_tool_count += 1
        else:
            existing.trust_status = t["trust"]
            existing.vapt_valid_from = now - timedelta(days=180)
            existing.vapt_valid_until = expiry_dt
            if t["trust"] == "DEGRADED":
                existing.para59_exception_ref = "EXC-2026-0001"

    session.flush()

    # 3. Seed Para 59 Technical Exceptions
    exc1 = session.scalar(select(Para59Exception).where(Para59Exception.exception_number == "EXC-2026-0001"))
    if not exc1:
        exc1 = Para59Exception(
            exception_number="EXC-2026-0001",
            asset_or_system="Legacy Branch Perimeter NIDS (Snort v2)",
            control_reference="RBI Master Direction Para 59.2 - Unverified Tool Exception",
            rationale="Hardware end-of-life replacement cycle underway; sensor awaiting next-gen appliance cutover",
            compensating_controls="Compensating deep packet inspection mirror on core Cisco Nexus switch, daily manual log correlation",
            owner="Branch Network Operations",
            risk_level="high",
            status="active",
            issue_date=now - timedelta(days=80),
            expiry_date=now + timedelta(days=10),  # Expiring in 10 days => Triggers EXPIRING_SOON warning badge!
            created_by_id=ciso.id,
        )
        session.add(exc1)

    exc2 = session.scalar(select(Para59Exception).where(Para59Exception.exception_number == "EXC-2026-0002"))
    if not exc2:
        exc2 = Para59Exception(
            exception_number="EXC-2026-0002",
            asset_or_system="Core Banking Settlement Batch Node",
            control_reference="RBI Para 59.5 - Automated Session Inactivity Timeout Deferral",
            rationale="Batch reconciliation jobs exceed 15-minute standard interactive timeout window",
            compensating_controls="Air-gapped dedicated VLAN, dual-custody physical console authentication, video monitoring",
            owner="Core Banking CBS Ops",
            risk_level="medium",
            status="active",
            issue_date=now - timedelta(days=20),
            expiry_date=now + timedelta(days=70),
            created_by_id=ciso.id,
        )
        session.add(exc2)

    session.flush()

    # 4. Seed CISO Risk Decision
    dec1 = session.scalar(select(RiskDecision).where(RiskDecision.decision_number == "DEC-2026-0001"))
    if not dec1:
        dec1 = RiskDecision(
            decision_number="DEC-2026-0001",
            decision_type="Risk Acceptance",
            status="active",
            rationale="Risk acceptance for 30-day scheduled data center link redundancy maintenance",
            compensating_controls="Hot-standby MPLS secondary line with active BGP route-monitoring",
            owner="Chief Information Security Officer",
            expiry_date=now + timedelta(days=30),
            created_by_id=ciso.id,
            created_at=now - timedelta(days=2),
            countersigned_by_id=approver.id,
            countersigned_at=now - timedelta(days=2),
            countersign_notes="Verified secondary route failover drill; accepted for 30-day migration window",
        )
        session.add(dec1)

    session.flush()

    # 5. Seed 3 Active Bank Cyber Incidents
    # Incident 1: Core Banking Switch ISO-8583 Anomaly (Critical, Running CERT-In 6h & RBI DAKSH 6h clocks)
    inc1 = session.scalar(select(Incident).where(Incident.incident_number == "INC-2026-0001"))
    if not inc1:
        inc1 = Incident(
            id=str(uuid.uuid4()),
            incident_number="INC-2026-0001",
            title="Core Banking Switch ISO-8583 Message Inversion & Account Balance Tampering",
            summary="Suspicious transaction payload mutates ISO-8583 message field 039 response codes across core settlement switch",
            severity="critical",
            status="confirmed",
            is_major=True,
            major_declared_at=now - timedelta(hours=2),
            major_declared_by_id=ciso.id,
            created_at=now - timedelta(hours=2, minutes=30),
            created_by_id=analyst.id,
        )
        session.add(inc1)
        session.flush()

        # Add detected and noticed triggers
        trig_not = IncidentTrigger(
            incident_id=inc1.id,
            trigger_type=StatutoryTriggerType.NOTICED.value,
            occurred_at=now - timedelta(hours=2, minutes=30),
            recorded_at=now - timedelta(hours=2, minutes=30),
            evidence_summary="SIEM correlation rule alerted anomalous ISO-8583 field modification",
            rationale="Statutory notice timestamp locked per CERT-In Directions 2022",
            asserted_by_id=analyst.id,
        )
        trig_det = IncidentTrigger(
            incident_id=inc1.id,
            trigger_type=StatutoryTriggerType.DETECTED.value,
            occurred_at=now - timedelta(hours=2),
            recorded_at=now - timedelta(hours=2),
            evidence_summary="SOC Lead forensics confirmed memory modification on CBS switch process",
            rationale="Statutory detection timestamp locked per RBI Master Directions Para 182",
            asserted_by_id=analyst.id,
        )
        session.add_all([trig_not, trig_det])
        session.flush()

        # Add running obligations
        obl_certin = ObligationInstance(
            incident_id=inc1.id,
            pack_id="certin_directions_2022",
            regulator="CERT-In",
            status="running",
            deadline_at=now + timedelta(hours=3, minutes=30),
            active_deadline_at=now + timedelta(hours=3, minutes=30),
            next_due_at=now + timedelta(hours=3, minutes=30),
            escalation_level=0,
            applicability_status="applicable",
        )
        obl_daksh = ObligationInstance(
            incident_id=inc1.id,
            pack_id="rbi_cybersecurity_directions_2026",
            regulator="RBI",
            status="running",
            deadline_at=now + timedelta(hours=4),
            active_deadline_at=now + timedelta(hours=4),
            next_due_at=now + timedelta(hours=4),
            escalation_level=0,
            applicability_status="applicable",
        )
        session.add_all([obl_certin, obl_daksh])
        session.flush()

        # Prepare Draft Statutory Filing Packets
        pkt_certin_payload = generate_certin_packet(
            incident_number=inc1.incident_number,
            title=inc1.title,
            summary=inc1.summary,
            severity=inc1.severity,
            occurred_at=trig_not.occurred_at,
            compromised_systems=["Core Banking Switch Gateway", "ISO-8583 Message Broker"],
            cve_ids=["CVE-2024-21413"],
        )
        raw_c_bytes = canonical_json(pkt_certin_payload)
        pkt_c_hash = hashlib.sha256(raw_c_bytes).hexdigest()

        pkt1 = FilingPacket(
            incident_id=inc1.id,
            pack_id="certin_directions_2022",
            regulator="CERT-In",
            version=1,
            status="draft",
            packet_hash=pkt_c_hash,
            packet_data=pkt_certin_payload,
            prepared_by_id=analyst.id,
            prepared_at=now - timedelta(hours=2),
        )
        session.add(pkt1)

    # Incident 2: UPI API Gateway DDoS & Credential Stuffing (High, running DPDP 72h clock)
    inc2 = session.scalar(select(Incident).where(Incident.incident_number == "INC-2026-0002"))
    if not inc2:
        inc2 = Incident(
            id=str(uuid.uuid4()),
            incident_number="INC-2026-0002",
            title="UPI API Gateway DDoS & Distributed Credential Stuffing",
            summary="High velocity distributed authentication attempts against mobile banking UPI endpoint",
            severity="high",
            status="triaged",
            is_major=False,
            created_at=now - timedelta(hours=1, minutes=15),
            created_by_id=analyst.id,
        )
        session.add(inc2)
        session.flush()

        trig_aware = IncidentTrigger(
            incident_id=inc2.id,
            trigger_type=StatutoryTriggerType.AWARE.value,
            occurred_at=now - timedelta(hours=1),
            recorded_at=now - timedelta(hours=1),
            evidence_summary="Credential enumeration identified breached customer phone numbers and hashed PIN attempts",
            rationale="DPDP Rule 7 awareness threshold reached by Incident Commander",
            asserted_by_id=analyst.id,
        )
        session.add(trig_aware)
        session.flush()

        obl_dpdp = ObligationInstance(
            incident_id=inc2.id,
            pack_id="dpdp_rules_2025",
            regulator="DPDP",
            status="running",
            deadline_at=now + timedelta(hours=71),
            active_deadline_at=now + timedelta(hours=71),
            next_due_at=now + timedelta(hours=71),
            escalation_level=0,
            applicability_status="applicable",
        )
        session.add(obl_dpdp)

    # Incident 3: Treasury SWIFT Endpoint EDR Memory Injection (Provisional Triage MSSP Safe-Harbor 30m)
    inc3 = session.scalar(select(Incident).where(Incident.incident_number == "INC-2026-0003"))
    if not inc3:
        inc3 = Incident(
            id=str(uuid.uuid4()),
            incident_number="INC-2026-0003",
            title="Treasury SWIFT Terminal EDR Memory Injection Alert",
            summary="CrowdStrike EDR detected shellcode injection into SWIFT Alliance Access interface process",
            severity="critical",
            status="new",
            is_major=False,
            created_at=now - timedelta(minutes=8),
            created_by_id=analyst.id,
        )
        session.add(inc3)
        session.flush()

        # MSSP Provisional Triage Obligation (starts with PROVISIONAL_TRIAGE status)
        obl_mssp = ObligationInstance(
            incident_id=inc3.id,
            pack_id="rbi_cybersecurity_directions_2026",
            regulator="RBI",
            status=ClockStatus.PROVISIONAL_TRIAGE.value,
            deadline_at=now + timedelta(hours=5, minutes=52),
            active_deadline_at=now + timedelta(hours=5, minutes=52),
            next_due_at=now + timedelta(hours=5, minutes=52),
            escalation_level=0,
            applicability_status="applicable",
        )
        session.add(obl_mssp)

    session.commit()

    return {
        "status": "SEEDED_SUCCESSFULLY",
        "tools_registered": len(SAMPLE_22_TOOLS),
        "incidents_seeded": 3,
        "exceptions_active": 2,
        "decisions_active": 1,
        "seeded_at": now.isoformat(),
    }
