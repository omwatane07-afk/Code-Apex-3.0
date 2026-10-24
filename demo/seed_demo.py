"""Seed script for CYBERQ demonstration.

Creates 5 realistic bank personas across all required roles,
and pre-seeds synthetic commercial banking incidents with audit trails.
Refuses to run in production mode.
"""

import os
import sys
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

# Set demo environment before importing settings
os.environ.setdefault("CYBERQ_ENV", "demo")
os.environ.setdefault("SESSION_SECRET", "cyberq-super-secret-key-32-chars-minimum!")

repo_root = Path(__file__).resolve().parent.parent
backend_src = repo_root / "backend" / "src"
if str(backend_src) not in sys.path:
    sys.path.insert(0, str(backend_src))

from cyberq.audit.chain import AuditService
from cyberq.audit.models import AuditEvent
from cyberq.core.config import EnvironmentType, get_settings
from sqlalchemy import select
from cyberq.core.database import Base, SessionLocal, engine
from cyberq.clocks.models import ObligationInstance
from cyberq.iam.models import RoleGrant, User
from cyberq.iam.policy import Role
from cyberq.incidents.models import Incident, IncidentTrigger

settings = get_settings()
if settings.ENV == EnvironmentType.PRODUCTION:
    print("FATAL: seed_demo.py is strictly forbidden in production mode!", file=sys.stderr)
    sys.exit(1)

DEMO_USERS = [
    {
        "username": "analyst.sharma",
        "email": "aarav.sharma@bank.internal",
        "full_name": "Aarav Sharma (SOC Analyst)",
        "role": Role.ANALYST,
    },
    {
        "username": "approver.deshmukh",
        "email": "priya.deshmukh@bank.internal",
        "full_name": "Priya Deshmukh (Compliance Approver)",
        "role": Role.COMPLIANCE_APPROVER,
    },
    {
        "username": "ciso.menon",
        "email": "rajesh.menon@bank.internal",
        "full_name": "Rajesh Menon (Chief Information Security Officer)",
        "role": Role.CISO,
    },
    {
        "username": "auditor.iyer",
        "email": "sunita.iyer@bank.internal",
        "full_name": "Sunita Iyer (Lead IS Auditor)",
        "role": Role.AUDITOR,
    },
    {
        "username": "admin.kulkarni",
        "email": "vikram.kulkarni@bank.internal",
        "full_name": "Vikram Kulkarni (System Administrator)",
        "role": Role.ADMIN,
    },
]


def seed() -> None:
    print(f"Initializing database for environment: {settings.ENV.value}...")
    from cyberq.core.database import init_db
    init_db()

    with SessionLocal() as db:
        print("Seeding demo users...")
        created_users: dict[str, User] = {}
        for u in DEMO_USERS:
            existing = db.query(User).filter(User.username == u["username"]).first()
            if not existing:
                user = User(
                    id=str(uuid.uuid4()),
                    username=u["username"],
                    email=u["email"],
                    full_name=u["full_name"],
                    is_active=True,
                )
                db.add(user)
                db.flush()
                grant = RoleGrant(
                    id=str(uuid.uuid4()),
                    user_id=user.id,
                    role=u["role"].value,
                    granted_by="system_seed",
                )
                db.add(grant)
                created_users[u["role"].value] = user
                print(f"  + Created {u['full_name']} [{u['role'].value}]")
            else:
                created_users[u["role"].value] = existing
                print(f"  * Existing {u['full_name']}")

        analyst = created_users.get("analyst") or db.query(User).first()
        now = datetime.now(UTC)

        print("Seeding synthetic commercial banking incidents...")
        inc1_num = "INC-2026-0001"
        inc1 = db.query(Incident).filter(Incident.incident_number == inc1_num).first()
        if not inc1:
            inc1 = Incident(
                id=str(uuid.uuid4()),
                incident_number=inc1_num,
                title="Core switch routing loop impacting RTGS settlement channel",
                summary="Intermittent packet loss and BGP neighbor flapping detected on primary datacenter core router DC1-RT-01.",
                severity="critical",
                status="triage",
                created_by_id=analyst.id if analyst else "analyst-01",
                created_at=now - timedelta(minutes=15),
                updated_at=now - timedelta(minutes=5),
            )
            db.add(inc1)
            db.flush()

            # Simultaneous CERT-In noticed and RBI detected triggers at exact same time
            occ_time = now - timedelta(minutes=10)
            t_certin = IncidentTrigger(
                id=str(uuid.uuid4()),
                incident_id=inc1.id,
                trigger_type="noticed",
                occurred_at=occ_time,
                recorded_at=occ_time,
                asserted_by_id=analyst.id if analyst else "analyst-01",
                evidence_summary="SIEM alert correlation #89201 on BGP reset",
                rationale="Threshold breached on primary datacenter core router.",
                is_disputed=False,
            )
            t_rbi = IncidentTrigger(
                id=str(uuid.uuid4()),
                incident_id=inc1.id,
                trigger_type="detected",
                occurred_at=occ_time,
                recorded_at=occ_time,
                asserted_by_id=analyst.id if analyst else "analyst-01",
                evidence_summary="SIEM alert correlation #89201 on BGP reset",
                rationale="Material disruption to RTGS payment system channel.",
                is_disputed=False,
            )
            db.add(t_certin)
            db.add(t_rbi)

            # Obligations
            deadline_6h = occ_time + timedelta(hours=6)
            obl_certin = ObligationInstance(
                id=str(uuid.uuid4()),
                incident_id=inc1.id,
                pack_id="certin-directions-2022",
                regulator="CERT-In",
                status="running",
                deadline_at=deadline_6h,
                active_deadline_at=deadline_6h,
                next_due_at=deadline_6h - timedelta(hours=4),
                applicability_status="assumed_applicable",
            )
            obl_rbi = ObligationInstance(
                id=str(uuid.uuid4()),
                incident_id=inc1.id,
                pack_id="rbi-cybersecurity-directions-2026",
                regulator="RBI",
                status="running",
                deadline_at=deadline_6h,
                active_deadline_at=deadline_6h,
                next_due_at=deadline_6h - timedelta(hours=4),
                applicability_status="assumed_applicable",
            )
            obl_dpdp = ObligationInstance(
                id=str(uuid.uuid4()),
                incident_id=inc1.id,
                pack_id="dpdp-rules-2025",
                regulator="DPDP",
                status="pending_trigger",
                deadline_at=None,
                active_deadline_at=None,
                next_due_at=None,
                applicability_status="not_in_force",
            )
            db.add(obl_certin)
            db.add(obl_rbi)
            db.add(obl_dpdp)
            print(f"  + Created {inc1_num} with active CERT-In and RBI clocks")

        inc2_num = "INC-2026-0002"
        inc2 = db.query(Incident).filter(Incident.incident_number == inc2_num).first()
        if not inc2:
            inc2 = Incident(
                id=str(uuid.uuid4()),
                incident_number=inc2_num,
                title="Vendor payment gateway staging credentials exposed on public GitHub repository",
                summary="Automated secret scan detected hardcoded merchant staging API keys and HMAC webhook secrets in public fork of payment connector. Key revoked, audit of transaction logs underway.",
                severity="high",
                status="investigating",
                created_by_id=analyst.id if analyst else "analyst-01",
                created_at=now - timedelta(hours=1, minutes=15),
                updated_at=now - timedelta(minutes=20),
            )
            db.add(inc2)
            db.flush()

            occ2_time = now - timedelta(minutes=45)
            t_certin2 = IncidentTrigger(
                id=str(uuid.uuid4()),
                incident_id=inc2.id,
                trigger_type="noticed",
                occurred_at=occ2_time,
                recorded_at=occ2_time,
                asserted_by_id=analyst.id if analyst else "analyst-01",
                evidence_summary="GitHub secret alert webhook #99182 on merchant connector repo",
                rationale="Credential compromise confirmed by SOC tier 2 analyst.",
                is_disputed=False,
            )
            db.add(t_certin2)

            deadline_6h_inc2 = occ2_time + timedelta(hours=6)
            obl2_certin = ObligationInstance(
                id=str(uuid.uuid4()),
                incident_id=inc2.id,
                pack_id="certin-directions-2022",
                regulator="CERT-In",
                status="running",
                deadline_at=deadline_6h_inc2,
                active_deadline_at=deadline_6h_inc2,
                next_due_at=deadline_6h_inc2 - timedelta(hours=4),
                applicability_status="assumed_applicable",
            )
            obl2_rbi = ObligationInstance(
                id=str(uuid.uuid4()),
                incident_id=inc2.id,
                pack_id="rbi-cybersecurity-directions-2026",
                regulator="RBI",
                status="running",
                deadline_at=deadline_6h_inc2,
                active_deadline_at=deadline_6h_inc2,
                next_due_at=deadline_6h_inc2 - timedelta(hours=4),
                applicability_status="assumed_applicable",
            )
            obl2_dpdp = ObligationInstance(
                id=str(uuid.uuid4()),
                incident_id=inc2.id,
                pack_id="dpdp-rules-2025",
                regulator="DPDP",
                status="pending_trigger",
                deadline_at=None,
                active_deadline_at=None,
                next_due_at=None,
                applicability_status="assumed_applicable",
            )
            db.add(obl2_certin)
            db.add(obl2_rbi)
            db.add(obl2_dpdp)
            print(f"  + Created {inc2_num} with active CERT-In and RBI clocks")

        inc3_num = "INC-2026-0003"
        inc3 = db.query(Incident).filter(Incident.incident_number == inc3_num).first()
        if not inc3:
            inc3 = Incident(
                id=str(uuid.uuid4()),
                incident_number=inc3_num,
                title="Core Banking System (CBS) NEFT batch processing timeout",
                summary="EOD clearing batch processing latency exceeded SLA threshold (90 min delay) due to Oracle database tablespace exhaustion during holiday settlement surge. No data loss observed.",
                severity="medium",
                status="contained",
                created_by_id=analyst.id if analyst else "analyst-01",
                created_at=now - timedelta(hours=3),
                updated_at=now - timedelta(minutes=30),
            )
            db.add(inc3)
            db.flush()

            occ3_time = now - timedelta(hours=2)
            t_rbi3 = IncidentTrigger(
                id=str(uuid.uuid4()),
                incident_id=inc3.id,
                trigger_type="detected",
                occurred_at=occ3_time,
                recorded_at=occ3_time,
                asserted_by_id=analyst.id if analyst else "analyst-01",
                evidence_summary="CBS APM alert #4412 on NEFT settlement batch stall",
                rationale="Disruption to clearing window under RBI Master Direction.",
                is_disputed=False,
            )
            db.add(t_rbi3)

            deadline_6h_inc3 = occ3_time + timedelta(hours=6)
            obl3_certin = ObligationInstance(
                id=str(uuid.uuid4()),
                incident_id=inc3.id,
                pack_id="certin-directions-2022",
                regulator="CERT-In",
                status="running",
                deadline_at=deadline_6h_inc3,
                active_deadline_at=deadline_6h_inc3,
                next_due_at=deadline_6h_inc3 - timedelta(hours=4),
                applicability_status="assumed_applicable",
            )
            obl3_rbi = ObligationInstance(
                id=str(uuid.uuid4()),
                incident_id=inc3.id,
                pack_id="rbi-cybersecurity-directions-2026",
                regulator="RBI",
                status="running",
                deadline_at=deadline_6h_inc3,
                active_deadline_at=deadline_6h_inc3,
                next_due_at=deadline_6h_inc3 - timedelta(hours=4),
                applicability_status="assumed_applicable",
            )
            obl3_dpdp = ObligationInstance(
                id=str(uuid.uuid4()),
                incident_id=inc3.id,
                pack_id="dpdp-rules-2025",
                regulator="DPDP",
                status="pending_trigger",
                deadline_at=None,
                active_deadline_at=None,
                next_due_at=None,
                applicability_status="assumed_applicable",
            )
            db.add(obl3_certin)
            db.add(obl3_rbi)
            db.add(obl3_dpdp)
            print(f"  + Created {inc3_num} with active RBI clock (status: contained)")

        # Seed an active Risk Decision for CISO
        from cyberq.governance.models import RiskDecision
        existing_dec = db.scalar(select(RiskDecision).where(RiskDecision.decision_number == "DEC-2026-0001"))
        if not existing_dec:
            dec1 = RiskDecision(
                id=str(uuid.uuid4()),
                decision_number="DEC-2026-0001",
                incident_id=inc1.id,
                decision_type="Temporary Risk Acceptance",
                status="active",
                rationale="RTGS traffic rerouted to redundant DC-2 fiber path while DC-1 core switch diagnostic capture is performed.",
                compensating_controls="24x7 SOC manual queue monitoring, micro-batch settlement limits enforced, dual-operator approval on settlements > 50 Cr.",
                owner="Chief Information Security Officer",
                expiry_date=datetime.now(UTC) + timedelta(days=14),
                created_by_id=created_users["ciso"].id,
                countersigned_by_id=created_users["compliance_approver"].id,
                countersigned_at=datetime.now(UTC),
                countersign_notes="Dual-control risk acceptance verified per RBI Cyber Security Framework Section 4.3.",
            )
            db.add(dec1)
            db.commit()
            print("  + Created active risk decision DEC-2026-0001 (countersigned)")

        # Audit chain genesis and event
        audit_svc = AuditService(settings.AUDIT_SIGNING_SEED)
        audit_svc.record_event(
            session=db,
            actor_id="system_seed",
            actor_role="admin",
            action="seed_demo_state",
            entity_type="system",
            entity_id="demo-seed",
            before_state=None,
            after_state={"environment": "demo", "incident_count": 3, "user_count": 5, "decision_count": 1},
        )
        print("  + Audit event recorded for demo seed initialization")

    print("\n==> DEMO STATE SEED COMPLETED SUCCESSFULLY <==")


if __name__ == "__main__":
    seed()
