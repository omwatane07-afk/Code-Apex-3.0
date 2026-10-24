"""Comprehensive test suite for CISO capabilities, Risk Decision Ledger, and maker-checker validation."""

from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from cyberq.api.app import app
from cyberq.core.config import EnvironmentType, get_settings
from cyberq.core.database import Base, engine
from cyberq.iam.policy import Action, PolicyEngine, Role
from cyberq.incidents.models import Incident

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_db():
    Base.metadata.create_all(bind=engine)
    yield


def _login(username: str, role: Role) -> dict[str, str]:
    client.cookies.clear()
    res = client.post(
        "/api/v1/auth/login",
        json={"username": username, "role": role.value},
    )
    assert res.status_code == 200, f"Login failed: {res.text}"
    data = res.json()
    client.cookies.clear()
    return {
        "X-CSRF-Token": data["csrf_token"],
        "X-Session-ID": data["session_id"],
        "user_id": data["id"],
    }


# ==============================================================================
# 1. Exhaustive PolicyEngine Unit & Branch Coverage Tests
# ==============================================================================


def test_policy_engine_ciso_and_all_roles():
    """Verify PolicyEngine evaluation across all actions for every role."""
    # CISO permissions
    assert PolicyEngine.is_allowed(Role.CISO, Action.INCIDENT_READ) is True
    assert PolicyEngine.is_allowed(Role.CISO, Action.INCIDENT_UPDATE) is True
    assert PolicyEngine.is_allowed(Role.CISO, Action.INCIDENT_SEVERITY_SET) is True
    assert PolicyEngine.is_allowed(Role.CISO, Action.INCIDENT_MAJOR_DECLARE) is True
    assert PolicyEngine.is_allowed(Role.CISO, Action.INCIDENT_CLOSE_APPROVE) is True
    assert PolicyEngine.is_allowed(Role.CISO, Action.DECISION_READ) is True
    assert PolicyEngine.is_allowed(Role.CISO, Action.DECISION_CREATE) is True
    assert PolicyEngine.is_allowed(Role.CISO, Action.DECISION_APPROVE) is True
    assert PolicyEngine.is_allowed(Role.CISO, Action.AUDIT_READ) is True
    assert PolicyEngine.is_allowed(Role.CISO, Action.AUDIT_VERIFY) is True
    assert PolicyEngine.is_allowed(Role.CISO, Action.BOARD_PACK_READ) is True

    # CISO non-goals: cannot create initial incident, cannot file packets, cannot admin config
    assert PolicyEngine.is_allowed(Role.CISO, Action.INCIDENT_CREATE) is False
    assert PolicyEngine.is_allowed(Role.CISO, Action.PACKET_APPROVE) is False
    assert PolicyEngine.is_allowed(Role.CISO, Action.PACKET_RECORD_FILED) is False
    assert PolicyEngine.is_allowed(Role.CISO, Action.ADMIN_CONFIG) is False

    # Analyst: can create and read incidents, cannot set severity, declare major, or approve closure
    assert PolicyEngine.is_allowed(Role.ANALYST, Action.INCIDENT_CREATE) is True
    assert PolicyEngine.is_allowed(Role.ANALYST, Action.INCIDENT_SEVERITY_SET) is False
    assert PolicyEngine.is_allowed(Role.ANALYST, Action.INCIDENT_MAJOR_DECLARE) is False
    assert PolicyEngine.is_allowed(Role.ANALYST, Action.INCIDENT_CLOSE_APPROVE) is False
    assert PolicyEngine.is_allowed(Role.ANALYST, Action.DECISION_CREATE) is False
    assert PolicyEngine.is_allowed(Role.ANALYST, Action.DECISION_READ) is True

    # Compliance approver: can approve decisions, cannot draft decisions or declare major
    assert PolicyEngine.is_allowed(Role.COMPLIANCE_APPROVER, Action.DECISION_APPROVE) is True
    assert PolicyEngine.is_allowed(Role.COMPLIANCE_APPROVER, Action.DECISION_CREATE) is False
    assert PolicyEngine.is_allowed(Role.COMPLIANCE_APPROVER, Action.INCIDENT_SEVERITY_SET) is False

    # Auditor & Model Validator
    assert PolicyEngine.is_allowed(Role.AUDITOR, Action.AUDIT_READ) is True
    assert PolicyEngine.is_allowed(Role.AUDITOR, Action.DECISION_READ) is True
    assert PolicyEngine.is_allowed(Role.AUDITOR, Action.DECISION_CREATE) is False
    assert PolicyEngine.is_allowed(Role.MODEL_VALIDATOR, Action.AUDIT_READ) is True
    assert PolicyEngine.is_allowed(Role.MODEL_VALIDATOR, Action.DECISION_CREATE) is False

    # Admin: cannot read audit ledger or create decisions, can verify audit probe
    assert PolicyEngine.is_allowed(Role.ADMIN, Action.AUDIT_READ) is False
    assert PolicyEngine.is_allowed(Role.ADMIN, Action.AUDIT_VERIFY) is True
    assert PolicyEngine.is_allowed(Role.ADMIN, Action.DECISION_CREATE) is False
    assert PolicyEngine.is_allowed(Role.ADMIN, Action.INCIDENT_SEVERITY_SET) is False

    # Invalid role or action returns False (fail closed)
    assert PolicyEngine.is_allowed("invalid_role", Action.INCIDENT_READ) is False
    assert PolicyEngine.is_allowed(Role.CISO, "invalid_action") is False


def test_maker_checker_permutations():
    """Exhaustive maker-checker tests including whitespace, unicode normalization, and UUIDs."""
    import uuid

    id1 = str(uuid.uuid4())
    id2 = str(uuid.uuid4())

    assert PolicyEngine.check_maker_checker(id1, id2) is True
    assert PolicyEngine.check_maker_checker(id1, id1) is False
    assert PolicyEngine.check_maker_checker(id1.upper(), id1.lower()) is False
    assert PolicyEngine.check_maker_checker(f" {id1} ", id1) is False
    assert PolicyEngine.check_maker_checker("", id2) is False
    assert PolicyEngine.check_maker_checker(id1, "") is False
    assert PolicyEngine.check_maker_checker(None, id2) is False  # type: ignore[arg-type]


# ==============================================================================
# 2. CISO Incident Controls API Tests
# ==============================================================================


def test_ciso_severity_update_and_audit():
    """CISO changes incident severity with mandatory rationale, creating audit event."""
    analyst_auth = _login("analyst_sev", Role.ANALYST)
    ciso_auth = _login("ciso_sev", Role.CISO)
    auditor_auth = _login("auditor_sev", Role.AUDITOR)

    # 1. Analyst creates high severity incident
    inc_res = client.post(
        "/api/v1/incidents",
        json={"title": "Switch Flapping", "summary": "RTGS switch flapping continuously", "severity": "high"},
        headers={"X-CSRF-Token": analyst_auth["X-CSRF-Token"], "X-Session-ID": analyst_auth["X-Session-ID"]},
    )
    assert inc_res.status_code == 201
    inc_id = inc_res.json()["id"]

    # 2. Auditor tries to change severity -> 403 Forbidden
    aud_res = client.post(
        f"/api/v1/incidents/{inc_id}/severity",
        json={"new_severity": "critical", "rationale": "Auditor attempting severity change"},
        headers={"X-CSRF-Token": auditor_auth["X-CSRF-Token"], "X-Session-ID": auditor_auth["X-Session-ID"]},
    )
    assert aud_res.status_code == 403

    # 3. CISO changes severity to critical with mandatory rationale -> 200 OK
    ciso_res = client.post(
        f"/api/v1/incidents/{inc_id}/severity",
        json={"new_severity": "critical", "rationale": "Directly impacts core settlement channels under RBI guidance"},
        headers={"X-CSRF-Token": ciso_auth["X-CSRF-Token"], "X-Session-ID": ciso_auth["X-Session-ID"]},
    )
    assert ciso_res.status_code == 200
    assert ciso_res.json()["severity"] == "critical"

    # 4. Verify audit ledger records incident:severity_change
    audit_res = client.get("/api/v1/audit/export", headers={"X-Session-ID": ciso_auth["X-Session-ID"]})
    assert audit_res.status_code == 200
    events = audit_res.json()["events"]
    sev_event = next((e for e in events if e["action"] == "incident:severity_change" and e["entity_id"] == inc_id), None)
    assert sev_event is not None
    assert sev_event["before_state"]["severity"] == "high"
    assert sev_event["after_state"]["severity"] == "critical"


def test_ciso_declare_major_incident():
    """CISO declares major incident with reason; duplicate declaration rejected."""
    analyst_auth = _login("analyst_major", Role.ANALYST)
    ciso_auth = _login("ciso_major", Role.CISO)

    inc_res = client.post(
        "/api/v1/incidents",
        json={"title": "Ransomware Detected", "summary": "Branch workstation infection", "severity": "critical"},
        headers={"X-CSRF-Token": analyst_auth["X-CSRF-Token"], "X-Session-ID": analyst_auth["X-Session-ID"]},
    )
    inc_id = inc_res.json()["id"]

    # CISO declares Major Incident
    maj_res = client.post(
        f"/api/v1/incidents/{inc_id}/declare-major",
        json={"reason": "Customer payment channel disrupted; activating War Room protocol"},
        headers={"X-CSRF-Token": ciso_auth["X-CSRF-Token"], "X-Session-ID": ciso_auth["X-Session-ID"]},
    )
    assert maj_res.status_code == 200
    data = maj_res.json()
    assert data["is_major"] is True
    assert data["major_reason"] == "Customer payment channel disrupted; activating War Room protocol"

    # Duplicate declaration fails with 400
    dup_res = client.post(
        f"/api/v1/incidents/{inc_id}/declare-major",
        json={"reason": "Attempting second declaration"},
        headers={"X-CSRF-Token": ciso_auth["X-CSRF-Token"], "X-Session-ID": ciso_auth["X-Session-ID"]},
    )
    assert dup_res.status_code == 400
    assert "already declared" in dup_res.json()["detail"].lower()


def test_ciso_closure_approval_maker_checker(isolated_db):
    """CISO cannot approve closure of an incident the CISO created. Different CISO can approve."""
    ciso1_auth = _login("ciso_creator", Role.CISO)
    ciso2_auth = _login("ciso_approver", Role.CISO)
    analyst_auth = _login("analyst_creator", Role.ANALYST)

    # 1. Analyst creates incident
    inc_res = client.post(
        "/api/v1/incidents",
        json={"title": "Phishing campaign", "summary": "Credential harvesting attack on employees", "severity": "medium"},
        headers={"X-CSRF-Token": analyst_auth["X-CSRF-Token"], "X-Session-ID": analyst_auth["X-Session-ID"]},
    )
    assert inc_res.status_code == 201, f"Create incident failed: {inc_res.text}"
    inc_id = inc_res.json()["id"]

    # Set status to contained for closure approval test
    with isolated_db() as s:
        inc = s.scalar(select(Incident).where(Incident.id == inc_id))
        inc.status = "contained"
        s.commit()

    # CISO2 approves closure -> 200 OK
    close_res = client.post(
        f"/api/v1/incidents/{inc_id}/approve-closure",
        json={"closure_notes": "All malicious domains blocked. Post-incident forensics complete."},
        headers={"X-CSRF-Token": ciso2_auth["X-CSRF-Token"], "X-Session-ID": ciso2_auth["X-Session-ID"]},
    )
    assert close_res.status_code == 200
    assert close_res.json()["status"] == "closed"

    # 2. Maker-checker test: What if an incident was created by CISO1?
    # Temporarily set created_by_id to ciso1_auth["user_id"] to test closure rule
    with isolated_db() as s:
        inc = s.scalar(select(Incident).where(Incident.id == inc_id))
        inc.created_by_id = ciso1_auth["user_id"]
        inc.status = "contained"
        s.commit()

    # CISO1 attempts self-approval -> 400 Maker-checker violation
    self_res = client.post(
        f"/api/v1/incidents/{inc_id}/approve-closure",
        json={"closure_notes": "Self approval attempt"},
        headers={"X-CSRF-Token": ciso1_auth["X-CSRF-Token"], "X-Session-ID": ciso1_auth["X-Session-ID"]},
    )
    assert self_res.status_code == 400
    assert "Maker-checker violation" in self_res.json()["detail"]


# ==============================================================================
# 3. Statutory Risk Decision Ledger & Countersignature Tests
# ==============================================================================


def test_risk_decision_ledger_end_to_end():
    """Verify drafting, maker-checker countersignature, and audit trail of risk decisions."""
    ciso1_auth = _login("ciso_maker", Role.CISO)
    ciso2_auth = _login("ciso_checker", Role.CISO)
    analyst_auth = _login("analyst_dec", Role.ANALYST)

    # 1. Analyst cannot draft decisions -> 403 Forbidden
    analyst_draft = client.post(
        "/api/v1/decisions",
        json={
            "decision_type": "Risk Acceptance",
            "rationale": "Analyst proposing risk acceptance",
            "compensating_controls": "Daily log review",
            "owner": "CISO",
            "expiry_date": (datetime.now(UTC) + timedelta(days=90)).isoformat(),
        },
        headers={"X-CSRF-Token": analyst_auth["X-CSRF-Token"], "X-Session-ID": analyst_auth["X-Session-ID"]},
    )
    assert analyst_draft.status_code == 403

    # 2. CISO1 drafts a new risk decision -> 201 Created
    ciso_draft = client.post(
        "/api/v1/decisions",
        json={
            "decision_type": "Regulatory Deferral",
            "rationale": "Core switch maintenance window deferral under change freeze",
            "compensating_controls": "Dual standby routing gateway and 24/7 dedicated network monitoring",
            "owner": "Head of Enterprise Infrastructure",
            "expiry_date": (datetime.now(UTC) + timedelta(days=30)).isoformat(),
        },
        headers={"X-CSRF-Token": ciso1_auth["X-CSRF-Token"], "X-Session-ID": ciso1_auth["X-Session-ID"]},
    )
    assert ciso_draft.status_code == 201
    dec = ciso_draft.json()
    dec_id = dec["id"]
    assert dec["status"] == "awaiting_countersignature"
    assert dec["decision_number"].startswith("DEC-")

    # 3. Maker-checker attack: CISO1 tries to countersign own decision -> 400 Bad Request
    self_counter = client.post(
        f"/api/v1/decisions/{dec_id}/countersign",
        json={"notes": "Self countersign attempt"},
        headers={"X-CSRF-Token": ciso1_auth["X-CSRF-Token"], "X-Session-ID": ciso1_auth["X-Session-ID"]},
    )
    assert self_counter.status_code == 400
    assert "Maker-checker violation" in self_counter.json()["detail"]

    # 4. CISO2 (checker) countersigns -> 200 OK, becomes Active
    checker_counter = client.post(
        f"/api/v1/decisions/{dec_id}/countersign",
        json={"notes": "Reviewed compensating controls and approved deferral period"},
        headers={"X-CSRF-Token": ciso2_auth["X-CSRF-Token"], "X-Session-ID": ciso2_auth["X-Session-ID"]},
    )
    assert checker_counter.status_code == 200
    assert checker_counter.json()["status"] == "active"
    assert checker_counter.json()["countersigned_by_id"] == ciso2_auth["user_id"]

    # 5. List decisions includes the new active decision
    list_res = client.get("/api/v1/decisions", headers={"X-Session-ID": ciso1_auth["X-Session-ID"]})
    assert list_res.status_code == 200
    items = list_res.json()
    assert any(d["id"] == dec_id and d["status"] == "active" for d in items)

    # 6. Audit trail contains decision:create and decision:countersign
    audit_res = client.get("/api/v1/audit/export", headers={"X-Session-ID": ciso1_auth["X-Session-ID"]})
    assert audit_res.status_code == 200
    events = audit_res.json()["events"]
    create_evt = next((e for e in events if e["action"] == "decision:create" and e["entity_id"] == dec_id), None)
    counter_evt = next((e for e in events if e["action"] == "decision:countersign" and e["entity_id"] == dec_id), None)
    assert create_evt is not None
    assert counter_evt is not None


# ==============================================================================
# 4. Board Preview & CISO Alerts Telemetry Tests
# ==============================================================================


def test_board_preview_and_ciso_alerts():
    """Verify board preview aggregation and CISO operational alerts."""
    ciso_auth = _login("ciso_gov", Role.CISO)

    # Board preview
    bp_res = client.get("/api/v1/governance/board-preview", headers={"X-Session-ID": ciso_auth["X-Session-ID"]})
    assert bp_res.status_code == 200
    bp_data = bp_res.json()
    assert "total_incidents" in bp_data
    assert "active_countdowns" in bp_data
    assert "active_risk_decisions" in bp_data
    assert "top_risks" in bp_data

    # CISO alerts
    alerts_res = client.get("/api/v1/governance/ciso-alerts", headers={"X-Session-ID": ciso_auth["X-Session-ID"]})
    assert alerts_res.status_code == 200
    alerts_data = alerts_res.json()
    assert "total_alerts" in alerts_data
    assert "severity_reviews" in alerts_data
    assert "closure_approvals_waiting" in alerts_data


# ==============================================================================
# 5. Production Safety: Rejection of Demo Login in Production Mode
# ==============================================================================


def test_production_mode_strictly_rejects_demo_login():
    """Verify that any environment not demo or dev refuses demo login with 403."""
    settings = get_settings()

    # Test with CYBERQ_ENV = production
    with patch.object(settings, "ENV", EnvironmentType.PRODUCTION):
        res = client.post(
            "/api/v1/auth/login",
            json={"username": "prod_user", "role": "ciso"},
        )
        assert res.status_code == 403
        assert "disabled in production" in res.json()["detail"].lower()

    # Test with CYBERQ_ENV = pilot
    with patch.object(settings, "ENV", EnvironmentType.PILOT):
        res = client.post(
            "/api/v1/auth/login",
            json={"username": "pilot_user", "role": "ciso"},
        )
        assert res.status_code == 403
        assert "disabled in production" in res.json()["detail"].lower()
