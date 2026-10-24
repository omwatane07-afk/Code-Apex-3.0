"""DeepTest integrity suite: Maker-Checker RBAC, statutory UTC clocks, and cryptographic ledger verification.

Guarantees:
- Strict Maker-Checker separation: Analyst cannot approve closures; creators cannot self-approve closures or exemptions.
- Statutory clock engine: DPDP (aware, 72h), CERT-In (noticed, 6h), and RBI (detected, 6h) store timestamps in UTC only.
- Cryptographic ledger: SHA-256 hash chaining and Ed25519 signature verification fail-closed on tampering.
"""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from cyberq.api.app import app
from cyberq.audit.chain import AuditService, compute_event_hash
from cyberq.clocks.models import ObligationInstance
from cyberq.core.config import get_settings
from cyberq.iam.policy import Action, PolicyEngine, Role

settings = get_settings()


def _login(test_client: TestClient, username: str, role: Role) -> dict[str, str]:
    test_client.cookies.clear()
    res = test_client.post(
        "/api/v1/auth/login",
        json={"username": username, "role": role.value},
    )
    assert res.status_code == 200, f"Login failed: {res.text}"
    data = res.json()
    return {
        "X-CSRF-Token": data["csrf_token"],
        "X-Session-ID": data["session_id"],
        "user_id": data["id"],
    }


# ==============================================================================
# 1. Maker-Checker RBAC Tests
# ==============================================================================


def test_analyst_cannot_approve_filing_or_close_incident():
    """Verify that Role.ANALYST is explicitly denied from approving filings or closing incidents."""
    # PolicyEngine checks
    assert PolicyEngine.is_allowed(Role.ANALYST, Action.PACKET_APPROVE) is False
    assert PolicyEngine.is_allowed(Role.ANALYST, Action.INCIDENT_CLOSE_APPROVE) is False

    analyst_client = TestClient(app)
    analyst_headers = _login(analyst_client, "analyst_denied", Role.ANALYST)

    # 1. Analyst creates an incident
    inc_res = analyst_client.post(
        "/api/v1/incidents",
        json={"title": "ATM Connectivity Drop", "summary": "Core ATM switch packet loss observed during morning sweep", "severity": "medium"},
        headers=analyst_headers,
    )
    assert inc_res.status_code == 201, inc_res.text
    inc_id = inc_res.json()["id"]

    # 2. Analyst attempts to approve closure -> 403 Forbidden
    close_res = analyst_client.post(
        f"/api/v1/incidents/{inc_id}/approve-closure",
        json={"closure_notes": "Attempting closure by analyst without authorization"},
        headers=analyst_headers,
    )
    assert close_res.status_code == 403


def test_compliance_approver_cannot_approve_incident_closure():
    """Compliance Approver has Action.PACKET_APPROVE but NOT Action.INCIDENT_CLOSE_APPROVE."""
    assert PolicyEngine.is_allowed(Role.COMPLIANCE_APPROVER, Action.PACKET_APPROVE) is True
    assert PolicyEngine.is_allowed(Role.COMPLIANCE_APPROVER, Action.INCIDENT_CLOSE_APPROVE) is False

    analyst_client = TestClient(app)
    analyst_headers = _login(analyst_client, "analyst_creator_ca", Role.ANALYST)

    approver_client = TestClient(app)
    approver_headers = _login(approver_client, "approver_ca", Role.COMPLIANCE_APPROVER)

    inc_res = analyst_client.post(
        "/api/v1/incidents",
        json={"title": "Branch Perimeter State Flap", "summary": "Firewall state table corrupted during BGP route convergence", "severity": "high"},
        headers=analyst_headers,
    )
    assert inc_res.status_code == 201, inc_res.text
    inc_id = inc_res.json()["id"]

    close_res = approver_client.post(
        f"/api/v1/incidents/{inc_id}/approve-closure",
        json={"closure_notes": "Compliance approver trying to sign closure"},
        headers=approver_headers,
    )
    assert close_res.status_code == 403


def test_compliance_approver_cannot_approve_own_exemption_assessment(isolated_db):
    """Maker-Checker: A compliance approver who assessed applicability cannot confirm their own exemption."""
    analyst_client = TestClient(app)
    analyst_headers = _login(analyst_client, "analyst_ex", Role.ANALYST)

    approver1_client = TestClient(app)
    approver1_headers = _login(approver1_client, "approver_maker", Role.COMPLIANCE_APPROVER)

    approver2_client = TestClient(app)
    approver2_headers = _login(approver2_client, "approver_checker", Role.COMPLIANCE_APPROVER)

    # 1. Analyst creates incident
    inc_res = analyst_client.post(
        "/api/v1/incidents",
        json={"title": "Test Exemption Incident", "summary": "Isolated test subnet packet noise during maintenance window", "severity": "low"},
        headers=analyst_headers,
    )
    assert inc_res.status_code == 201, inc_res.text
    inc_data = inc_res.json()
    obl_id = inc_data["obligations"][0]["id"]

    # 2. Obligation applicability assessed by approver1
    with isolated_db() as s:
        obl = s.scalar(select(ObligationInstance).where(ObligationInstance.id == obl_id))
        obl.applicability_assessed_by_id = approver1_headers["user_id"]
        obl.applicability_status = "pending_approval"
        s.commit()

    # 3. Approver 1 attempts to confirm exemption -> 403 Maker-Checker violation
    self_confirm = approver1_client.post(
        f"/api/v1/incidents/{inc_data['id']}/obligations/{obl_id}/confirm-exemption",
        json={"rationale": "Self-confirming exemption without second pair of eyes"},
        headers=approver1_headers,
    )
    assert self_confirm.status_code == 403, self_confirm.text
    assert "Maker-checker violation" in self_confirm.json()["detail"]

    # 4. Distinct Approver 2 confirms exemption -> 200 OK
    other_confirm = approver2_client.post(
        f"/api/v1/incidents/{inc_data['id']}/obligations/{obl_id}/confirm-exemption",
        json={"rationale": "Independent compliance officer verified non-applicability"},
        headers=approver2_headers,
    )
    assert other_confirm.status_code == 200
    assert other_confirm.json()["applicability_status"] == "not_applicable"


# ==============================================================================
# 2. Statutory Clock UTC & Future Timestamp Enforcement
# ==============================================================================


def test_statutory_triggers_utc_and_future_rejection():
    """Verify triggers enforce UTC timezone, reject future timestamps, and activate proper clocks."""
    analyst_client = TestClient(app)
    analyst_headers = _login(analyst_client, "analyst_utc_test", Role.ANALYST)

    inc_res = analyst_client.post(
        "/api/v1/incidents",
        json={"title": "Statutory Clock Verification", "summary": "Testing UTC constraints and multi-regulator countdowns", "severity": "high"},
        headers=analyst_headers,
    )
    assert inc_res.status_code == 201
    inc_id = inc_res.json()["id"]

    # 1. Reject future timestamp
    future_time = datetime.now(UTC) + timedelta(minutes=30)
    future_res = analyst_client.post(
        f"/api/v1/incidents/{inc_id}/triggers",
        json={
            "trigger_type": "noticed",
            "occurred_at": future_time.isoformat(),
            "evidence_summary": "Attempting future timestamp assertion",
            "rationale": "Testing future timestamp rejection",
        },
        headers=analyst_headers,
    )
    assert future_res.status_code == 400
    assert "cannot be in the future" in future_res.json()["detail"].lower()

    # 2. Assert dual triggers (noticed + detected) with valid past UTC timestamp
    past_time = datetime.now(UTC) - timedelta(minutes=15)
    dual_res = analyst_client.post(
        f"/api/v1/incidents/{inc_id}/triggers",
        json={
            "trigger_type": "noticed",
            "occurred_at": past_time.isoformat(),
            "evidence_summary": "SOC monitoring alert validated on SIEM",
            "rationale": "Dual statutory assertion for CERT-In and RBI clocks",
            "assert_both_triggers": True,
        },
        headers=analyst_headers,
    )
    assert dual_res.status_code == 201

    # 3. Assert DPDP aware trigger (72h clock)
    dpdp_res = analyst_client.post(
        f"/api/v1/incidents/{inc_id}/triggers",
        json={
            "trigger_type": "aware",
            "occurred_at": past_time.isoformat(),
            "evidence_summary": "Data breach assessment confirms potential PII exposure",
            "rationale": "Statutory awareness under DPDP Rule 7 asserted by SOC Analyst",
        },
        headers=analyst_headers,
    )
    assert dpdp_res.status_code == 201

    # Fetch incident and verify all 3 statutory clocks are running with UTC deadlines
    get_res = analyst_client.get(
        f"/api/v1/incidents/{inc_id}",
        headers=analyst_headers,
    )
    assert get_res.status_code == 200
    obls = {o["regulator"]: o for o in get_res.json()["obligations"]}

    assert obls["CERT-In"]["status"] == "running"
    assert obls["RBI"]["status"] == "running"
    assert obls["DPDP"]["status"] == "running"

    certin_deadline = datetime.fromisoformat(obls["CERT-In"]["deadline_at"].replace("Z", "+00:00"))
    rbi_deadline = datetime.fromisoformat(obls["RBI"]["deadline_at"].replace("Z", "+00:00"))
    dpdp_deadline = datetime.fromisoformat(obls["DPDP"]["deadline_at"].replace("Z", "+00:00"))

    # CERT-In and RBI deadlines: exactly 6 hours
    assert certin_deadline == rbi_deadline
    assert (certin_deadline - past_time).total_seconds() == pytest.approx(6 * 3600, abs=1)

    # DPDP deadline: exactly 72 hours
    assert (dpdp_deadline - past_time).total_seconds() == pytest.approx(72 * 3600, abs=1)


# ==============================================================================
# 3. Cryptographic Ledger & Offline Verification Tests
# ==============================================================================


def test_tamper_evident_audit_chain_integrity():
    """Verify SHA-256 hash chaining, Ed25519 signing, and that tampering breaks verify_chain."""
    from cyberq.audit.chain import GENESIS_HASH

    audit_svc = AuditService(settings.AUDIT_SIGNING_SEED)

    # Create dummy events
    ev1 = {
        "id": "ev-01",
        "sequence_number": 1,
        "timestamp": datetime.now(UTC).isoformat(),
        "prev_hash": GENESIS_HASH,
        "actor_id": "test_actor",
        "actor_role": "analyst",
        "client_ip": "127.0.0.1",
        "request_id": "req-1",
        "action": "incident:create",
        "entity_type": "incident",
        "entity_id": "inc-01",
        "before_state": None,
        "after_state": {"title": "Test"},
    }
    ev1["hash"] = compute_event_hash(ev1, GENESIS_HASH)

    ev2 = {
        "id": "ev-02",
        "sequence_number": 2,
        "timestamp": datetime.now(UTC).isoformat(),
        "prev_hash": ev1["hash"],
        "actor_id": "test_actor",
        "actor_role": "ciso",
        "client_ip": "127.0.0.1",
        "request_id": "req-2",
        "action": "incident:severity_change",
        "entity_type": "incident",
        "entity_id": "inc-01",
        "before_state": {"severity": "medium"},
        "after_state": {"severity": "critical"},
    }
    ev2["hash"] = compute_event_hash(ev2, ev1["hash"])

    # 1. Unmodified chain passes
    valid, reason = audit_svc.verify_chain([ev1, ev2])
    assert valid is True
    assert "valid" in reason.lower()

    # 2. Tampered before_state breaks hash check
    tampered_ev = dict(ev2)
    tampered_ev["before_state"] = {"severity": "low"}  # modified without recalculating hash
    valid_tampered, reason_tampered = audit_svc.verify_chain([ev1, tampered_ev])
    assert valid_tampered is False
    assert "tampered event" in reason_tampered.lower()

    # 3. Broken sequence discontinuity breaks verify_chain
    discontinuous_ev = dict(ev2)
    discontinuous_ev["sequence_number"] = 3
    valid_disc, reason_disc = audit_svc.verify_chain([ev1, discontinuous_ev])
    assert valid_disc is False
    assert "sequence discontinuity" in reason_disc.lower()
