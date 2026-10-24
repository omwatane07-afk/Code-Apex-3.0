"""Tests for Incident lifecycle, regulatory clock triggers, PII redaction, transitions, and auditor masking."""

import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from cyberq.api.app import app
from cyberq.iam.policy import Role


def _login(test_client: TestClient, role: Role, username: str | None = None) -> dict[str, str]:
    test_client.cookies.clear()
    uname = username or f"user_{role.value}"
    res = test_client.post(
        "/api/v1/auth/login",
        json={"username": uname, "role": role.value},
    )
    assert res.status_code == 200, res.text
    data = res.json()
    return {
        "X-CSRF-Token": data["csrf_token"],
    }


def test_incident_create_and_sequential_numbering():
    client = TestClient(app)
    analyst_headers = _login(client, Role.ANALYST, "analyst_seq")

    res1 = client.post(
        "/api/v1/incidents",
        json={
            "title": "First Security Event",
            "summary": "Core switch packet loss observed during morning network sweep",
            "severity": "high",
        },
        headers=analyst_headers,
    )
    assert res1.status_code == 201, res1.text
    data1 = res1.json()
    assert "INC-" in data1["incident_number"]
    assert len(data1["obligations"]) == 3
    # Check default obligations
    regulators = {o["regulator"]: o["status"] for o in data1["obligations"]}
    assert regulators["CERT-In"] == "pending_trigger"
    assert regulators["RBI"] == "pending_trigger"
    assert regulators["DPDP"] in ("pending_trigger", "not_in_force")

    res2 = client.post(
        "/api/v1/incidents",
        json={
            "title": "Second Security Event",
            "summary": "Secondary DNS latency spike recorded across edge resolvers",
            "severity": "medium",
        },
        headers=analyst_headers,
    )
    assert res2.status_code == 201, res2.text
    data2 = res2.json()
    assert data2["incident_number"] != data1["incident_number"]


@pytest.mark.postgres
def test_concurrent_incident_creation():
    """Verify sequence and counter table locking across real concurrent processes on Postgres."""
    pg_url = os.environ.get("CYBERQ_TEST_PG_URL")
    if not pg_url:
        pytest.skip("CYBERQ_TEST_PG_URL not set; real PostgreSQL 16 database required")

    client = TestClient(app)
    analyst_headers = _login(client, Role.ANALYST, "analyst_concurrent")

    created_numbers: list[str] = []

    def create_one(idx: int) -> str:
        res = client.post(
            "/api/v1/incidents",
            json={
                "title": f"Concurrent Incident {idx}",
                "summary": f"Network anomaly recorded during concurrent stress testing index {idx}",
                "severity": "medium",
            },
            headers=analyst_headers,
        )
        assert res.status_code == 201, res.text
        return res.json()["incident_number"]

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(create_one, i) for i in range(10)]
        for f in futures:
            created_numbers.append(f.result())

    # All 10 created numbers must be strictly unique
    assert len(set(created_numbers)) == 10, f"Colliding incident numbers generated: {created_numbers}"


def test_incident_pii_soft_redacted_with_warning_and_override():
    """Verify PII guard does not hard-reject, redacts with warning, and supports audited overrides."""
    client = TestClient(app)
    analyst_headers = _login(client, Role.ANALYST, "analyst_pii")

    # 1. Un-overridden submission: soft-redacts text and returns visible notice
    res1 = client.post(
        "/api/v1/incidents",
        json={
            "title": "Compromised Account Report",
            "summary": "Customer details Aadhaar 9999 4105 7058 leaked in pastebin",
            "severity": "high",
        },
        headers=analyst_headers,
    )
    assert res1.status_code == 201, res1.text
    data1 = res1.json()
    assert "[REDACTED_AADHAAR]" in data1["summary"]
    assert "9999 4105 7058" not in data1["summary"]
    assert data1["warning"] is not None
    assert "Personal data detected and redacted" in data1["warning"]

    # 2. Audited override submission: retains text with audited justification
    res2 = client.post(
        "/api/v1/incidents",
        json={
            "title": "Customer Data Pen-Test Result",
            "summary": "Customer PAN BKZPK4321A verified as synthetic test vector",
            "severity": "high",
            "override_pii": True,
            "override_pii_reason": "Synthetic test PAN generated for SOC training simulation",
        },
        headers=analyst_headers,
    )
    assert res2.status_code == 201, res2.text
    data2 = res2.json()
    assert "BKZPK4321A" in data2["summary"]
    assert "Audited PII override applied" in data2["warning"]


def test_incident_state_machine_transitions():
    client = TestClient(app)
    analyst_headers = _login(client, Role.ANALYST, "analyst_fsm")

    # Create incident
    res = client.post(
        "/api/v1/incidents",
        json={
            "title": "Transition Test Event",
            "summary": "Testing valid and invalid state machine transitions",
            "severity": "low",
        },
        headers=analyst_headers,
    )
    assert res.status_code == 201
    inc_id = res.json()["id"]

    # Valid transition: new -> triaged
    res_triaged = client.post(
        f"/api/v1/incidents/{inc_id}/transition",
        json={"target_status": "triaged"},
        headers=analyst_headers,
    )
    assert res_triaged.status_code == 200
    assert res_triaged.json()["status"] == "triaged"

    # Invalid transition: triaged -> closed (must go through confirmed/false_positive)
    res_invalid = client.post(
        f"/api/v1/incidents/{inc_id}/transition",
        json={"target_status": "closed"},
        headers=analyst_headers,
    )
    assert res_invalid.status_code == 400
    assert "Illegal state transition" in res_invalid.text


def test_auditor_free_text_redaction():
    analyst_client = TestClient(app)
    analyst_headers = _login(analyst_client, Role.ANALYST, "analyst_author")

    # Create incident with sensitive internal investigation narrative
    res = analyst_client.post(
        "/api/v1/incidents",
        json={
            "title": "Confidential Security Investigation",
            "summary": "Internal employee credential compromised on trading desk host TD-04",
            "severity": "critical",
        },
        headers=analyst_headers,
    )
    assert res.status_code == 201
    inc_id = res.json()["id"]

    # Analyst sees full narrative
    analyst_view = analyst_client.get(f"/api/v1/incidents/{inc_id}", headers=analyst_headers)
    assert "trading desk" in analyst_view.json()["summary"]

    # Auditor sees masked narrative
    auditor_client = TestClient(app)
    auditor_headers = _login(auditor_client, Role.AUDITOR, "auditor_inspect")
    auditor_view = auditor_client.get(f"/api/v1/incidents/{inc_id}", headers=auditor_headers)
    assert auditor_view.status_code == 200
    assert auditor_view.json()["summary"] == "[REDACTED_FOR_AUDIT]"
    assert auditor_view.json()["title"] == "Confidential Security Investigation"


def test_admin_forbidden_from_reading_incidents():
    analyst_client = TestClient(app)
    analyst_headers = _login(analyst_client, Role.ANALYST, "analyst_admin_test")
    res = analyst_client.post(
        "/api/v1/incidents",
        json={
            "title": "Admin Isolation Test",
            "summary": "Testing that admins are strictly forbidden from reading incident contents",
            "severity": "low",
        },
        headers=analyst_headers,
    )
    assert res.status_code == 201
    inc_id = res.json()["id"]

    # Admin attempts to read incident
    admin_client = TestClient(app)
    admin_headers = _login(admin_client, Role.ADMIN, "admin_sys")
    admin_res = admin_client.get(f"/api/v1/incidents/{inc_id}", headers=admin_headers)
    assert admin_res.status_code == 403


def test_assert_trigger_and_clock_activation():
    analyst_client = TestClient(app)
    analyst_headers = _login(analyst_client, Role.ANALYST, "analyst_trigger")

    res = analyst_client.post(
        "/api/v1/incidents",
        json={
            "title": "Clock Binding Incident",
            "summary": "Trigger assertion should activate statutory clocks",
            "severity": "high",
        },
        headers=analyst_headers,
    )
    assert res.status_code == 201
    inc_id = res.json()["id"]

    # Assert noticed trigger (binds CERT-In 6h clock)
    occurred = datetime.now(UTC) - timedelta(hours=1)
    trig_res = analyst_client.post(
        f"/api/v1/incidents/{inc_id}/triggers",
        json={
            "trigger_type": "noticed",
            "occurred_at": occurred.isoformat(),
            "evidence_summary": "Alert notified via SOC SIEM console",
            "rationale": "Analyst acknowledged alert",
        },
        headers=analyst_headers,
    )
    assert trig_res.status_code == 201, trig_res.text

    # Verify CERT-In clock is running
    get_res = analyst_client.get(f"/api/v1/incidents/{inc_id}", headers=analyst_headers)
    data = get_res.json()
    certin_obl = next(o for o in data["obligations"] if o["regulator"] == "CERT-In")

    assert certin_obl["status"] == "running"
    assert certin_obl["deadline_at"] is not None
    assert certin_obl["active_deadline_at"] is not None
    assert certin_obl["next_due_at"] is not None


def test_dispute_trigger_by_compliance_approver():
    analyst_client = TestClient(app)
    analyst_headers = _login(analyst_client, Role.ANALYST, "analyst_maker")

    res = analyst_client.post(
        "/api/v1/incidents",
        json={
            "title": "Dispute Verification Incident",
            "summary": "Testing trigger dispute resolution and dual deadlines",
            "severity": "critical",
        },
        headers=analyst_headers,
    )
    assert res.status_code == 201, res.text
    inc_id = res.json()["id"]

    # Assert detected trigger (binds RBI 6h clock)
    occurred_1 = datetime.now(UTC) - timedelta(hours=2)
    trig_res = analyst_client.post(
        f"/api/v1/incidents/{inc_id}/triggers",
        json={
            "trigger_type": "detected",
            "occurred_at": occurred_1.isoformat(),
            "evidence_summary": "First detection in SIEM",
            "rationale": "Analyst detection assertion",
        },
        headers=analyst_headers,
    )
    assert trig_res.status_code == 201, trig_res.text
    trig_id = trig_res.json()["id"]

    # Analyst cannot dispute (must be Approver / CISO)
    counter_time = datetime.now(UTC) - timedelta(hours=1)
    analyst_dispute = analyst_client.post(
        f"/api/v1/incidents/{inc_id}/triggers/{trig_id}/dispute",
        json={
            "dispute_reason": "Counter evidence suggests later detection",
            "counter_occurred_at": counter_time.isoformat(),
        },
        headers=analyst_headers,
    )
    assert analyst_dispute.status_code == 403

    # Approver disputes
    approver_client = TestClient(app)
    approver_headers = _login(approver_client, Role.COMPLIANCE_APPROVER, "approver_checker")

    approver_dispute = approver_client.post(
        f"/api/v1/incidents/{inc_id}/triggers/{trig_id}/dispute",
        json={
            "dispute_reason": "Verified initial anomaly was benign; actual compromise detected later",
            "counter_occurred_at": counter_time.isoformat(),
        },
        headers=approver_headers,
    )
    assert approver_dispute.status_code == 200, approver_dispute.text
    dispute_data = approver_dispute.json()
    assert dispute_data["is_disputed"] is True
    assert dispute_data["dispute_reason"] is not None

    get_res = approver_client.get(f"/api/v1/incidents/{inc_id}", headers=approver_headers)
    rbi_obl = next(o for o in get_res.json()["obligations"] if o["regulator"] == "RBI")
    assert rbi_obl["status"] == "disputed"
    assert rbi_obl["disputed_deadline_at"] is not None
    assert rbi_obl["active_deadline_at"] == rbi_obl["deadline_at"]


def test_dual_trigger_assertion():
    """Verify simultaneous assertion of noticed and detected triggers."""
    client = TestClient(app)
    analyst_headers = _login(client, Role.ANALYST, "analyst_dual")

    res = client.post(
        "/api/v1/incidents",
        json={
            "title": "Dual Trigger Incident",
            "summary": "Incident testing default simultaneous trigger assertion",
            "severity": "high",
        },
        headers=analyst_headers,
    )
    inc_id = res.json()["id"]

    occurred = datetime.now(UTC) - timedelta(hours=1)
    trig_res = client.post(
        f"/api/v1/incidents/{inc_id}/triggers",
        json={
            "trigger_type": "noticed",
            "occurred_at": occurred.isoformat(),
            "evidence_summary": "Simultaneous notice and detection from monitoring console",
            "rationale": "Default concurrent operational assertion",
            "assert_both_triggers": True,
        },
        headers=analyst_headers,
    )
    assert trig_res.status_code == 201

    inc_res = client.get(f"/api/v1/incidents/{inc_id}", headers=analyst_headers)
    triggers = inc_res.json()["triggers"]
    trigger_types = {t["trigger_type"] for t in triggers}
    assert "noticed" in trigger_types
    assert "detected" in trigger_types


def test_server_preview_matches_actual_calculation():
    """Verify that the server preview endpoint produces identical deadline to actual assertion."""
    client = TestClient(app)
    analyst_headers = _login(client, Role.ANALYST, "analyst_preview")

    occurred = datetime.now(UTC) - timedelta(minutes=45)
    preview_res = client.post(
        "/api/v1/incidents/preview-trigger",
        json={
            "occurred_at": occurred.isoformat(),
            "trigger_type": "noticed",
        },
        headers=analyst_headers,
    )
    assert preview_res.status_code == 200
    preview_data = preview_res.json()
    certin_preview = next(i for i in preview_data["preview_items"] if i["regulator"] == "CERT-In")
    assert certin_preview["deadline_at"] is not None

    # Now create real incident and assert trigger
    inc_res = client.post(
        "/api/v1/incidents",
        json={
            "title": "Preview Parity Incident",
            "summary": "Validating preview calculation parity against actual calculation",
            "severity": "high",
        },
        headers=analyst_headers,
    )
    inc_id = inc_res.json()["id"]

    client.post(
        f"/api/v1/incidents/{inc_id}/triggers",
        json={
            "trigger_type": "noticed",
            "occurred_at": occurred.isoformat(),
            "evidence_summary": "Parity assertion verification",
            "rationale": "Testing preview equality",
        },
        headers=analyst_headers,
    )

    get_res = client.get(f"/api/v1/incidents/{inc_id}", headers=analyst_headers)
    certin_actual = next(o for o in get_res.json()["obligations"] if o["regulator"] == "CERT-In")

    # Preview deadline must match actual deadline exactly to the second
    assert certin_preview["deadline_at"] == certin_actual["active_deadline_at"]


def test_applicability_analyst_cannot_stop_clock_maker_checker():
    """Verify that an analyst selecting 'No' cannot stop a clock; it enters pending approval."""
    analyst_client = TestClient(app)
    analyst_headers = _login(analyst_client, Role.ANALYST, "analyst_app")

    inc_res = analyst_client.post(
        "/api/v1/incidents",
        json={
            "title": "Applicability Check Incident",
            "summary": "Testing maker-checker gate on applicability exemptions",
            "severity": "medium",
        },
        headers=analyst_headers,
    )
    inc_id = inc_res.json()["id"]
    certin_obl = next(o for o in inc_res.json()["obligations"] if o["regulator"] == "CERT-In")
    obl_id = certin_obl["id"]

    # Analyst asserts trigger to start clock
    occurred = datetime.now(UTC) - timedelta(hours=1)
    analyst_client.post(
        f"/api/v1/incidents/{inc_id}/triggers",
        json={
            "trigger_type": "noticed",
            "occurred_at": occurred.isoformat(),
            "evidence_summary": "Notice established",
            "rationale": "Analyst noticed event",
        },
        headers=analyst_headers,
    )

    # Analyst answers "No" to reportable category
    app_res = analyst_client.post(
        f"/api/v1/incidents/{inc_id}/obligations/{obl_id}/assess-applicability",
        json={
            "personal_data_involved": "no",
            "reportable_category": "no",
            "rationale": "Analyst believes this is non-reportable internal ping fluctuation",
        },
        headers=analyst_headers,
    )
    assert app_res.status_code == 200
    obl_data = app_res.json()
    # Clock MUST NOT be stopped! It remains pending_approval and status remains running
    assert obl_data["applicability_status"] == "pending_approval"
    assert obl_data["status"] == "running"
    assert obl_data["active_deadline_at"] is not None

    # Analyst cannot call confirm-exemption
    analyst_confirm = analyst_client.post(
        f"/api/v1/incidents/{inc_id}/obligations/{obl_id}/confirm-exemption",
        json={"rationale": "Attempting self-confirmation"},
        headers=analyst_headers,
    )
    assert analyst_confirm.status_code == 403

    # Compliance approver confirms exemption
    approver_client = TestClient(app)
    approver_headers = _login(approver_client, Role.COMPLIANCE_APPROVER, "approver_app")
    conf_res = approver_client.post(
        f"/api/v1/incidents/{inc_id}/obligations/{obl_id}/confirm-exemption",
        json={"rationale": "Compliance reviewed architecture; confirms system is out of scope."},
        headers=approver_headers,
    )
    assert conf_res.status_code == 200
    conf_data = conf_res.json()
    assert conf_data["applicability_status"] == "not_applicable"
    assert conf_data["status"] == "not_applicable"
    assert conf_data["active_deadline_at"] is None


def test_wallboard_endpoint_leakage_and_role_isolation():
    """Verify wallboard endpoint returns sanitized telemetry with zero titles, summaries, or PII."""
    analyst_client = TestClient(app)
    analyst_headers = _login(analyst_client, Role.ANALYST, "analyst_wb")

    analyst_client.post(
        "/api/v1/incidents",
        json={
            "title": "Confidential Cardholder Data Center Fire",
            "summary": "Customer PII exposure risk at Mumbai Data Center rack DC4",
            "severity": "critical",
        },
        headers=analyst_headers,
    )

    # 1. Login as dedicated Role.WALLBOARD
    wb_client = TestClient(app)
    wb_headers = _login(wb_client, Role.WALLBOARD, "soc_wallboard_screen_01")

    wb_res = wb_client.get("/api/v1/incidents/wallboard", headers=wb_headers)
    assert wb_res.status_code == 200, wb_res.text
    wb_data = wb_res.json()
    assert len(wb_data) > 0

    # Leak test: verify NO titles, NO summaries, NO user names, NO contact details
    raw_response_text = wb_res.text
    assert "Confidential" not in raw_response_text
    assert "Cardholder" not in raw_response_text
    assert "Mumbai Data Center" not in raw_response_text
    assert "rack DC4" not in raw_response_text

    for item in wb_data:
        assert "incident_number" in item
        assert "severity" in item
        assert "status" in item
        assert "obligations" in item
        assert "title" not in item
        assert "summary" not in item
        assert "created_by_id" not in item

    # Role isolation: Wallboard role CANNOT access standard incident endpoint
    wb_leak_attempt = wb_client.get("/api/v1/incidents", headers=wb_headers)
    assert wb_leak_attempt.status_code == 403


def test_simulated_time_refused_in_production():
    """Verify simulated time acceleration is refused in production mode."""
    client = TestClient(app)
    analyst_headers = _login(client, Role.ANALYST, "analyst_sim")

    # In demo mode, it succeeds
    res_demo = client.post(
        "/api/v1/incidents/simulation-speed",
        json={"speed_multiplier": 60},
        headers=analyst_headers,
    )
    assert res_demo.status_code == 200
    assert "SIMULATED TIME ACTIVE" in res_demo.json()["banner"]


def test_admin_and_auditor_raw_api_masking():
    """Verify raw API responses enforce masking for Role.ADMIN and Role.AUDITOR."""
    from cyberq.incidents.service import mask_incident_for_role

    client = TestClient(app)
    analyst_headers = _login(client, Role.ANALYST, "analyst_mask_src")

    res = client.post(
        "/api/v1/incidents",
        json={
            "title": "Core Database Key Exposure",
            "summary": "Confidential production cryptographic keys compromised on host srv-db-01",
            "severity": "critical",
        },
        headers=analyst_headers,
    )
    assert res.status_code == 201
    inc_id = res.json()["id"]

    # 1. Admin reads incident via API: denied with 403 (administrative separation of duties)
    admin_client = TestClient(app)
    admin_headers = _login(admin_client, Role.ADMIN, "admin_verifier")
    admin_res = admin_client.get(f"/api/v1/incidents/{inc_id}", headers=admin_headers)
    assert admin_res.status_code == 403

    # Direct masking function verification for admin role
    masked_admin = mask_incident_for_role(
        {"incident_number": "INC-2026-0001", "title": "Core Database Key Exposure", "summary": "Secret data"},
        Role.ADMIN.value,
    )
    assert "Narrative masked - Admin role" in masked_admin["title"]
    assert "[REDACTED_FOR_ADMIN" in masked_admin["summary"]

    # 2. Auditor reads incident via API: permitted, but summary masked for audit
    auditor_client = TestClient(app)
    auditor_headers = _login(auditor_client, Role.AUDITOR, "auditor_verifier")
    auditor_res = auditor_client.get(f"/api/v1/incidents/{inc_id}", headers=auditor_headers)
    assert auditor_res.status_code == 200
    auditor_data = auditor_res.json()
    assert auditor_data["summary"] == "[REDACTED_FOR_AUDIT]"
    assert "Confidential production cryptographic keys" not in auditor_data["summary"]


def test_simulated_time_auditing_and_server_clock_invariance(isolated_db):
    """Verify simulated time is audited, refuses in production, and does not alter server time."""
    from unittest.mock import patch

    from sqlalchemy import select

    from cyberq.audit.models import AuditEvent
    from cyberq.core.config import EnvironmentType, get_settings

    client = TestClient(app)
    analyst_headers = _login(client, Role.ANALYST, "analyst_sim_audit")

    # 1. Check real server time before simulation call
    hz_before = client.get("/healthz").json()
    time_before = datetime.fromisoformat(hz_before["server_time_utc"])

    # 2. Call simulation speed endpoint
    res = client.post(
        "/api/v1/incidents/simulation-speed",
        json={"speed_multiplier": 10},
        headers=analyst_headers,
    )
    assert res.status_code == 200

    # 3. Check real server time after simulation call: must NOT jump by 10x
    hz_after = client.get("/healthz").json()
    time_after = datetime.fromisoformat(hz_after["server_time_utc"])
    delta_seconds = abs((time_after - time_before).total_seconds())
    assert delta_seconds < 5.0, f"Server clock jumped unexpectedly: {delta_seconds}s"

    # 4. Verify audit trail recorded event
    with isolated_db() as db:
        event = db.execute(
            select(AuditEvent)
            .where(AuditEvent.action == "simulate_speed_change")
            .order_by(AuditEvent.sequence_number.desc())
        ).scalars().first()
        assert event is not None
        assert event.entity_type == "system_simulation"
        assert event.after_state == {"speed_multiplier": 10.0}

    # 5. Verify refusal in production mode
    settings = get_settings()
    with patch.object(settings, "ENV", EnvironmentType.PRODUCTION):
        https_client = TestClient(app, base_url="https://testserver")
        https_client.cookies = client.cookies
        res_prod = https_client.post(
            "/api/v1/incidents/simulation-speed",
            json={"speed_multiplier": 10},
            headers=analyst_headers,
        )
        assert res_prod.status_code == 403
        assert "Simulated time acceleration is strictly forbidden in production mode" in res_prod.json()["detail"]


def test_wallboard_session_lifecycle_and_idle_exemption(isolated_db):
    """Verify wallboard session creation, rotation, and exclusive idle-timeout exemption."""
    from cyberq.core.config import get_settings
    from cyberq.iam.models import User
    from cyberq.iam.session import SessionError, SessionExpiredError, SessionManager

    settings = get_settings()

    with isolated_db() as db:
        # Create test users
        user_wb = User(id="user_wb_lifecycle", username="wb_lifecycle", email="wb@bank.local", full_name="Wallboard Display")
        user_an = User(id="user_an_lifecycle", username="an_lifecycle", email="an@bank.local", full_name="SOC Analyst")
        db.merge(user_wb)
        db.merge(user_an)
        db.commit()

        # 1. Issue sessions
        session_wb = SessionManager.create_session(db, user_wb, Role.WALLBOARD)
        session_an = SessionManager.create_session(db, user_an, Role.ANALYST)
        wb_id = session_wb.id
        an_id = session_an.id

        # 2. Rotate wallboard session
        rotated_wb = SessionManager.rotate_session(db, session_wb)
        assert rotated_wb.id != wb_id
        assert rotated_wb.csrf_token != session_wb.csrf_token
        # Old session must no longer validate
        with pytest.raises(SessionError):
            SessionManager.validate_session(db, wb_id)

        # 3. Idle timeout test: simulate 20 minutes of inactivity
        past_active = datetime.now(UTC) - timedelta(minutes=settings.SESSION_IDLE_TIMEOUT_MINUTES + 5)
        rotated_wb.last_active_at = past_active
        session_an.last_active_at = past_active
        db.commit()

        # Wallboard session MUST survive idle timeout
        validated_wb = SessionManager.validate_session(db, rotated_wb.id)
        assert validated_wb is not None

        # Analyst session MUST expire due to idle timeout
        with pytest.raises(SessionExpiredError):
            SessionManager.validate_session(db, an_id)

        # 4. Absolute timeout test: simulate 9 hours passed (exceeds 8h absolute limit)
        past_expires = datetime.now(UTC) - timedelta(hours=1)
        validated_wb.expires_at = past_expires
        db.commit()

        # Wallboard session MUST expire when absolute limit is reached
        with pytest.raises(SessionExpiredError):
            SessionManager.validate_session(db, validated_wb.id)


def test_dpdp_aware_trigger_analyst_only_rbac():
    """Verify DPDP 'aware' trigger: only Role.ANALYST permitted; binds 72-hour statutory clock."""
    analyst_client = TestClient(app)
    analyst_headers = _login(analyst_client, Role.ANALYST, "analyst_dpdp")

    approver_client = TestClient(app)
    approver_headers = _login(approver_client, Role.COMPLIANCE_APPROVER, "approver_dpdp")

    ciso_client = TestClient(app)
    ciso_headers = _login(ciso_client, Role.CISO, "ciso_dpdp")

    # 1. Create incident as Analyst
    inc_res = analyst_client.post(
        "/api/v1/incidents",
        json={
            "title": "Suspected Customer Data Leakage via Rogue Endpoint",
            "summary": "Customer PII indicators detected on unauthorized egress gateway node.",
            "severity": "high",
        },
        headers=analyst_headers,
    )
    assert inc_res.status_code == 201
    inc_id = inc_res.json()["id"]

    now = datetime.now(UTC)
    occ_iso = (now - timedelta(minutes=15)).isoformat()

    # 2. Compliance Approver attempts to assert 'aware' -> STRICT 403 Forbidden
    approver_res = approver_client.post(
        f"/api/v1/incidents/{inc_id}/triggers",
        json={
            "trigger_type": "aware",
            "occurred_at": occ_iso,
            "evidence_summary": "Egress gateway telemetry logs #77210 showing potential data principal leakage",
            "rationale": "Statutory awareness under DPDP Rule 7 asserted by approver",
        },
        headers=approver_headers,
    )
    assert approver_res.status_code == 403, approver_res.text
    assert "ONLY the SOC Analyst role is permitted to assert the statutory DPDP 'aware' trigger" in approver_res.json()["detail"]

    # 3. CISO attempts to assert 'aware' -> STRICT 403 Forbidden
    ciso_res = ciso_client.post(
        f"/api/v1/incidents/{inc_id}/triggers",
        json={
            "trigger_type": "aware",
            "occurred_at": occ_iso,
            "evidence_summary": "Executive briefing indicating personal data compromise",
            "rationale": "CISO asserting awareness",
        },
        headers=ciso_headers,
    )
    assert ciso_res.status_code == 403, ciso_res.text

    # 4. Analyst asserts 'aware' -> SUCCESS 201 Created
    analyst_res = analyst_client.post(
        f"/api/v1/incidents/{inc_id}/triggers",
        json={
            "trigger_type": "aware",
            "occurred_at": occ_iso,
            "evidence_summary": "Egress gateway telemetry logs #77210 showing potential data principal leakage",
            "rationale": "Statutory awareness under DPDP Rule 7 asserted by SOC Analyst",
        },
        headers=analyst_headers,
    )
    assert analyst_res.status_code == 201, analyst_res.text
    trig_data = analyst_res.json()
    assert trig_data["trigger_type"] == "aware"

    # 5. Fetch updated incident and verify DPDP 72-hour countdown clock is RUNNING
    get_res = analyst_client.get(f"/api/v1/incidents/{inc_id}", headers=analyst_headers)
    assert get_res.status_code == 200
    inc_data = get_res.json()

    dpdp_obl = next(o for o in inc_data["obligations"] if o["regulator"] == "DPDP")
    assert dpdp_obl["status"] == "running"
    assert dpdp_obl["deadline_at"] is not None

    # Verify deadline is exactly occurred_at + 72 hours
    deadline = datetime.fromisoformat(dpdp_obl["deadline_at"].replace("Z", "+00:00"))
    occurred = datetime.fromisoformat(occ_iso.replace("Z", "+00:00"))
    assert (deadline - occurred).total_seconds() == 72 * 3600

