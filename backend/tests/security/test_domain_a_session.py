"""Executable security exploit tests for Domain A: Session Management.

Rules of Engagement:
- Imports and enforces tools/redteam/scope_guard.py.
- Uses disposable local database fixtures via conftest.py.
"""

from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from tools.redteam.scope_guard import enforce_scope

from cyberq.api.app import app
from cyberq.core.config import get_settings
from cyberq.iam.models import UserSession
from cyberq.iam.policy import Role

enforce_scope("localhost")

client = TestClient(app)
settings = get_settings()


@pytest.fixture(autouse=True)
def setup_cookies():
    client.cookies.clear()
    yield
    client.cookies.clear()


def test_session_conflict_between_cookie_and_header_rejected(isolated_db):
    """ATTACK A-04: Session identifier ambiguity / smuggling.

    An attacker injects an X-Session-ID header differing from the cyberq_session cookie.
    Ambiguous conflicting session identifiers MUST be rejected with HTTP 400 Bad Request
    to prevent session confusion / cross-session smuggling attacks.
    """
    # 1. Login user A
    res_a = client.post(
        "/api/v1/auth/login", json={"username": "user_alpha", "role": Role.ANALYST.value}
    )
    session_a = res_a.json()["session_id"]

    # 2. Login user B
    client.cookies.clear()
    res_b = client.post(
        "/api/v1/auth/login", json={"username": "user_beta", "role": Role.CISO.value}
    )
    session_b = res_b.json()["session_id"]

    # 3. Present Cookie A AND Header B simultaneously
    client.cookies.set("cyberq_session", session_a)
    conflict_res = client.get("/api/v1/auth/me", headers={"X-Session-ID": session_b})
    assert conflict_res.status_code == 400, (
        f"VULNERABILITY: Conflicting session credentials accepted! Status: {conflict_res.status_code}"
    )
    assert (
        "conflicting" in conflict_res.json()["detail"].lower()
        or "ambiguous" in conflict_res.json()["detail"].lower()
    )


def test_session_idle_timeout_enforced(isolated_db):
    """ATTACK A-05: Stale session hijacking after 15-minute inactivity.

    Sessions inactive for > SESSION_IDLE_TIMEOUT_MINUTES must be deleted and rejected (401).
    """
    TestingSessionLocal = isolated_db
    db = TestingSessionLocal()
    try:
        res = client.post(
            "/api/v1/auth/login", json={"username": "idle_victim", "role": Role.ANALYST.value}
        )
        session_id = res.json()["session_id"]

        # Fast-forward last_active_at by 16 minutes in the past
        sess = db.get(UserSession, session_id)
        assert sess is not None
        sess.last_active_at = datetime.now(UTC) - timedelta(
            minutes=settings.SESSION_IDLE_TIMEOUT_MINUTES + 1
        )
        db.commit()

        # Attempt authenticated request
        client.cookies.set("cyberq_session", session_id)
        req_res = client.get("/api/v1/auth/me")
        assert req_res.status_code == 401, (
            f"VULNERABILITY: Idle session was not expired! Status: {req_res.status_code}"
        )
        detail = req_res.json()["detail"].lower()
        assert "inactivity" in detail or "timed out" in detail or "timeout" in detail
    finally:
        db.close()


def test_session_absolute_timeout_enforced(isolated_db):
    """ATTACK A-06: Absolute session expiration after 8 hours.

    Even if continuously active, sessions must expire after SESSION_ABSOLUTE_TIMEOUT_HOURS (401).
    """
    TestingSessionLocal = isolated_db
    db = TestingSessionLocal()
    try:
        res = client.post(
            "/api/v1/auth/login", json={"username": "absolute_victim", "role": Role.ANALYST.value}
        )
        session_id = res.json()["session_id"]

        # Backdate created_at by 9 hours
        sess = db.get(UserSession, session_id)
        assert sess is not None
        sess.created_at = datetime.now(UTC) - timedelta(
            hours=settings.SESSION_ABSOLUTE_TIMEOUT_HOURS + 1
        )
        sess.expires_at = datetime.now(UTC) - timedelta(minutes=1)
        db.commit()

        client.cookies.set("cyberq_session", session_id)
        req_res = client.get("/api/v1/auth/me")
        assert req_res.status_code == 401, (
            f"VULNERABILITY: Absolute session duration exceeded! Status: {req_res.status_code}"
        )
        assert (
            "duration" in req_res.json()["detail"].lower()
            or "expired" in req_res.json()["detail"].lower()
        )
    finally:
        db.close()


def test_session_invalidation_after_logout(isolated_db):
    """ATTACK A-07: Reuse of terminated session token after logout."""
    res = client.post(
        "/api/v1/auth/login", json={"username": "logout_user", "role": Role.ANALYST.value}
    )
    session_id = res.json()["session_id"]
    csrf_token = res.json()["csrf_token"]

    # Logout
    logout_res = client.post(
        "/api/v1/auth/logout",
        headers={"X-Session-ID": session_id, "X-CSRF-Token": csrf_token},
    )
    assert logout_res.status_code == 200

    # Attempt to reuse logged-out session
    client.cookies.clear()
    reuse_res = client.get("/api/v1/auth/me", headers={"X-Session-ID": session_id})
    assert reuse_res.status_code == 401


def test_session_fixation_attack_prevented(isolated_db):
    """ATTACK A-08: Session fixation attempt.

    Attacker presets a cookie or session ID before victim logs in.
    Server MUST generate a completely new cryptographic session ID and ignore
    any client-preseeded session identifier.
    """
    attacker_preseeded_session = "preseeded_attacker_session_token_12345678901234567890"
    client.cookies.set("cyberq_session", attacker_preseeded_session)

    res = client.post(
        "/api/v1/auth/login",
        json={"username": "fixation_victim", "role": Role.COMPLIANCE_APPROVER.value},
    )
    assert res.status_code == 200
    issued_session = res.json()["session_id"]

    # Server must have issued a fresh session distinct from the attacker's seed
    assert issued_session != attacker_preseeded_session
    assert len(issued_session) >= 48

    # The attacker's preseeded session must NOT exist in the database or be authenticated
    client.cookies.clear()
    client.cookies.set("cyberq_session", attacker_preseeded_session)
    victim_check = client.get("/api/v1/auth/me")
    assert victim_check.status_code == 401


def test_malformed_session_identifiers_rejected_without_db_lookup(isolated_db):
    """ATTACK A-09: Overlong session identifier rejection (CWE-1287)."""
    overlong_token = "A" * 200
    res = client.get("/api/v1/auth/me", headers={"X-Session-ID": overlong_token})
    assert res.status_code == 400
    assert "excessive length" in res.json()["detail"].lower()


def test_login_rate_limiting_enforced(isolated_db):
    """ATTACK A-10: Brute force login abuse / credential stuffing.

    CYBERQ MUST rate-limit login attempts (max 5 attempts within window)
    and reject subsequent attempts with HTTP 429 Too Many Requests.
    """
    from cyberq.api.routes_auth import clear_login_rate_limits

    clear_login_rate_limits()
    username = "rate_limit_target"

    # Make 5 attempts
    for i in range(5):
        res = client.post(
            "/api/v1/auth/login",
            json={"username": username, "role": Role.ANALYST.value},
        )
        assert res.status_code == 200, f"Attempt {i+1} should succeed, got {res.status_code}"

    # 6th attempt must be rejected with HTTP 429
    res_blocked = client.post(
        "/api/v1/auth/login",
        json={"username": username, "role": Role.ANALYST.value},
    )
    assert res_blocked.status_code == 429, (
        f"VULNERABILITY: Rate limiting failed! Status: {res_blocked.status_code}"
    )
    assert "too many login attempts" in res_blocked.json()["detail"].lower()
    clear_login_rate_limits()


def test_rate_limiter_lockout_denial_of_response(isolated_db):
    """ATTACK A-11 (Failure Mode): Lockout denial-of-response.

    Attacker shares an IP (e.g. corporate proxy/gateway) with legitimate user 'victim_alice'.
    Attacker exhausts the 5-attempt quota for 'victim_alice'.
    The legitimate victim's subsequent attempt is locked out (HTTP 429),
    proving that ip:username in-memory rate limiting enables user lockout DoS.
    """
    from cyberq.api.routes_auth import clear_login_rate_limits

    clear_login_rate_limits()
    try:
        victim = "victim_alice"
        # Attacker triggers 5 attempts on the victim username from the same gateway
        for _ in range(5):
            res = client.post(
                "/api/v1/auth/login",
                json={"username": victim, "role": Role.ANALYST.value},
            )
            assert res.status_code == 200

        # Legitimate victim attempts login from the same corporate IP/proxy
        victim_res = client.post(
            "/api/v1/auth/login",
            json={"username": victim, "role": Role.ANALYST.value},
        )
        assert victim_res.status_code == 429, (
            "Expected HTTP 429 lockout denial-of-response against victim"
        )
        assert "too many login attempts" in victim_res.json()["detail"].lower()
    finally:
        clear_login_rate_limits()


def test_rate_limiter_x_forwarded_for_spoofing_cannot_bypass(isolated_db):
    """ATTACK A-12 (Failure Mode): Spoofed X-Forwarded-For headers cannot bypass rate limit.

    Attacker attempts to bypass the 5-attempt rate limit by rotating spoofed
    X-Forwarded-For headers (198.51.100.1, 198.51.100.2, etc.).
    Because the application keys on the socket peer (request.client.host) rather
    than untrusted request headers, the bypass fails and attempt 6 returns HTTP 429.
    """
    from cyberq.api.routes_auth import clear_login_rate_limits

    clear_login_rate_limits()
    try:
        target = "spoof_target_user"
        for i in range(5):
            res = client.post(
                "/api/v1/auth/login",
                json={"username": target, "role": Role.ANALYST.value},
                headers={"X-Forwarded-For": f"198.51.100.{i+1}"},
            )
            assert res.status_code == 200

        # Attempt 6 with yet another spoofed IP header must still be blocked
        blocked_res = client.post(
            "/api/v1/auth/login",
            json={"username": target, "role": Role.ANALYST.value},
            headers={"X-Forwarded-For": "198.51.100.99"},
        )
        assert blocked_res.status_code == 429
        assert "too many login attempts" in blocked_res.json()["detail"].lower()
    finally:
        clear_login_rate_limits()


def test_rate_limiter_trusted_proxy_honors_forwarded_ip(isolated_db):
    """Prove that when request arrives from a TRUSTED_PROXIES host, X-Forwarded-For is honored."""
    from cyberq.api.routes_auth import clear_login_rate_limits, settings

    clear_login_rate_limits()
    # TestClient socket host is 'testclient'
    with patch.object(settings, "TRUSTED_PROXIES", ["testclient"]):
        try:
            target = "proxy_target_user"
            # 5 requests from Client IP A via trusted proxy
            for _ in range(5):
                res = client.post(
                    "/api/v1/auth/login",
                    json={"username": target, "role": Role.ANALYST.value},
                    headers={"X-Forwarded-For": "203.0.113.10"},
                )
                assert res.status_code == 200

            # 6th request from Client IP A is rate limited
            res_a = client.post(
                "/api/v1/auth/login",
                json={"username": target, "role": Role.ANALYST.value},
                headers={"X-Forwarded-For": "203.0.113.10"},
            )
            assert res_a.status_code == 429

            # But a request from Client IP B via the same trusted proxy is NOT rate limited
            res_b = client.post(
                "/api/v1/auth/login",
                json={"username": target, "role": Role.ANALYST.value},
                headers={"X-Forwarded-For": "203.0.113.20"},
            )
            assert res_b.status_code == 200
        finally:
            clear_login_rate_limits()


def test_rate_limiter_restart_resets_state(isolated_db):
    """ATTACK A-13 (Failure Mode): Process restart wipes in-memory rate limiter state.

    Proves the architectural limitation: in-memory state is transient.
    When a server restarts (simulated via clear_login_rate_limits), an attacker's
    lockout counters reset to zero, allowing immediate resumption of brute force.
    """
    from cyberq.api.routes_auth import clear_login_rate_limits

    clear_login_rate_limits()
    try:
        username = "restart_target_user"
        for _ in range(5):
            res = client.post(
                "/api/v1/auth/login",
                json={"username": username, "role": Role.ANALYST.value},
            )
            assert res.status_code == 200

        # Locked out
        res_locked = client.post(
            "/api/v1/auth/login",
            json={"username": username, "role": Role.ANALYST.value},
        )
        assert res_locked.status_code == 429

        # Process restart / worker recycle occurs
        clear_login_rate_limits()

        # Attacker can immediately attempt again without waiting out the 60s window
        res_after_restart = client.post(
            "/api/v1/auth/login",
            json={"username": username, "role": Role.ANALYST.value},
        )
        assert res_after_restart.status_code == 200
    finally:
        clear_login_rate_limits()


def test_rate_limiter_multi_worker_bypass():
    """ATTACK A-14 (Failure Mode): Multi-worker in-memory bypass.

    Demonstrates that in a multi-worker deployment (e.g. Uvicorn with 2 workers),
    each OS process maintains its own independent in-memory defaultdict.
    An attacker distributing requests across workers doubles their attack surface.
    """
    from collections import defaultdict

    # Worker 1 and Worker 2 memory spaces
    worker_1_memory = defaultdict(list)
    worker_2_memory = defaultdict(list)

    def worker_check(mem: dict, key: str, max_attempts: int = 5) -> bool:
        attempts = mem[key]
        if len(attempts) >= max_attempts:
            return False  # HTTP 429
        mem[key].append(1.0)
        return True  # HTTP 200

    target_key = "127.0.0.1:distributed_target"

    # Attacker sends 5 requests to Worker 1
    w1_allowed = [worker_check(worker_1_memory, target_key) for _ in range(5)]
    assert all(w1_allowed)
    assert not worker_check(worker_1_memory, target_key)  # Worker 1 now locked

    # Attacker alternates and sends 5 requests to Worker 2 - all succeed because state is not shared!
    w2_allowed = [worker_check(worker_2_memory, target_key) for _ in range(5)]
    assert all(w2_allowed)
    assert not worker_check(worker_2_memory, target_key)  # Worker 2 now locked

    # Total successful attempts without rate limiting = 10, proving multi-worker state bypass
    assert len(worker_1_memory[target_key]) + len(worker_2_memory[target_key]) == 10
