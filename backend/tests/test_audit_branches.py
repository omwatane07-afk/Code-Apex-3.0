"""Exhaustive branch coverage tests for audit chain, crypto providers, and IAM policy."""

from unittest.mock import MagicMock

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from cyberq.audit.chain import AuditService
from cyberq.audit.crypto import LocalKeyProvider
from cyberq.core.database import Base
from cyberq.iam.policy import Action, PolicyEngine, Role

TEST_SEED = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


def test_iam_policy_all_branches():
    # 1. Invalid role or action raises ValueError internally and returns False
    assert PolicyEngine.is_allowed("nonexistent_role", Action.INCIDENT_CREATE) is False
    assert PolicyEngine.is_allowed(Role.ANALYST, "nonexistent_action") is False

    # 2. _normalize_id empty value
    assert PolicyEngine._normalize_id("") == ""
    assert PolicyEngine._normalize_id(None) == ""

    # 3. check_maker_checker empty values
    assert PolicyEngine.check_maker_checker("", "valid-id") is False
    assert PolicyEngine.check_maker_checker("valid-id", "") is False
    assert PolicyEngine.check_maker_checker(None, "valid-id") is False


def test_crypto_key_provider_branches():
    # 1. Invalid seed length raises ValueError
    with pytest.raises(ValueError, match="at least 32 bytes"):
        LocalKeyProvider("012345")  # only 3 bytes

    # 2. Direct KeyProvider instance passed to AuditService
    provider = LocalKeyProvider(TEST_SEED)
    svc = AuditService(provider)
    assert svc.public_key_hex == provider.get_public_key_hex()


def test_audit_chain_all_verification_branches():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()

    svc = AuditService(TEST_SEED)

    # 1. Postgres advisory lock branch
    mock_session = MagicMock()
    mock_session.get_bind.return_value.dialect.name = "postgresql"
    mock_session.execute.return_value.scalar_one_or_none.return_value = None
    svc.record_event(mock_session, "u1", "analyst", "test", "inc", "1")
    assert mock_session.execute.called

    # 2. create_checkpoint with no events returns None (both default and explicit from_sequence)
    empty_cp = svc.create_checkpoint(session)
    assert empty_cp is None
    empty_cp2 = svc.create_checkpoint(session, from_sequence=999)
    assert empty_cp2 is None

    # 3. Record event and create first checkpoint
    e1 = svc.record_event(session, "u1", "analyst", "act", "ent", "1")
    session.commit()
    cp1 = svc.create_checkpoint(session)
    session.commit()
    assert cp1.sequence_number == 1

    # 4. Record second event and create second checkpoint (exercises last_cp branch)
    e2 = svc.record_event(session, "u2", "analyst", "act2", "ent", "1")
    session.commit()
    cp2 = svc.create_checkpoint(session)
    session.commit()
    assert cp2.sequence_number == 2

    # 5. verify_chain: Sequence discontinuity branch
    d1 = e1.to_canonical_dict()
    d1["hash"] = e1.hash
    d2 = e2.to_canonical_dict()
    d2["hash"] = e2.hash

    discontinuous = [d1, {**d2, "sequence_number": 99}]
    valid, reason = AuditService.verify_chain(discontinuous)
    assert valid is False
    assert "Sequence discontinuity" in reason

    # 6. verify_chain: Broken hash chain branch
    broken_chain = [d1, {**d2, "prev_hash": "wrong_prev_hash" * 4}]
    valid, reason = AuditService.verify_chain(broken_chain)
    assert valid is False
    assert "Broken hash chain" in reason

    # 7. verify_chain: Invalid public key hex
    valid, reason = AuditService.verify_chain([d1], [cp1.to_canonical_dict()], "invalid_hex")
    assert valid is False
    assert "Invalid public key" in reason

    # 8. verify_chain: Checkpoint starting sequence missing
    cp1_dict = cp1.to_canonical_dict()
    cp1_dict["signature"] = cp1.signature
    cp_spanning = {**cp1_dict, "from_sequence": 1, "to_sequence": 2}
    valid, reason = AuditService.verify_chain([d2], [cp_spanning], svc.public_key_hex)
    assert valid is False
    assert "starting sequence 1 is missing" in reason

    # 9. verify_chain: from_event_id mismatch
    cp1_dict = cp1.to_canonical_dict()
    cp1_dict["signature"] = cp1.signature
    bad_from_id = {**cp1_dict, "from_event_id": "wrong-id"}
    valid, reason = AuditService.verify_chain([d1], [bad_from_id], svc.public_key_hex)
    assert valid is False
    assert "from_event_id mismatch" in reason

    # 10. verify_chain: to_event_id mismatch
    bad_to_id = {**cp1_dict, "to_event_id": "wrong-id"}
    valid, reason = AuditService.verify_chain([d1], [bad_to_id], svc.public_key_hex)
    assert valid is False
    assert "to_event_id mismatch" in reason

    session.close()
    engine.dispose()


def test_deps_all_branches(isolated_db):
    from fastapi.testclient import TestClient

    from cyberq.api.app import app
    from cyberq.iam.models import User

    client = TestClient(app)

    # 1. Bearer token authorization header
    login_res = client.post(
        "/api/v1/auth/login", json={"username": "bearer_user", "role": "analyst"}
    )
    assert login_res.status_code == 200
    session_id = login_res.json()["session_id"]
    user_id = login_res.json()["id"]

    # 1. Bearer token authorization header (without cookie)
    client.cookies.clear()
    res_bearer = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {session_id}"})
    assert res_bearer.status_code == 200
    assert res_bearer.json()["username"] == "bearer_user"

    # 2. X-Session-ID header (without cookie)
    client.cookies.clear()
    res_header = client.get("/api/v1/auth/me", headers={"X-Session-ID": session_id})
    assert res_header.status_code == 200

    # 3. Invalid session raising SessionError
    client.cookies.clear()
    res_invalid = client.get(
        "/api/v1/auth/me", headers={"X-Session-ID": "invalid_session_id_format_1234"}
    )
    assert res_invalid.status_code == 401
    assert "Session not found" in res_invalid.json()["detail"]

    # 4. Inactive user returns 401
    db = isolated_db()
    try:
        user = db.get(User, user_id)
        assert user is not None
        user.is_active = False
        db.commit()
    finally:
        db.close()

    res_inactive = client.get("/api/v1/auth/me", headers={"X-Session-ID": session_id})
    assert res_inactive.status_code == 401
    assert "User inactive" in res_inactive.json()["detail"]

    # 5. require_csrf on GET request (does nothing)
    from fastapi import Request

    from cyberq.api.deps import require_csrf

    mock_request = MagicMock(spec=Request)
    mock_request.method = "GET"
    mock_session = MagicMock()
    # Should not raise exception
    require_csrf(mock_request, mock_session, None)
