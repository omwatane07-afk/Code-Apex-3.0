"""Unit 6: Milestones M5 & M6 — Rupee Exposure Engine, PuLP Optimizer & CSITE Verifier Tests."""

from datetime import UTC, datetime
import json
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

import cyberq.audit.models  # noqa: F401
import cyberq.clocks.models  # noqa: F401
import cyberq.filings.models  # noqa: F401
import cyberq.governance.models  # noqa: F401
import cyberq.iam.models  # noqa: F401
import cyberq.incidents.models  # noqa: F401
import cyberq.intake.models  # noqa: F401

from cyberq.api.app import app
from cyberq.api.deps import get_current_session, get_db
from cyberq.audit.chain import AuditService, canonical_json
from cyberq.audit.crypto import LocalKeyProvider
from cyberq.audit.merkle import build_merkle_tree, generate_merkle_proof
from cyberq.core.database import Base
from cyberq.exposure.engine import ExposureEngine
from cyberq.exposure.models import ExposureScenario
from cyberq.iam.models import User, UserSession
from cyberq.iam.policy import Role
from cyberq.optimizer.engine import DEFAULT_BANK_CONTROLS, CapitalOptimizer
from cyberq.optimizer.models import SecurityControl


@pytest.fixture
def db_session() -> Session:
    """In-memory SQLite database session fixture."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()

    test_user = User(
        id="ciso-user-01",
        username="ciso",
        email="ciso@bank.co.in",
        full_name="Chief Information Security Officer",
        is_active=True,
    )
    session.add(test_user)
    session.commit()

    yield session
    session.close()


@pytest.fixture
def mock_ciso_session(db_session: Session) -> UserSession:
    """Mock active CISO session for authenticated route testing."""
    return UserSession(
        id="sess-ciso-01",
        user_id="ciso-user-01",
        active_role=Role.CISO.value,
        csrf_token="csrf-mock-token-01",
        expires_at=datetime.now(UTC),
    )


def test_sobol_qmc_exposure_engine_determinism(db_session: Session) -> None:
    """Verifies that 16,384 Sobol Quasi-Monte Carlo iterations produce monotonic quantiles and deterministic output."""
    scenario = ExposureScenario(
        scenario_id="SCEN-TEST-RANSOMWARE",
        name="Ransomware & CBS Data Exfiltration",
        threat_event_frequency_min=1.0,
        threat_event_frequency_mode=3.0,
        threat_event_frequency_max=8.0,
        vulnerability=0.30,
        primary_loss_min_lakhs=50.0,
        primary_loss_mode_lakhs=200.0,
        primary_loss_max_lakhs=800.0,
        secondary_loss_prob=0.50,
        secondary_loss_min_lakhs=100.0,
        secondary_loss_mode_lakhs=600.0,
        secondary_loss_max_lakhs=3000.0,
    )

    test_seed_hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

    # Run 1
    res1 = ExposureEngine.simulate_scenario(scenario, seed_hash=test_seed_hash, session=db_session)

    # 1. Monotonic quantiles
    assert res1.p10_lakhs <= res1.p50_lakhs, "P10 must be <= P50"
    assert res1.p50_lakhs <= res1.p90_lakhs, "P50 must be <= P90 (VaR)"
    assert res1.p90_lakhs <= res1.p99_lakhs, "P90 must be <= P99 (Tail)"

    # 2. Iteration count
    assert res1.iterations == 16384

    # 3. Currency conversion
    assert abs(res1.p90_crores - (res1.p90_lakhs / 100.0)) < 1e-4

    # 4. RBI MRM Manifest
    mrm = res1.rbi_mrm_manifest
    assert mrm["sample_size"] == 16384
    assert mrm["sobol_dimensions"] == 4
    assert mrm["standard"] == "OPEN_FAIR_ISO_IEC_27005"
    assert res1.ks_pvalue > 0.0

    # Run 2: Exact determinism with same seed hash
    res2 = ExposureEngine.simulate_scenario(scenario, seed_hash=test_seed_hash, session=db_session)
    assert res1.p10_lakhs == res2.p10_lakhs
    assert res1.p50_lakhs == res2.p50_lakhs
    assert res1.p90_lakhs == res2.p90_lakhs
    assert res1.p99_lakhs == res2.p99_lakhs


def test_pulp_capital_optimizer_milp_constraints() -> None:
    """Verifies that PuLP Mixed-Integer Linear Programming strictly enforces budget, dependency, and exclusivity."""
    budget_cap = 90.0  # ₹90 Lakhs

    # Candidate controls:
    # CTRL-PAM-01: Cost 35, Red 120
    # CTRL-EDR-02: Cost 45, Red 145 (Depends on CTRL-PAM-01)
    # CTRL-DAM-03: Cost 40, Red 110
    # CTRL-MICROSEG-05: Cost 60, Red 190 (Mutex with CTRL-LEGACY-VLAN-07)
    # CTRL-LEGACY-VLAN-07: Cost 15, Red 40 (Mutex with CTRL-MICROSEG-05)

    result = CapitalOptimizer.solve_allocation(
        budget_cap_lakhs=budget_cap,
        controls=DEFAULT_BANK_CONTROLS,
    )

    # 1. Budget constraint strictly met
    assert result.total_cost_lakhs <= budget_cap, f"Total cost {result.total_cost_lakhs} exceeds cap {budget_cap}"
    assert result.solver_status in ("Optimal", "Feasible")

    # 2. Dependency constraint: If EDR is chosen, PAM must be chosen
    if "CTRL-EDR-02" in result.selected_control_ids:
        assert "CTRL-PAM-01" in result.selected_control_ids, "EDR requires PAM prerequisite"

    # 3. Mutual exclusivity constraint: MICROSEG and LEGACY-VLAN cannot co-exist
    has_microseg = "CTRL-MICROSEG-05" in result.selected_control_ids
    has_vlan = "CTRL-LEGACY-VLAN-07" in result.selected_control_ids
    assert not (has_microseg and has_vlan), "Mutually exclusive controls cannot both be selected"

    # 4. Pareto frontier curve points
    assert len(result.pareto_frontier) == 10
    assert result.pareto_frontier[0]["budget_cap_lakhs"] < result.pareto_frontier[-1]["budget_cap_lakhs"]


def test_csite_selective_disclosure_and_dual_curve() -> None:
    """Verifies RFC 6962 selective disclosure proof verification and ECDSA P-256 dual-curve signing."""
    # 1. Generate ECDSA P-256 key pair
    key_provider = LocalKeyProvider(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        algorithm="ECDSA_P256",
    )
    pk_hex = key_provider.get_public_key_hex()

    # 2. Create 4 stream event hashes
    leaf_hashes = [
        "1111111111111111111111111111111111111111111111111111111111111111",
        "2222222222222222222222222222222222222222222222222222222222222222",
        "3333333333333333333333333333333333333333333333333333333333333333",
        "4444444444444444444444444444444444444444444444444444444444444444",
    ]
    leaves_bytes = [h.encode("ascii") for h in leaf_hashes]

    # 3. Build RFC 6962 Merkle tree
    merkle_root, _ = build_merkle_tree(leaves_bytes)
    assert merkle_root is not None

    # 4. Sign checkpoint payload with ECDSA P-256
    cp_payload = {
        "id": "ckpt-test-01",
        "sequence_number": 1,
        "timestamp": "2026-10-21T18:00:00+00:00",
        "from_sequence": 1,
        "to_sequence": 4,
        "from_event_id": "ev-01",
        "to_event_id": "ev-04",
        "root_hash": leaf_hashes[-1],
        "signer_public_key": pk_hex,
        "merkle_root": merkle_root,
        "algorithm": "ECDSA_P256",
    }
    canonical_cp = canonical_json(cp_payload)
    sig_bytes = key_provider.sign(canonical_cp)

    checkpoint_dict = {
        **cp_payload,
        "signature": sig_bytes.hex(),
    }

    # 5. Generate selective disclosure proof for leaf 1 (the 2nd event)
    proof_steps = generate_merkle_proof(1, leaves_bytes)

    # 6. Verify selective disclosure without revealing other leaves
    is_valid, msg = AuditService.verify_selective_disclosure(
        event_hash=leaf_hashes[1],
        proof=proof_steps,
        checkpoint=checkpoint_dict,
        public_key_hex=pk_hex,
    )
    assert is_valid, f"Selective disclosure failed: {msg}"

    # 7. Tamper verification: alter event hash -> Must fail!
    tampered_hash = "9999999999999999999999999999999999999999999999999999999999999999"
    is_tampered_valid, tamper_msg = AuditService.verify_selective_disclosure(
        event_hash=tampered_hash,
        proof=proof_steps,
        checkpoint=checkpoint_dict,
        public_key_hex=pk_hex,
    )
    assert not is_tampered_valid, "Tampered event hash must fail verification"


def test_exposure_and_optimizer_fastapi_routes(
    db_session: Session, mock_ciso_session: UserSession
) -> None:
    """Verifies FastAPI API endpoints under /api/v1/exposure."""
    app.dependency_overrides[get_db] = lambda: db_session
    app.dependency_overrides[get_current_session] = lambda: mock_ciso_session

    client = TestClient(app)

    try:
        # 1. GET /api/v1/exposure/controls
        res_ctrls = client.get("/api/v1/exposure/controls")
        assert res_ctrls.status_code == 200
        controls_data = res_ctrls.json()
        assert len(controls_data) >= 5

        # 2. POST /api/v1/exposure/simulate
        sim_payload = {
            "scenario_id": "SCEN-API-TEST",
            "name": "API Automated VaR Test",
            "threat_event_frequency_min": 1.0,
            "threat_event_frequency_mode": 2.0,
            "threat_event_frequency_max": 5.0,
            "vulnerability": 0.20,
            "primary_loss_min_lakhs": 10.0,
            "primary_loss_mode_lakhs": 50.0,
            "primary_loss_max_lakhs": 200.0,
            "secondary_loss_prob": 0.30,
            "secondary_loss_min_lakhs": 20.0,
            "secondary_loss_mode_lakhs": 100.0,
            "secondary_loss_max_lakhs": 500.0,
        }
        res_sim = client.post("/api/v1/exposure/simulate", json=sim_payload)
        assert res_sim.status_code == 200
        sim_data = res_sim.json()
        assert sim_data["p90_lakhs"] > 0
        assert sim_data["iterations"] == 16384

        # 3. POST /api/v1/exposure/optimize
        opt_payload = {
            "budget_cap_lakhs": 120.0,
            "candidate_controls": controls_data,
        }
        res_opt = client.post("/api/v1/exposure/optimize", json=opt_payload)
        assert res_opt.status_code == 200
        opt_data = res_opt.json()
        assert opt_data["total_cost_lakhs"] <= 120.0
        assert len(opt_data["selected_control_ids"]) > 0

        # 4. GET /api/v1/exposure/pareto
        res_pareto = client.get("/api/v1/exposure/pareto?budget_cap_lakhs=120.0")
        assert res_pareto.status_code == 200
        pareto_data = res_pareto.json()
        assert len(pareto_data) == 10
    finally:
        app.dependency_overrides.clear()


def test_offline_verifier_cli_tool() -> None:
    """Verifies that the tools/verify-audit/verify.py offline CLI tool executes properly."""
    import subprocess
    import sys

    # 1. Setup ECDSA P-256 key and selective disclosure test packet
    key_provider = LocalKeyProvider(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        algorithm="ECDSA_P256",
    )
    pk_hex = key_provider.get_public_key_hex()

    leaf_hashes = [
        "1111111111111111111111111111111111111111111111111111111111111111",
        "2222222222222222222222222222222222222222222222222222222222222222",
    ]
    leaves_bytes = [h.encode("ascii") for h in leaf_hashes]
    merkle_root, _ = build_merkle_tree(leaves_bytes)
    assert merkle_root is not None

    cp_payload = {
        "id": "ckpt-cli-01",
        "sequence_number": 1,
        "timestamp": "2026-10-21T18:00:00+00:00",
        "from_sequence": 1,
        "to_sequence": 2,
        "from_event_id": "ev-01",
        "to_event_id": "ev-02",
        "root_hash": leaf_hashes[-1],
        "signer_public_key": pk_hex,
        "merkle_root": merkle_root,
        "algorithm": "ECDSA_P256",
    }
    canonical_cp = canonical_json(cp_payload)
    sig_bytes = key_provider.sign(canonical_cp)
    checkpoint_dict = {**cp_payload, "signature": sig_bytes.hex()}

    proof_steps = generate_merkle_proof(0, leaves_bytes)

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(
            {
                "event_hash": leaf_hashes[0],
                "proof": proof_steps,
                "checkpoint": checkpoint_dict,
                "public_key": pk_hex,
            },
            f,
        )
        temp_path = f.name

    try:
        script_path = (
            Path(__file__).resolve().parent.parent.parent / "tools" / "verify-audit" / "verify.py"
        )
        # Execute selective disclosure verification
        cmd = [
            sys.executable,
            str(script_path),
            "--input",
            temp_path,
            "--selective-disclosure",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        assert result.returncode == 0, f"CLI verification failed: {result.stderr}"
        assert "[SELECTIVE DISCLOSURE VERIFIED]" in result.stdout
    finally:
        Path(temp_path).unlink(missing_ok=True)

