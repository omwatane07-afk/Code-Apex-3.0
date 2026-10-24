"""Tests for STATE 2: Monte Carlo Risk Engine (Scipy Sobol QMC & PERT loss distributions)."""

from datetime import UTC, datetime

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from cyberq.audit.chain import AuditService
from cyberq.core.database import Base
from cyberq.exposure.engine import ExposureEngine
from cyberq.exposure.models import ExposureScenario
from cyberq.incidents.models import Incident

TEST_SEED = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


@pytest.fixture
def db_session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    yield session
    session.close()


def test_scenario_derivation_from_telemetry_and_incident() -> None:
    """Verifies that ExposureEngine properly calibrates risk parameters based on severity and asset tier."""
    # Tier 1 Critical Asset (CBS)
    scen_crit = ExposureEngine.scenario_from_telemetry(
        severity="critical",
        assets=["CBS-PROD-APP01", "RTGS-GATEWAY"],
        cve_ids=["CVE-2024-3400"],
    )
    assert scen_crit.threat_event_frequency_mode >= 5.0
    assert scen_crit.primary_loss_mode_lakhs > 400.0  # Boosted for Tier 1 asset
    assert scen_crit.secondary_loss_prob >= 0.70

    # Low Severity General Asset
    scen_low = ExposureEngine.scenario_from_telemetry(
        severity="low",
        assets=["branch-printer-01"],
    )
    assert scen_low.threat_event_frequency_mode <= 1.0
    assert scen_low.primary_loss_mode_lakhs <= 30.0

    # Incident Wiring
    inc = Incident(
        id="inc-test-var",
        incident_number="INC-2026-0999",
        title="Intake Alert: Palo Alto Threat Alert (rtgs-switch.bank.internal)",
        summary="Command injection exploit CVE-2024-3400 targeting RTGS Interface",
        severity="critical",
        created_by_id="system-intake",
    )
    scen_from_inc = ExposureEngine.scenario_from_incident(inc)
    assert "RTGS" in scen_from_inc.name or "INC-2026-0999" in scen_from_inc.scenario_id
    assert scen_from_inc.vulnerability > 0.35


def test_sobol_16384_iterations_and_two_sided_ks_convergence(db_session: Session) -> None:
    """Verifies that 16,384 scrambled Sobol iterations produce valid VaR in ₹ Crores and two-sided KS proofs."""
    audit = AuditService(TEST_SEED)
    scen = ExposureEngine.scenario_from_telemetry(
        severity="critical",
        assets=["RTGS-GATEWAY", "SWIFT-INTERFACE"],
        cve_ids=["CVE-2024-3400", "CVE-2023-4966"],
    )

    res = ExposureEngine.simulate_scenario(
        scenario=scen,
        session=db_session,
        audit=audit,
    )

    # 1. Exact iteration count invariant
    assert res.iterations == 16384

    # 2. Monotonic quantiles
    assert res.p10_lakhs <= res.p50_lakhs <= res.p90_lakhs <= res.p99_lakhs
    assert res.p10_crores <= res.p50_crores <= res.p90_crores <= res.p99_crores

    # 3. Currency scaling (1 Crore = 100 Lakhs)
    assert abs(res.p50_crores - (res.p50_lakhs / 100.0)) < 1e-4
    assert abs(res.p99_crores - (res.p99_lakhs / 100.0)) < 1e-4

    # 4. RBI-mandated Two-Sided Kolmogorov-Smirnov test output
    assert res.ks_stat > 0.0
    assert 0.0 <= res.ks_pvalue <= 1.0
    assert res.rbi_mrm_manifest["ks_convergence_test"] == "Two-sided Kolmogorov-Smirnov"
    assert "CONVERGED" in res.rbi_mrm_manifest["convergence_status"]


def test_simulate_directly_from_incident(db_session: Session) -> None:
    """Verifies end-to-end simulation invocation directly from an Incident instance."""
    audit = AuditService(TEST_SEED)
    inc = Incident(
        id="inc-direct-sim",
        incident_number="INC-2026-1001",
        title="Mimikatz memory injection on Core Banking Switch",
        summary="Exploit CVE-2024-3400 lateral movement towards CBS database cluster",
        severity="critical",
        created_by_id="analyst-maker",
    )
    db_session.add(inc)
    db_session.commit()

    res = ExposureEngine.simulate_from_incident(
        incident=inc,
        session=db_session,
        audit=audit,
    )
    assert res.iterations == 16384
    assert res.p90_crores > 0.0
    assert res.expected_annual_loss_crores > 0.0
