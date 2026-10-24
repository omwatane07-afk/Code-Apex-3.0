"""Tests for CYBERQ Professional Multi-Agent Cybersecurity Verification Team.

Covers:
- Level 1-6 Organizational Structure & HR Workforce Management
- Canonical Evidence & Tamper-Evident SHA-256 Provenance
- Deterministic Decision Engine & Quality Gates
- Scenario A: Correct Detection -> PASS
- Scenario B: Missed Critical Threat -> FAIL (mandatory failure blocks PASS)
- Scenario C: Contradictory Agents -> Preserves both findings, no majority voting
- Scenario D: False Evidence -> Auditor rejects claim contradicting raw logs
- Scenario E: Missing Telemetry -> Disconnected connector identified as observability failure, not safety
- Scenario F: Repeated Review -> Revision after rejection, regression verification
- Scenario G: Unresolved Investigation -> Budget exhausted, terminates INCONCLUSIVE with limitations
- Scenario H: Conflicting Regulatory Claim -> Unverified citation rejected, primary source enforced
- Verification REST API endpoints
"""

from fastapi.testclient import TestClient

from cyberq.api.app import create_app
from cyberq.verification.connectors import (
    BankIntegrationManager,
    ConnectorStatus,
    TelemetryObservationType,
)
from cyberq.verification.engine import (
    VerificationTeamEngine,
)
from cyberq.verification.models import (
    CanonicalEvidenceModel,
    EvidenceValidationStatus,
    VerificationVerdict,
)
from cyberq.verification.organization import (
    AgentHierarchyLevel,
    AgentRole,
    HRWorkforceCoordinator,
    initialize_default_organization,
)


def test_organization_structure_levels() -> None:
    """Verifies that all 6 organizational hierarchy levels and defined roles exist."""
    registry = initialize_default_organization()
    assert len(registry) == 16

    levels = {agent.level for agent in registry.values()}
    assert AgentHierarchyLevel.LEVEL_1_DIRECTOR in levels
    assert AgentHierarchyLevel.LEVEL_2_TEAM_LEAD in levels
    assert AgentHierarchyLevel.LEVEL_3_SPECIALIST in levels
    assert AgentHierarchyLevel.LEVEL_4_HR_COORDINATOR in levels
    assert AgentHierarchyLevel.LEVEL_5_INDEPENDENT_QA in levels
    assert AgentHierarchyLevel.LEVEL_6_VERDICT_COMMITTEE in levels

    # Director exists and cannot declare secure without evidence
    director = registry["DIR-01"]
    assert director.role == AgentRole.TEAM_DIRECTOR
    assert "Never declare a product secure without verified evidence" in director.responsibilities

    # Independent QA exists and reports independently
    qa = registry["QA-RED-01"]
    assert qa.role == AgentRole.INDEPENDENT_QA_LEAD
    assert qa.supervisor_role is None  # Independent


def test_hr_workforce_coordinator_assignment_and_metrics() -> None:
    """Tests HR Coordinator role assignment, quality score tracking, and stall detection."""
    registry = initialize_default_organization()
    hr = HRWorkforceCoordinator(registry)

    # Assign task to Threat Detection Specialist
    assigned = hr.assign_task("TASK-001", AgentRole.THREAT_DETECTION_SPECIALIST)
    assert assigned.role == AgentRole.THREAT_DETECTION_SPECIALIST
    assert assigned.tasks_assigned == 1

    # Record review rejection (score decreases)
    initial_score = assigned.evidence_grounding_score
    hr.record_review_outcome(assigned.agent_id, passed=False, rejection_reason="Missing hash")
    assert assigned.evidence_grounding_score < initial_score
    assert assigned.rejections_count == 1

    # Record review pass (score increases, task completed)
    hr.record_review_outcome(assigned.agent_id, passed=True)
    assert assigned.tasks_completed == 1

    # Stall detection triggers at >= 4 cycles
    stall_normal = hr.detect_unproductive_cycles("TASK-001", 2)
    assert stall_normal["stalled"] is False

    stall_flagged = hr.detect_unproductive_cycles("TASK-001", 4)
    assert stall_flagged["stalled"] is True


def test_canonical_evidence_hashing_and_validation() -> None:
    """Tests SHA-256 tamper-evident integrity of canonical evidence records."""
    raw_obs = {"timestamp": "2026-10-21T12:00:00Z", "port": 514, "event": "ALERT_TRIGGERED"}
    hash_1 = CanonicalEvidenceModel.calculate_hash(raw_obs)
    hash_2 = CanonicalEvidenceModel.calculate_hash(raw_obs)
    assert hash_1 == hash_2
    assert len(hash_1) == 64  # SHA-256 hex string

    # Modifying payload produces different hash
    raw_obs_modified = {"timestamp": "2026-10-21T12:00:00Z", "port": 514, "event": "ALERT_SUPPRESSED"}
    hash_3 = CanonicalEvidenceModel.calculate_hash(raw_obs_modified)
    assert hash_1 != hash_3


def test_scenario_a_correct_detection() -> None:
    """SCENARIO A — Correct Detection: Product detects all required synthetic threats -> PASS."""
    engine = VerificationTeamEngine()
    result = engine.run_scenario_a_correct_detection()

    assert result["verdict"] == VerificationVerdict.PASS.value
    assert result["quality_gate"]["overall_pass"] is True
    assert result["evidence_count"] >= 8
    assert result["mandatory_tests_passed"] >= 7


def test_scenario_b_missed_critical_threat() -> None:
    """SCENARIO B — Missed Critical Threat: Missed mandatory detection blocks PASS -> FAIL."""
    engine = VerificationTeamEngine()
    result = engine.run_scenario_b_missed_threat()

    assert result["verdict"] == VerificationVerdict.FAIL.value
    assert "SCEN-MALWARE-01" in result["failed_mandatory_tests"]
    assert result["quality_gate"]["all_critical_passed"] is False

    # Check deterministic rule triggered
    rule_ids = [r["rule_id"] for r in result["rules_triggered"]]
    assert "RULE-DET-02" in rule_ids


def test_scenario_c_contradictory_agents() -> None:
    """SCENARIO C — Contradictory Agents: System preserves disagreement and refuses majority voting."""
    engine = VerificationTeamEngine()
    result = engine.run_scenario_c_contradictory_agents()

    assert result["majority_voting_refused"] is True
    dispute = result["disagreement_preserved"]
    assert dispute["agent_a_role"] == "threat_detection_specialist"
    assert dispute["agent_b_role"] == "false_positive_specialist"
    assert dispute["resolution_outcome"] is None  # Preserved without arbitrary suppression
    assert result["verdict"] == VerificationVerdict.CONDITIONAL.value


def test_scenario_d_false_evidence() -> None:
    """SCENARIO D — False Evidence: Auditor rejects claim that contradicts raw observation."""
    engine = VerificationTeamEngine()
    result = engine.run_scenario_d_false_evidence()

    assert result["auditor_action"] == "SUBMISSION_REJECTED"
    assert result["evidence_status"] == EvidenceValidationStatus.CONTRADICTED.value
    assert result["raw_log_contradiction"]["http_status"] == 404
    assert result["hr_action"]["status"] == "RECORDED"


def test_scenario_e_missing_telemetry() -> None:
    """SCENARIO E — Missing Telemetry: Disconnected connector identified as observability failure, NOT safety."""
    engine = VerificationTeamEngine()
    result = engine.run_scenario_e_missing_telemetry()

    assert result["verdict"] == VerificationVerdict.INCONCLUSIVE.value
    assert result["observation_type"] == TelemetryObservationType.CONNECTOR_FAILURE.value
    assert "OBSERVABILITY FAILURE" in result["analysis"]["reason"]
    # Fundamental invariant: is_safe must be False!
    assert result["analysis"]["is_safe"] is False


def test_scenario_f_repeated_review_and_regression() -> None:
    """SCENARIO F — Repeated Review: Specialist revises finding; regression tests verified passing."""
    engine = VerificationTeamEngine()
    result = engine.run_scenario_f_repeated_review()

    assert result["review_cycles"] == 2
    assert result["regression_passed"] is True
    assert result["history_preserved"] is True


def test_scenario_g_unresolved_investigation() -> None:
    """SCENARIO G — Unresolved Investigation: Iteration budget exhausted -> INCONCLUSIVE with limitations."""
    engine = VerificationTeamEngine()
    result = engine.run_scenario_g_unresolved_investigation()

    assert result["verdict"] == VerificationVerdict.INCONCLUSIVE.value
    assert result["iterations_used"] == 5
    assert len(result["explicit_limitations"]) > 0


def test_scenario_h_conflicting_regulatory_claim() -> None:
    """SCENARIO H — Conflicting Regulatory Claim: Unsupported requirement blocked from publication."""
    engine = VerificationTeamEngine()
    result = engine.run_scenario_h_conflicting_regulatory_claim()

    assert result["is_verified"] is False
    assert result["blocked_from_publication"] is True
    assert "CONTRADICTION DETECTED" in result["critique"]
    assert "six hours" in result["verified_primary_text"]


def test_bank_connectors_telemetry_gap_analysis() -> None:
    """Tests bank integration manager gap detection and outage simulation."""
    mgr = BankIntegrationManager()
    assert len(mgr.connectors) == 8

    # Healthy check
    res_healthy = mgr.analyze_telemetry_receipt(
        "CONN-EDR-01",
        "SCEN-AUTH-01",
        [{"event_id": "EV-1", "timestamp": "NOW", "severity": "HIGH", "threat_indicator": "IP"}],
    )
    assert res_healthy["is_safe"] is True

    # Outage check
    mgr.simulate_connector_outage("CONN-SIEM-01", ConnectorStatus.DISCONNECTED, "HEC Buffer Overflow")
    res_outage = mgr.analyze_telemetry_receipt("CONN-SIEM-01", "SCEN-LOGGING-01", [])
    assert res_outage["is_safe"] is False
    assert res_outage["observation_type"] == TelemetryObservationType.CONNECTOR_FAILURE.value


def test_verification_api_endpoints() -> None:
    """Tests REST API endpoints for status, organization, timeline, results, and scenario execution."""
    app = create_app()
    client = TestClient(app)

    # 1. Status
    res_status = client.get("/api/v1/verification/status")
    assert res_status.status_code == 200
    status_data = res_status.json()
    assert status_data["status"] == "OPERATIONAL"
    assert "disclaimer" in status_data

    # 2. Organization
    res_org = client.get("/api/v1/verification/organization")
    assert res_org.status_code == 200
    org_data = res_org.json()
    assert org_data["total_agents"] == 16

    # 3. Connectors
    res_conn = client.get("/api/v1/verification/connectors")
    assert res_conn.status_code == 200
    conn_data = res_conn.json()
    assert conn_data["connectors_count"] == 8

    # 4. Results
    res_results = client.get("/api/v1/verification/results")
    assert res_results.status_code == 200
    results_data = res_results.json()
    assert "confusion_matrix" in results_data
    assert "metrics" in results_data

    # 5. Execute Scenario via API
    res_scen_b = client.post("/api/v1/verification/scenarios/scenario_b/execute")
    assert res_scen_b.status_code == 200
    assert res_scen_b.json()["verdict"] == "FAIL"

    # 6. Report Generation
    res_report = client.get("/api/v1/verification/reports/INV-SCENARIO-B")
    assert res_report.status_code == 200
    report_data = res_report.json()
    assert report_data["report_type"] == "Platform-Issued Cybersecurity Verification Report"
    assert len(report_data["committee_signoffs"]) == 4
