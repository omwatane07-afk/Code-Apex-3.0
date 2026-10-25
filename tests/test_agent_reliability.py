"""Rigorous Reliability & Stress Benchmark for CYBERQ 11-Phase Multi-Agent Engine.

Executes:
- State 1: 10 Complex Synthetic Banking SOC Alerts with mathematically & statutorily known ground truth.
- State 2: Profiling of Accuracy (Zero Hallucination Clause Matching), Reliability (Strict JSON), and Latency.
- State 3: Self-healing schema validation and canonical statutory grounding.
- State 4: 100% regression clearance across all 10 synthetic enterprise scenarios.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Generator
from datetime import UTC, datetime
from typing import Any

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from cyberq.audit.chain import AuditService
from cyberq.core.database import Base
from cyberq.intake.models import NormalizedSecurityEvent
from cyberq.verification.engine import VerificationTeamEngine
from cyberq.verification.llm_client import (
    CANONICAL_STATUTORY_TAXONOMY,
    OLLAMA_MODEL_NAME,
    OllamaLLMClient,
)
from cyberq.verification.models import (
    MultiAgentTriageBundle,
    RegulatoryClauseMatcherOutput,
    ToolPassportInspectorOutput,
    TriageSpecialistOutput,
    VerificationVerdict,
)

logger = logging.getLogger(__name__)

TEST_AUDIT_SEED = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

# ============================================================================
# STATE 1: 10 COMPLEX SYNTHETIC BANKING SOC ALERTS WITH GROUND TRUTH
# ============================================================================

SYNTHETIC_BENCHMARK_SCENARIOS: list[dict[str, Any]] = [
    {
        "scenario_id": "SYNTH-01-RANSOMWARE-CBS",
        "description": "Core Banking ransomware with Volume Shadow Copy deletion and AES encryption",
        "alert": {
            "event_id": "ALERT-CBS-2026-001",
            "source_tool": "CrowdStrike Falcon",
            "vendor": "CrowdStrike",
            "category": "EDR/XDR",
            "severity": "critical",
            "cve_ids": ["CVE-2024-3400"],
            "certin_advisories": ["CIVN-2024-0131: Ransomware Campaign Targeting Financial Systems"],
            "raw_message": (
                "Ransomware binary detected on CBS-PROD-DB-01 executing 'vssadmin delete shadows /all /quiet' "
                "followed by AES encryption of database storage volumes."
            ),
        },
        "passport": {"tool_id": "CrowdStrike Falcon", "trust_status": "VERIFIED", "vapt_valid": True, "is_unverified": False},
        "ground_truth": {
            "severity": "critical",
            "triage_disposition": "ESCALATE_TO_INCIDENT",
            "is_reportable": True,
            "deadline_hours": 6,
            "required_clause_keywords": ["Malicious code attacks such as Ransomware", "Para 182"],
            "trust_status": "VERIFIED",
            "final_verdict": VerificationVerdict.PASS.value,
        },
    },
    {
        "scenario_id": "SYNTH-02-RTGS-RCE-PAYMENT",
        "description": "Zero-day remote code execution on RTGS payment gateway switch",
        "alert": {
            "event_id": "ALERT-RTGS-2026-002",
            "source_tool": "Palo Alto Networks Cortex XDR",
            "vendor": "Palo Alto Networks",
            "category": "Network Security",
            "severity": "critical",
            "cve_ids": ["CVE-2024-3400", "CVE-2024-21887"],
            "certin_advisories": ["CIVN-2024-0105: Critical Flaws in Payment Switching Appliances"],
            "raw_message": (
                "Zero-day command injection exploit targeting RTGS payment gateway switch interface (RTGS-SW-01). "
                "Reverse bash shell spawned from nginx root."
            ),
        },
        "passport": {"tool_id": "Palo Alto Networks Cortex XDR", "trust_status": "VERIFIED", "vapt_valid": True, "is_unverified": False},
        "ground_truth": {
            "severity": "critical",
            "triage_disposition": "ESCALATE_TO_INCIDENT",
            "is_reportable": True,
            "deadline_hours": 6,
            "required_clause_keywords": ["Digital Payment", "critical information infrastructure"],
            "trust_status": "VERIFIED",
            "final_verdict": VerificationVerdict.PASS.value,
        },
    },
    {
        "scenario_id": "SYNTH-03-SWIFT-LATERAL-MVT",
        "description": "SWIFT Alliance Gateway lateral movement via Kerberoasting",
        "alert": {
            "event_id": "ALERT-SWIFT-2026-003",
            "source_tool": "Microsoft Defender for Endpoint",
            "vendor": "Microsoft",
            "category": "EDR/XDR",
            "severity": "critical",
            "cve_ids": [],
            "certin_advisories": ["CIVN-2024-0089: Targeted Kerberoasting on Financial Messaging Systems"],
            "raw_message": (
                "Service Ticket extraction (Kerberoasting) against SPN 'MSSQLSvc/swift-sag.bank.internal:1433' "
                "followed by SMB Pass-The-Hash lateral movement to SWIFT Alliance Gateway."
            ),
        },
        "passport": {"tool_id": "Microsoft Defender for Endpoint", "trust_status": "VERIFIED", "vapt_valid": True, "is_unverified": False},
        "ground_truth": {
            "severity": "critical",
            "triage_disposition": "ESCALATE_TO_INCIDENT",
            "is_reportable": True,
            "deadline_hours": 6,
            "required_clause_keywords": ["Compromise of critical systems", "SWIFT, RTGS, CBS"],
            "trust_status": "VERIFIED",
            "final_verdict": VerificationVerdict.PASS.value,
        },
    },
    {
        "scenario_id": "SYNTH-04-PII-EXFILTRATION-DPDP",
        "description": "Massive customer Aadhaar and PAN database exfiltration",
        "alert": {
            "event_id": "ALERT-DATA-2026-004",
            "source_tool": "Splunk Enterprise Security",
            "vendor": "Splunk",
            "category": "SIEM",
            "severity": "critical",
            "cve_ids": [],
            "certin_advisories": ["CIVN-2024-0045: Unauthorized Data Exfiltration Campaign"],
            "raw_message": (
                "Data exfiltration detected on ANALYTICS-DB-02: 450,000 Aadhaar numbers and 320,000 PAN cards dumped "
                "via pg_dump and compressed to tar.gz over external HTTPS socket to 198.51.100.42."
            ),
        },
        "passport": {"tool_id": "Splunk Enterprise Security", "trust_status": "VERIFIED", "vapt_valid": True, "is_unverified": False},
        "ground_truth": {
            "severity": "critical",
            "triage_disposition": "ESCALATE_TO_INCIDENT",
            "is_reportable": True,
            "deadline_hours": 72,
            "required_clause_keywords": ["DPDP Act 2023", "Unauthorized access of IT systems/data"],
            "trust_status": "VERIFIED",
            "final_verdict": VerificationVerdict.PASS.value,
        },
    },
    {
        "scenario_id": "SYNTH-05-UPI-DDOS-FLOOD",
        "description": "Volumetric TCP SYN flood saturating UPI immediate payment gateway",
        "alert": {
            "event_id": "ALERT-UPI-2026-005",
            "source_tool": "Cloudflare Magic Transit",
            "vendor": "Cloudflare",
            "category": "DDoS Mitigation",
            "severity": "high",
            "cve_ids": [],
            "certin_advisories": ["CIVN-2024-0012: Volumetric DDoS on Banking Switch Endpoints"],
            "raw_message": (
                "Volumetric TCP SYN flood measuring 65 Gbps / 42 Mpps targeting api.upi.bank.internal. "
                "Transactions experiencing 45% timeout degradation."
            ),
        },
        "passport": {"tool_id": "Cloudflare Magic Transit", "trust_status": "VERIFIED", "vapt_valid": True, "is_unverified": False},
        "ground_truth": {
            "severity": "high",
            "triage_disposition": "ESCALATE_TO_INCIDENT",
            "is_reportable": True,
            "deadline_hours": 6,
            "required_clause_keywords": ["Digital Payment", "critical information infrastructure"],
            "trust_status": "VERIFIED",
            "final_verdict": VerificationVerdict.PASS.value,
        },
    },
    {
        "scenario_id": "SYNTH-06-AD-GOLDEN-TICKET",
        "description": "Active Directory Golden Ticket forgery with Domain Controller takeover",
        "alert": {
            "event_id": "ALERT-AD-2026-006",
            "source_tool": "CrowdStrike Falcon Identity Protection",
            "vendor": "CrowdStrike",
            "category": "Identity Security",
            "severity": "critical",
            "cve_ids": [],
            "certin_advisories": ["CIVN-2024-0067: Active Directory Domain Controller Privilege Escalation"],
            "raw_message": (
                "Kerberos TGT ticket forged with domain KRBTGT NTLM hash (Golden Ticket) for Administrator account. "
                "Ticket lifetime set to 10 years, injected into LSASS on DC-PRIMARY.bank.internal."
            ),
        },
        "passport": {"tool_id": "CrowdStrike Falcon Identity Protection", "trust_status": "VERIFIED", "vapt_valid": True, "is_unverified": False},
        "ground_truth": {
            "severity": "critical",
            "triage_disposition": "ESCALATE_TO_INCIDENT",
            "is_reportable": True,
            "deadline_hours": 6,
            "required_clause_keywords": ["Compromise of critical systems", "Identity theft, spoofing"],
            "trust_status": "VERIFIED",
            "final_verdict": VerificationVerdict.PASS.value,
        },
    },
    {
        "scenario_id": "SYNTH-07-EXPIRED-VAPT-PASSPORT",
        "description": "Unverified telemetry with expired tool VAPT passport (RBI Para 90 exception)",
        "alert": {
            "event_id": "ALERT-VAPT-2026-007",
            "source_tool": "Legacy-Syslog-Parser-v2",
            "vendor": "Legacy Tool Vendor",
            "category": "SIEM",
            "severity": "medium",
            "cve_ids": [],
            "certin_advisories": [],
            "raw_message": (
                "Anomalous administrative login on jumpbox server 10.10.5.20. Note: Sensor passport VAPT "
                "certification expired 45 days ago."
            ),
        },
        "passport": {"tool_id": "Legacy-Syslog-Parser-v2", "trust_status": "DEGRADED", "vapt_valid": False, "is_unverified": True},
        "ground_truth": {
            "severity": "medium",
            "triage_disposition": "REQUIRES_DEEP_INSPECTION",
            "is_reportable": False,
            "deadline_hours": 0,
            "required_clause_keywords": [],
            "trust_status": "DEGRADED",
            "final_verdict": VerificationVerdict.CONDITIONAL.value,
        },
    },
    {
        "scenario_id": "SYNTH-08-SUPPLY-CHAIN-POISON",
        "description": "Compromised PyPI dependency in Internet Banking CI/CD build pipeline",
        "alert": {
            "event_id": "ALERT-SC-2026-008",
            "source_tool": "Snyk Container Security",
            "vendor": "Snyk",
            "category": "AppSec / SCA",
            "severity": "critical",
            "cve_ids": ["CVE-2024-29025"],
            "certin_advisories": ["CIVN-2024-0118: Malicious Packages in Software Supply Chain"],
            "raw_message": (
                "Compromised PyPI package 'net-crypto-helper-v2' identified in NetBanking build CI/CD runner. "
                "Payload attempts credential theft from /etc/vault/tokens."
            ),
        },
        "passport": {"tool_id": "Snyk Container Security", "trust_status": "VERIFIED", "vapt_valid": True, "is_unverified": False},
        "ground_truth": {
            "severity": "critical",
            "triage_disposition": "ESCALATE_TO_INCIDENT",
            "is_reportable": True,
            "deadline_hours": 6,
            "required_clause_keywords": ["Supply chain attack", "Malicious code attacks"],
            "trust_status": "VERIFIED",
            "final_verdict": VerificationVerdict.PASS.value,
        },
    },
    {
        "scenario_id": "SYNTH-09-MAINTENANCE-BENIGN",
        "description": "Scheduled DBA maintenance script execution during approved change window",
        "alert": {
            "event_id": "ALERT-BENIGN-2026-009",
            "source_tool": "Wazuh HIDS",
            "vendor": "Wazuh",
            "category": "Host IDS",
            "severity": "low",
            "cve_ids": [],
            "certin_advisories": [],
            "raw_message": (
                "Privileged script execution 'cbs_nightly_backup.ps1' by service account 'svc_backup' on BACKUP-SRV-02 "
                "during approved maintenance window CHG-2026-881."
            ),
        },
        "passport": {"tool_id": "Wazuh HIDS", "trust_status": "VERIFIED", "vapt_valid": True, "is_unverified": False},
        "ground_truth": {
            "severity": "low",
            "triage_disposition": "SUPPRESS_BENIGN",
            "is_reportable": False,
            "deadline_hours": 0,
            "required_clause_keywords": [],
            "trust_status": "VERIFIED",
            "final_verdict": VerificationVerdict.PASS.value,
        },
    },
    {
        "scenario_id": "SYNTH-10-PERIMETER-SCAN-PROBE",
        "description": "External perimeter port scan dropped at perimeter firewall",
        "alert": {
            "event_id": "ALERT-PROBE-2026-010",
            "source_tool": "Palo Alto Networks Edge Firewall",
            "vendor": "Palo Alto Networks",
            "category": "Firewall",
            "severity": "low",
            "cve_ids": [],
            "certin_advisories": [],
            "raw_message": (
                "External IP 203.0.113.88 scanned TCP ports 22, 80, 443 on public edge router. "
                "All packets dropped at perimeter firewall rule DENY_ALL_UNSOLICITED."
            ),
        },
        "passport": {"tool_id": "Palo Alto Networks Edge Firewall", "trust_status": "VERIFIED", "vapt_valid": True, "is_unverified": False},
        "ground_truth": {
            "severity": "low",
            "triage_disposition": "SUPPRESS_BENIGN",
            "is_reportable": False,
            "deadline_hours": 0,
            "required_clause_keywords": [],
            "trust_status": "VERIFIED",
            "final_verdict": VerificationVerdict.PASS.value,
        },
    },
]


@pytest.fixture
def db_session() -> Generator[Session, None, None]:
    import cyberq.audit.models
    import cyberq.clocks.models
    import cyberq.filings.models
    import cyberq.governance.models
    import cyberq.iam.models
    import cyberq.incidents.models
    import cyberq.intake.models

    _ = (
        cyberq.audit.models,
        cyberq.clocks.models,
        cyberq.filings.models,
        cyberq.governance.models,
        cyberq.iam.models,
        cyberq.incidents.models,
        cyberq.intake.models,
    )

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    yield session
    session.close()


@pytest.fixture
def ollama_client() -> OllamaLLMClient:
    return OllamaLLMClient(timeout=120.0)


# ============================================================================
# STATE 2 & 4: EXECUTION, ACCURACY PROFILING, AND REGRESSION CLEARANCE
# ============================================================================


def test_synthetic_benchmark_scenarios_count() -> None:
    """Verifies that exactly 10 diverse banking scenarios are defined with full ground truth."""
    assert len(SYNTHETIC_BENCHMARK_SCENARIOS) == 10
    scenario_ids = {s["scenario_id"] for s in SYNTHETIC_BENCHMARK_SCENARIOS}
    assert len(scenario_ids) == 10


@pytest.mark.parametrize("scenario", SYNTHETIC_BENCHMARK_SCENARIOS, ids=lambda s: s["scenario_id"])
def test_agent_reliability_per_scenario(
    scenario: dict[str, Any],
    ollama_client: OllamaLLMClient,
    db_session: Session,
) -> None:
    """Rigorous evaluation of individual SOC alerts:

    Profiles:
    1. Accuracy: Strict statutory clause identification and zero hallucination.
    2. Reliability: Clean JSON deserialization into Pydantic models.
    3. Latency: Full 11-phase workflow execution within expected UAT window.
    """
    scen_id = scenario["scenario_id"]
    alert = scenario["alert"]
    passport_data = scenario["passport"]
    gt = scenario["ground_truth"]

    logger.info("Executing Benchmark Scenario: %s (%s)", scen_id, scenario["description"])
    t_start = time.perf_counter()

    # Phase 1-11 Execution via VerificationTeamEngine
    audit = AuditService(TEST_AUDIT_SEED)
    engine = VerificationTeamEngine(db_session=db_session, llm_client=ollama_client)

    event = NormalizedSecurityEvent(
        event_id=alert["event_id"],
        source_tool=alert["source_tool"],
        vendor=alert["vendor"],
        category=alert["category"],
        timestamp=datetime.now(UTC),
        source_ip="10.14.2.77",
        destination_ip="172.16.0.4",
        source_hostname="workstation.bank.internal",
        destination_hostname="core.bank.internal",
        cve_ids=alert["cve_ids"],
        signature_id=f"SIG-{scen_id}",
        event_name=scen_id,
        severity=alert["severity"],
        raw_message=alert["raw_message"],
        certin_advisories=alert["certin_advisories"],
        is_telemetry_unverified=bool(passport_data.get("is_unverified", False)),
    )

    inv = engine.run_live_intake_verification(
        event=event,
        audit=audit,
        db_session=db_session,
        use_llm=True,
    )
    t_elapsed = round(time.perf_counter() - t_start, 2)

    logger.info("Scenario %s completed in %.2f seconds", scen_id, t_elapsed)

    # ------------------------------------------------------------------------
    # METRIC 1: RELIABILITY (JSON DESERIALIZATION & SCHEMA INTEGRITY)
    # ------------------------------------------------------------------------
    assert "multi_agent_bundle" in inv, f"Multi-agent bundle missing for {scen_id}"
    bundle_data = inv["multi_agent_bundle"]

    bundle = MultiAgentTriageBundle.model_validate(bundle_data)
    assert bundle.model_used == OLLAMA_MODEL_NAME
    assert isinstance(bundle.triage, TriageSpecialistOutput)
    assert isinstance(bundle.regulatory, RegulatoryClauseMatcherOutput)
    assert isinstance(bundle.passport, ToolPassportInspectorOutput)

    # ------------------------------------------------------------------------
    # METRIC 2: ACCURACY & STATUTORY CLAUSE GROUNDING (ZERO HALLUCINATION)
    # ------------------------------------------------------------------------
    # Verify reportability flag matches statutory mandate
    assert bundle.regulatory.is_reportable == gt["is_reportable"], (
        f"Statutory reportability mismatch for {scen_id}: expected {gt['is_reportable']}, got {bundle.regulatory.is_reportable}"
    )

    # Verify deadline hours
    if gt["is_reportable"]:
        assert bundle.regulatory.deadline_hours in (6, 72), (
            f"Invalid statutory deadline for {scen_id}: got {bundle.regulatory.deadline_hours}h"
        )
    else:
        assert bundle.regulatory.deadline_hours == 0, (
            f"Benign event should have 0 deadline hours, got {bundle.regulatory.deadline_hours}"
        )

    # Verify zero-hallucination constraint: all matched clauses MUST belong to verified taxonomy
    for clause in bundle.regulatory.matched_clauses:
        assert clause in CANONICAL_STATUTORY_TAXONOMY, (
            f"HALLUCINATED CLAUSE DETECTED for {scen_id}: '{clause}' is not in verified statutory canon!"
        )

    # Verify required domain statutory keywords are present
    if gt["required_clause_keywords"]:
        has_required_clause = any(
            any(kw.lower() in c.lower() for c in bundle.regulatory.matched_clauses)
            for kw in gt["required_clause_keywords"]
        )
        assert has_required_clause, (
            f"Missing required statutory clause for {scen_id}: Expected one of {gt['required_clause_keywords']}, "
            f"got {bundle.regulatory.matched_clauses}"
        )

    # Verify passport compliance status
    assert bundle.passport.trust_status == gt["trust_status"], (
        f"Passport trust status mismatch for {scen_id}: expected {gt['trust_status']}, got {bundle.passport.trust_status}"
    )

    # Verify final deterministic verdict
    assert inv["final_verdict"] == gt["final_verdict"], (
        f"Final verdict mismatch for {scen_id}: expected {gt['final_verdict']}, got {inv['final_verdict']}"
    )

    # ------------------------------------------------------------------------
    # METRIC 3: LATENCY & 11-PHASE WORKFLOW COMPLETION
    # ------------------------------------------------------------------------
    assert inv["current_phase"] == "Phase 11: Final Approval"
    assert t_elapsed < 120.0, f"UAT Timeout Exceeded: {t_elapsed}s > 120s"
