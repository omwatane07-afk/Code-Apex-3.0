"""Tests for STATE 3 & 4: Local Ollama Qwen 2.5 Coder Multi-Agent Verification Pipeline.

Validates:
1. Air-Gapped execution via http://localhost:11434 with model 'qwen2.5-coder'.
2. Deterministic JSON output parsing into strict Pydantic schemas.
3. Multi-agent execution of Triage Specialist, Regulatory Clause Matcher, and Tool Passport Inspector.
4. Full 11-phase VerificationTeamEngine integration with dummy CrowdStrike alert.
"""

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

TEST_SEED = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"


@pytest.fixture
def db_session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    yield session
    session.close()


@pytest.fixture
def dummy_crowdstrike_alert() -> dict[str, Any]:
    """Provides a realistic dummy CrowdStrike Falcon alert payload for testing."""
    return {
        "event_id": "CS-ALERT-2026-9901",
        "source_tool": "CrowdStrike Falcon",
        "vendor": "CrowdStrike",
        "category": "EDR/XDR",
        "severity": "critical",
        "signature_id": "FALCON-MIMIKATZ-INJECT",
        "event_name": "Credential Access via Mimikatz Memory Injection",
        "source_ip": "10.14.2.77",
        "destination_ip": "172.16.0.4",
        "source_hostname": "workstation-hr.bank.internal",
        "destination_hostname": "RTGS-SWITCH-01",
        "cve_ids": ["CVE-2024-3400"],
        "certin_advisories": ["CIVN-2024-0131: Palo Alto PAN-OS GlobalProtect Command Injection"],
        "raw_message": (
            "Process injection detected: svchost.exe spawned unauthorized powershell.exe "
            "attempting Mimikatz memory dump on RTGS payment gateway switch."
        ),
    }


def test_ollama_qwen_model_name_and_airgap_invariant() -> None:
    """Verifies non-negotiable model name 'qwen2.5-coder' and local base URL."""
    client = OllamaLLMClient()
    assert client.model == "qwen2.5-coder"
    assert "11434" in client.base_url
    assert "openai" not in client.base_url.lower()
    assert "anthropic" not in client.base_url.lower()


def test_ollama_qwen_individual_agents(dummy_crowdstrike_alert: dict[str, Any]) -> None:
    """Verifies that Qwen 2.5 Coder generates valid JSON conforming to all individual agent schemas."""
    client = OllamaLLMClient(timeout=90.0)

    # 1. Triage Specialist Agent
    triage_out = client.run_triage_specialist(dummy_crowdstrike_alert)
    assert isinstance(triage_out, TriageSpecialistOutput)
    assert triage_out.agent == "TriageSpecialist"
    assert triage_out.severity in ("critical", "high")
    assert triage_out.triage_disposition in (
        "ESCALATE_TO_INCIDENT",
        "REQUIRES_DEEP_INSPECTION",
        "SUPPRESS_BENIGN",
    )
    assert len(triage_out.summary) > 5

    # 2. Regulatory Clause Matcher Agent
    reg_out = client.run_regulatory_matcher(
        dummy_crowdstrike_alert,
        cve_ids=dummy_crowdstrike_alert["cve_ids"],
    )
    assert isinstance(reg_out, RegulatoryClauseMatcherOutput)
    assert reg_out.agent == "RegulatoryClauseMatcher"
    assert reg_out.is_reportable is True
    assert reg_out.deadline_hours in (6, 48, 72)
    assert len(reg_out.reasoning) > 5

    # 3. Tool Passport Inspector Agent
    passport_out = client.run_passport_inspector(
        tool_id="crowdstrike",
        passport_data={"trust_status": "VERIFIED", "vapt_valid": True},
    )
    assert isinstance(passport_out, ToolPassportInspectorOutput)
    assert passport_out.agent == "ToolPassportInspector"
    assert passport_out.trust_status == "VERIFIED"
    assert passport_out.vapt_valid is True
    assert passport_out.is_telemetry_unverified is False


def test_ollama_qwen_multi_agent_pipeline_bundle(dummy_crowdstrike_alert: dict[str, Any]) -> None:
    """Verifies execution of the aggregated multi-agent pipeline bundle."""
    client = OllamaLLMClient(timeout=90.0)
    bundle = client.run_multi_agent_pipeline(
        event_data=dummy_crowdstrike_alert,
        passport_data={"trust_status": "VERIFIED", "vapt_valid": True},
        investigation_id="INV-QWEN-TEST-001",
    )

    assert isinstance(bundle, MultiAgentTriageBundle)
    assert bundle.investigation_id == "INV-QWEN-TEST-001"
    assert bundle.model_used == "qwen2.5-coder"
    assert bundle.source_tool == "CrowdStrike Falcon"
    assert bundle.final_verdict in ("PASS", "CONDITIONAL")
    assert bundle.triage.severity in ("critical", "high")
    assert bundle.regulatory.is_reportable is True


def test_verification_engine_with_ollama_crowdstrike_live(
    db_session: Session,
    dummy_crowdstrike_alert: dict[str, Any],
) -> None:
    """End-to-end integration: VerificationTeamEngine runs 11 phases with Qwen 2.5 Coder."""
    audit = AuditService(TEST_SEED)
    client = OllamaLLMClient(timeout=90.0)
    engine = VerificationTeamEngine(db_session=db_session, llm_client=client)

    event = NormalizedSecurityEvent(
        event_id=dummy_crowdstrike_alert["event_id"],
        source_tool=dummy_crowdstrike_alert["source_tool"],
        vendor=dummy_crowdstrike_alert["vendor"],
        category=dummy_crowdstrike_alert["category"],
        timestamp=datetime.now(UTC),
        source_ip=dummy_crowdstrike_alert["source_ip"],
        destination_ip=dummy_crowdstrike_alert["destination_ip"],
        source_hostname=dummy_crowdstrike_alert["source_hostname"],
        destination_hostname=dummy_crowdstrike_alert["destination_hostname"],
        cve_ids=dummy_crowdstrike_alert["cve_ids"],
        signature_id=dummy_crowdstrike_alert["signature_id"],
        event_name=dummy_crowdstrike_alert["event_name"],
        severity=dummy_crowdstrike_alert["severity"],
        raw_message=dummy_crowdstrike_alert["raw_message"],
        certin_advisories=dummy_crowdstrike_alert["certin_advisories"],
        is_telemetry_unverified=False,
    )

    inv = engine.run_live_intake_verification(
        event=event,
        audit=audit,
        db_session=db_session,
        use_llm=True,
    )
    db_session.commit()

    # 1. 11 review phases completed
    assert inv["current_phase"] == "Phase 11: Final Approval"
    assert inv["final_verdict"] == VerificationVerdict.PASS.value
    assert inv["model_used"] == "qwen2.5-coder"

    # 2. Multi-agent bundle present in investigation output
    assert "multi_agent_bundle" in inv
    assert inv["multi_agent_bundle"]["model_used"] == "qwen2.5-coder"

    # 3. Canonical Evidence record reflects Qwen analysis
    evd_id = f"EVD-{event.event_id[:10]}"
    assert evd_id in engine.evidence_store
    evd = engine.evidence_store[evd_id]
    assert evd["model_used"] == "qwen2.5-coder"
    assert "llm_triage" in evd
    assert "llm_regulatory" in evd

    # 4. Timeline contains Phase 3 with Qwen annotation
    p3_events = [
        tl for tl in engine.timeline_events
        if tl["phase"] == "Phase 3: Investigate" and tl["investigation_id"] == inv["id"]
    ]
    assert len(p3_events) >= 1
    assert "Local Qwen 2.5 Coder" in p3_events[0]["details"]
