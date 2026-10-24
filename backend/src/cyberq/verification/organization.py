"""Multi-Agent Organizational Structure, Registry, and HR Workforce Management.

Implements the 6-Level cybersecurity organization hierarchy:
Level 1: Executive Orchestrator / Team Director
Level 2: Specialist Team Leads (Security Testing, Evidence & Accuracy, Integration & Monitoring, Compliance & Audit)
Level 3: Specialized Engineers (Threat Detection, False-Positive, Adversarial Designer, Security Config,
         Telemetry & Integration, Reliability, Threat Intel, Independent Evidence Auditor)
Level 4: HR / Workforce Coordinator Agent
Level 5: Independent Quality Assurance / Red Team Review
Level 6: Final Verdict Committee & Deterministic Decision Engine
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class AgentHierarchyLevel(StrEnum):
    LEVEL_1_DIRECTOR = "Level 1: Executive Orchestrator / Team Director"
    LEVEL_2_TEAM_LEAD = "Level 2: Specialist Team Lead"
    LEVEL_3_SPECIALIST = "Level 3: Specialized Engineer"
    LEVEL_4_HR_COORDINATOR = "Level 4: HR / Workforce Coordinator"
    LEVEL_5_INDEPENDENT_QA = "Level 5: Independent QA / Red Team"
    LEVEL_6_VERDICT_COMMITTEE = "Level 6: Final Verdict Committee"


class AgentRole(StrEnum):
    # Level 1
    TEAM_DIRECTOR = "team_director"
    
    # Level 2 Leads
    SECURITY_TESTING_LEAD = "security_testing_lead"
    EVIDENCE_ACCURACY_LEAD = "evidence_accuracy_lead"
    INTEGRATION_MONITORING_LEAD = "integration_monitoring_lead"
    COMPLIANCE_AUDIT_LEAD = "compliance_audit_lead"
    
    # Level 3 Specialists
    THREAT_DETECTION_SPECIALIST = "threat_detection_specialist"
    FALSE_POSITIVE_SPECIALIST = "false_positive_specialist"
    ADVERSARIAL_TEST_DESIGNER = "adversarial_test_designer"
    SECURITY_CONFIG_SPECIALIST = "security_config_specialist"
    TELEMETRY_INTEGRATION_SPECIALIST = "telemetry_integration_specialist"
    RELIABILITY_REPRODUCIBILITY_SPECIALIST = "reliability_reproducibility_specialist"
    THREAT_INTEL_SPECIALIST = "threat_intel_specialist"
    INDEPENDENT_EVIDENCE_AUDITOR = "independent_evidence_auditor"
    
    # Level 4 HR
    HR_WORKFORCE_COORDINATOR = "hr_workforce_coordinator"
    
    # Level 5 QA
    INDEPENDENT_QA_LEAD = "independent_qa_lead"
    
    # Level 6 Final Verdict
    DECISION_ENGINE = "deterministic_decision_engine"


@dataclass
class AgentProfile:
    agent_id: str
    role: AgentRole
    level: AgentHierarchyLevel
    display_name: str
    department: str
    supervisor_role: AgentRole | None
    responsibilities: list[str]
    # Benchmarked performance metrics
    benchmarked_precision: float
    benchmarked_recall: float
    evidence_grounding_score: float
    tasks_assigned: int = 0
    tasks_completed: int = 0
    rejections_count: int = 0
    status: str = "AVAILABLE"  # AVAILABLE, INVESTIGATING, REVIEWING, REASSIGNMENT_RECOMMENDED


class HRWorkforceCoordinator:
    """Level 4: Internal workforce and task-management function.

    Tracks agent performance metrics, detects overloaded agents, flags stalled tasks,
    and detects repeated unproductive review cycles.
    NEVER determines security verdicts based on agent popularity, confidence, or speed.
    """

    def __init__(self, registry: dict[str, AgentProfile]) -> None:
        self.registry = registry
        self.assignment_log: list[dict[str, Any]] = []
        self.cycle_history: list[dict[str, Any]] = []

    def assign_task(self, task_id: str, required_role: AgentRole) -> AgentProfile:
        """Finds the best specialist for the role based on expertise and current load."""
        candidates = [
            agent for agent in self.registry.values()
            if agent.role == required_role and agent.status != "REASSIGNMENT_RECOMMENDED"
        ]
        if not candidates:
            # Fallback to any agent with that role
            candidates = [a for a in self.registry.values() if a.role == required_role]

        if not candidates:
            raise ValueError(f"No registered agent found for role: {required_role}")

        # Choose least-loaded candidate
        chosen = min(candidates, key=lambda a: a.tasks_assigned - a.tasks_completed)
        chosen.tasks_assigned += 1
        chosen.status = "INVESTIGATING"

        self.assignment_log.append({
            "task_id": task_id,
            "agent_id": chosen.agent_id,
            "role": chosen.role.value,
            "timestamp": "ISO_NOW",
        })
        return chosen

    def record_review_outcome(
        self,
        agent_id: str,
        passed: bool,
        rejection_reason: str | None = None,
    ) -> dict[str, Any]:
        """Records whether specialist output passed lead/QA review, updating quality metrics."""
        agent = self.registry.get(agent_id)
        if not agent:
            return {"status": "UNKNOWN_AGENT"}

        if passed:
            agent.tasks_completed += 1
            agent.status = "AVAILABLE"
            # Grounding score slightly improves
            agent.evidence_grounding_score = min(1.0, agent.evidence_grounding_score + 0.01)
        else:
            agent.rejections_count += 1
            agent.evidence_grounding_score = max(0.5, agent.evidence_grounding_score - 0.05)
            # Check for excessive ungrounded submissions
            if agent.rejections_count >= 3 and agent.evidence_grounding_score < 0.70:
                agent.status = "REASSIGNMENT_RECOMMENDED"
                return {
                    "status": "ALERT",
                    "action": "REASSIGNMENT_RECOMMENDED",
                    "reason": f"Agent {agent_id} ({agent.role.value}) repeatedly produced rejected/unsupported conclusions ({agent.rejections_count} rejections). HR recommends supervisory review.",
                }

        return {
            "status": "RECORDED",
            "agent_id": agent_id,
            "rejections": agent.rejections_count,
            "grounding_score": agent.evidence_grounding_score,
        }

    def detect_unproductive_cycles(self, task_id: str, cycle_count: int) -> dict[str, Any]:
        """Detects if an investigation has exceeded review threshold without progress."""
        if cycle_count >= 4:
            return {
                "stalled": True,
                "warning": f"Task {task_id} has completed {cycle_count} review cycles without resolution. Escalating to Director and QA Lead for boundary limitation.",
            }
        return {"stalled": False, "cycles": cycle_count}


def initialize_default_organization() -> dict[str, AgentProfile]:
    """Instantiates the canonical 15-agent cybersecurity verification organization."""
    return {
        # Level 1
        "DIR-01": AgentProfile(
            agent_id="DIR-01",
            role=AgentRole.TEAM_DIRECTOR,
            level=AgentHierarchyLevel.LEVEL_1_DIRECTOR,
            display_name="Dr. Vikram Rao (Executive Orchestrator)",
            department="Executive Direction",
            supervisor_role=None,
            responsibilities=[
                "Define verification scope, acceptance criteria, test environments",
                "Break complex objectives into specialized work packages",
                "Maintain shared task board and detect conflicting conclusions",
                "Ensure final report satisfies bank-grade quality requirements",
                "Never declare a product secure without verified evidence",
            ],
            benchmarked_precision=0.99,
            benchmarked_recall=0.98,
            evidence_grounding_score=0.99,
        ),

        # Level 2 Leads
        "LEAD-SEC-01": AgentProfile(
            agent_id="LEAD-SEC-01",
            role=AgentRole.SECURITY_TESTING_LEAD,
            level=AgentHierarchyLevel.LEVEL_2_TEAM_LEAD,
            display_name="Ananya Sharma (Security Testing Lead)",
            department="Offensive & Defensive Security Testing",
            supervisor_role=AgentRole.TEAM_DIRECTOR,
            responsibilities=[
                "Own test planning and threat scenario coverage",
                "Assign work packages to security-testing specialists",
                "Review completeness and validity of test scenarios",
                "Verify that tests match the product's claimed function",
            ],
            benchmarked_precision=0.96,
            benchmarked_recall=0.95,
            evidence_grounding_score=0.97,
        ),
        "LEAD-EVD-01": AgentProfile(
            agent_id="LEAD-EVD-01",
            role=AgentRole.EVIDENCE_ACCURACY_LEAD,
            level=AgentHierarchyLevel.LEVEL_2_TEAM_LEAD,
            display_name="Marcus Vance (Evidence & Accuracy Lead)",
            department="Evidence Forensics & Traceability",
            supervisor_role=AgentRole.TEAM_DIRECTOR,
            responsibilities=[
                "Check quality, provenance, relevance, and consistency of evidence",
                "Identify unsupported conclusions and hallucinated assertions",
                "Ensure claims link to canonical raw observations",
                "Demand additional evidence when findings are ambiguous",
            ],
            benchmarked_precision=0.98,
            benchmarked_recall=0.97,
            evidence_grounding_score=0.99,
        ),
        "LEAD-INT-01": AgentProfile(
            agent_id="LEAD-INT-01",
            role=AgentRole.INTEGRATION_MONITORING_LEAD,
            level=AgentHierarchyLevel.LEVEL_2_TEAM_LEAD,
            display_name="Rohit Verma (Integration & Telemetry Lead)",
            department="Enterprise Telemetry & Connectors",
            supervisor_role=AgentRole.TEAM_DIRECTOR,
            responsibilities=[
                "Review connector behavior, log ingestion, and alert delivery",
                "Detect missing security-event fields and disconnected integrations",
                "Ensure missing data is NEVER interpreted as evidence of security",
                "Verify timestamp fidelity and event deduplication",
            ],
            benchmarked_precision=0.95,
            benchmarked_recall=0.96,
            evidence_grounding_score=0.96,
        ),
        "LEAD-CMP-01": AgentProfile(
            agent_id="LEAD-CMP-01",
            role=AgentRole.COMPLIANCE_AUDIT_LEAD,
            level=AgentHierarchyLevel.LEVEL_2_TEAM_LEAD,
            display_name="Meera Iyer (Compliance & Audit Lead)",
            department="Regulatory Architecture & Audit",
            supervisor_role=AgentRole.TEAM_DIRECTOR,
            responsibilities=[
                "Review applicable regulatory circulars (RBI, CERT-In, DPDP)",
                "Cross-check exact clauses, circular numbers, and statutory deadlines",
                "Distinguish verified requirements from interpretations",
                "Ensure verification report maintains complete audit proof",
            ],
            benchmarked_precision=0.99,
            benchmarked_recall=0.98,
            evidence_grounding_score=0.99,
        ),

        # Level 3 Specialists
        "SPEC-THREAT-01": AgentProfile(
            agent_id="SPEC-THREAT-01",
            role=AgentRole.THREAT_DETECTION_SPECIALIST,
            level=AgentHierarchyLevel.LEVEL_3_SPECIALIST,
            display_name="Kavita Pillai (Threat Detection Specialist)",
            department="Detection Engineering",
            supervisor_role=AgentRole.SECURITY_TESTING_LEAD,
            responsibilities=[
                "Evaluate whether product detects predefined malicious behaviors",
                "Compare expected threat events with observed telemetry",
                "Identify missed detections, detection latency, and coverage limits",
            ],
            benchmarked_precision=0.94,
            benchmarked_recall=0.93,
            evidence_grounding_score=0.95,
        ),
        "SPEC-FP-01": AgentProfile(
            agent_id="SPEC-FP-01",
            role=AgentRole.FALSE_POSITIVE_SPECIALIST,
            level=AgentHierarchyLevel.LEVEL_3_SPECIALIST,
            display_name="Devendra Joshi (False-Positive Specialist)",
            department="Signal Quality & Noise Analysis",
            supervisor_role=AgentRole.SECURITY_TESTING_LEAD,
            responsibilities=[
                "Review legitimate banking traffic incorrectly flagged as malicious",
                "Identify benign patterns causing alert storms and analyst fatigue",
                "Calculate false-positive rates under synthetic operational baselines",
            ],
            benchmarked_precision=0.93,
            benchmarked_recall=0.91,
            evidence_grounding_score=0.94,
        ),
        "SPEC-ADV-01": AgentProfile(
            agent_id="SPEC-ADV-01",
            role=AgentRole.ADVERSARIAL_TEST_DESIGNER,
            level=AgentHierarchyLevel.LEVEL_3_SPECIALIST,
            display_name="Alex Chen (Adversarial Test Designer)",
            department="Synthetic Threat Emulation",
            supervisor_role=AgentRole.SECURITY_TESTING_LEAD,
            responsibilities=[
                "Design controlled test cases covering relevant threat scenarios",
                "Use safe, isolated simulations and synthetic events",
                "Identify blind spots without executing destructive payloads",
            ],
            benchmarked_precision=0.96,
            benchmarked_recall=0.97,
            evidence_grounding_score=0.97,
        ),
        "SPEC-CFG-01": AgentProfile(
            agent_id="SPEC-CFG-01",
            role=AgentRole.SECURITY_CONFIG_SPECIALIST,
            level=AgentHierarchyLevel.LEVEL_3_SPECIALIST,
            display_name="Pooja Kulkarni (Security Configuration Specialist)",
            department="Posture & Policy Enforcement",
            supervisor_role=AgentRole.SECURITY_TESTING_LEAD,
            responsibilities=[
                "Review configuration weaknesses, unsafe defaults, and access policies",
                "Distinguish configuration misconfigurations from product defects",
                "Validate policy enforcement under strict least-privilege rules",
            ],
            benchmarked_precision=0.95,
            benchmarked_recall=0.92,
            evidence_grounding_score=0.96,
        ),
        "SPEC-TEL-01": AgentProfile(
            agent_id="SPEC-TEL-01",
            role=AgentRole.TELEMETRY_INTEGRATION_SPECIALIST,
            level=AgentHierarchyLevel.LEVEL_3_SPECIALIST,
            display_name="Sanjay Nair (Telemetry & Ingestion Specialist)",
            department="Enterprise Telemetry & Connectors",
            supervisor_role=AgentRole.INTEGRATION_MONITORING_LEAD,
            responsibilities=[
                "Test event ingestion, field normalization, and timestamp integrity",
                "Identify dropped, stale, duplicated, or malformed events",
                "Verify alert delivery pipelines across SIEM and EDR connectors",
            ],
            benchmarked_precision=0.95,
            benchmarked_recall=0.96,
            evidence_grounding_score=0.96,
        ),
        "SPEC-REL-01": AgentProfile(
            agent_id="SPEC-REL-01",
            role=AgentRole.RELIABILITY_REPRODUCIBILITY_SPECIALIST,
            level=AgentHierarchyLevel.LEVEL_3_SPECIALIST,
            display_name="Elena Rostov (Reliability & Reproducibility Specialist)",
            department="Quality Assurance & Benchmarking",
            supervisor_role=AgentRole.EVIDENCE_ACCURACY_LEAD,
            responsibilities=[
                "Repeat selected test cases to verify deterministic consistency",
                "Investigate nondeterministic outcomes and race conditions",
                "Record exact environmental parameters and product builds",
            ],
            benchmarked_precision=0.98,
            benchmarked_recall=0.96,
            evidence_grounding_score=0.98,
        ),
        "SPEC-INTEL-01": AgentProfile(
            agent_id="SPEC-INTEL-01",
            role=AgentRole.THREAT_INTEL_SPECIALIST,
            level=AgentHierarchyLevel.LEVEL_3_SPECIALIST,
            display_name="Tariq Mansoor (Threat Intelligence Specialist)",
            department="Threat Research & Taxonomies",
            supervisor_role=AgentRole.COMPLIANCE_AUDIT_LEAD,
            responsibilities=[
                "Map test scenarios to MITRE ATT&CK techniques and NIST CSF categories",
                "Record primary source URLs, publication dates, and citations",
                "Strictly avoid fabricating threat intelligence or advisory bulletins",
            ],
            benchmarked_precision=0.97,
            benchmarked_recall=0.95,
            evidence_grounding_score=0.98,
        ),
        "SPEC-AUDIT-01": AgentProfile(
            agent_id="SPEC-AUDIT-01",
            role=AgentRole.INDEPENDENT_EVIDENCE_AUDITOR,
            level=AgentHierarchyLevel.LEVEL_3_SPECIALIST,
            display_name="Deepak Menon (Independent Evidence Auditor)",
            department="Evidence Forensics & Traceability",
            supervisor_role=AgentRole.EVIDENCE_ACCURACY_LEAD,
            responsibilities=[
                "Examine raw observations rather than trusting agent summaries",
                "Challenge unsupported assertions and identify contradictions",
                "Validate that claimed results strictly align with raw logs",
                "Reject submissions lacking cryptographic provenance or trace",
            ],
            benchmarked_precision=0.99,
            benchmarked_recall=0.98,
            evidence_grounding_score=0.99,
        ),

        # Level 4 HR
        "HR-COORD-01": AgentProfile(
            agent_id="HR-COORD-01",
            role=AgentRole.HR_WORKFORCE_COORDINATOR,
            level=AgentHierarchyLevel.LEVEL_4_HR_COORDINATOR,
            display_name="Staff Coordinator Alpha (Workforce & Review Auditor)",
            department="HR & Workforce Management",
            supervisor_role=AgentRole.TEAM_DIRECTOR,
            responsibilities=[
                "Maintain agent registry, capability matrix, and specialization",
                "Track quality metrics and detect stalled/unproductive review loops",
                "Recommend specialist reassignment upon repeated unsupported claims",
                "Never determine security verdicts by speed, popularity, or confidence",
            ],
            benchmarked_precision=0.99,
            benchmarked_recall=0.99,
            evidence_grounding_score=0.99,
        ),

        # Level 5 QA
        "QA-RED-01": AgentProfile(
            agent_id="QA-RED-01",
            role=AgentRole.INDEPENDENT_QA_LEAD,
            level=AgentHierarchyLevel.LEVEL_5_INDEPENDENT_QA,
            display_name="Maya Sundaram (Independent Red Team QA Lead)",
            department="Independent Quality Assurance & Red Team",
            supervisor_role=None,  # Reports independently to Verdict Committee
            responsibilities=[
                "Attempt to disprove proposed conclusions with counterexamples",
                "Examine false negatives, false positives, and missing test cases",
                "Reject incomplete reports and send them back for mandatory revision",
                "Ensure absence of evidence is NEVER confused with evidence of absence",
                "Maintain direct read access to raw test logs, not summaries",
            ],
            benchmarked_precision=0.99,
            benchmarked_recall=0.98,
            evidence_grounding_score=0.99,
        ),

        # Level 6 Final Verdict Engine
        "ENG-VERDICT-01": AgentProfile(
            agent_id="ENG-VERDICT-01",
            role=AgentRole.DECISION_ENGINE,
            level=AgentHierarchyLevel.LEVEL_6_VERDICT_COMMITTEE,
            display_name="Deterministic Decision Engine (Deterministic Verdict Logic)",
            department="Final Verdict Committee",
            supervisor_role=None,
            responsibilities=[
                "Execute deterministic rule-based evaluation of all test criteria",
                "Ensure mandatory failure conditions block PASS unconditionally",
                "Require unanimous committee sign-offs before report publication",
                "A language model must NEVER independently issue a security verdict",
            ],
            benchmarked_precision=1.00,
            benchmarked_recall=1.00,
            evidence_grounding_score=1.00,
        ),
    }
