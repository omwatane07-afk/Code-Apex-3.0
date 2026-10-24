"""Data Models, Schemas, and Canonical Evidence Structures for Verification Team."""

import hashlib
import json
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import (
    JSON,
    Boolean,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from cyberq.core.database import Base, UTCDateTime


class VerificationVerdict(StrEnum):
    PASS = "PASS"  # nosec B105: verification verdict outcome, not a credential
    CONDITIONAL = "CONDITIONAL"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_TESTED = "NOT_TESTED"
    PENDING = "PENDING"


class ReviewLoopPhase(StrEnum):
    PHASE_1_PLAN = "Phase 1: Plan"
    PHASE_2_DELEGATE = "Phase 2: Delegate"
    PHASE_3_INVESTIGATE = "Phase 3: Investigate"
    PHASE_4_SUBMIT = "Phase 4: Submit"
    PHASE_5_LEAD_REVIEW = "Phase 5: Team-Lead Review"
    PHASE_6_CROSS_EXAM = "Phase 6: Cross-Examination"
    PHASE_7_DISAGREEMENT = "Phase 7: Disagreement Resolution"
    PHASE_8_REVISION = "Phase 8: Revision"
    PHASE_9_REGRESSION = "Phase 9: Regression Check"
    PHASE_10_QUALITY_GATE = "Phase 10: Quality Gate"
    PHASE_11_FINAL_APPROVAL = "Phase 11: Final Approval"


class WorkPackageStatus(StrEnum):
    ASSIGNED = "ASSIGNED"
    IN_PROGRESS = "IN_PROGRESS"
    SUBMITTED = "SUBMITTED"
    UNDER_LEAD_REVIEW = "UNDER_LEAD_REVIEW"
    REVISION_REQUESTED = "REVISION_REQUESTED"
    CHALLENGED_BY_QA = "CHALLENGED_BY_QA"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class EvidenceValidationStatus(StrEnum):
    VERIFIED = "VERIFIED"
    CONTRADICTED = "CONTRADICTED"
    UNVERIFIED = "UNVERIFIED"
    TAMPERED = "TAMPERED"


# ============================================================================
# SQLAlchemy ORM Models
# ============================================================================


class VerificationInvestigationModel(Base):
    """An end-to-end evaluation investigation of a target banking security product."""

    __tablename__ = "verification_investigations"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: f"INV-{uuid4().hex[:8].upper()}")
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    target_product_name: Mapped[str] = mapped_column(String(128), nullable=False)
    target_product_version: Mapped[str] = mapped_column(String(64), nullable=False)
    environment_profile: Mapped[str] = mapped_column(String(255), nullable=False)
    current_phase: Mapped[str] = mapped_column(String(64), nullable=False, default=ReviewLoopPhase.PHASE_1_PLAN.value)
    iteration_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    max_iterations: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    budget_limit: Mapped[int] = mapped_column(Integer, nullable=False, default=50)
    budget_used: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    final_verdict: Mapped[str] = mapped_column(String(32), nullable=False, default=VerificationVerdict.PENDING.value)
    deterministic_rules_triggered: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    summary: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=lambda: datetime.now(UTC))
    completed_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    # Relationships
    work_packages: Mapped[list["VerificationWorkPackageModel"]] = relationship(
        "VerificationWorkPackageModel", back_populates="investigation", cascade="all, delete-orphan"
    )
    evidence_records: Mapped[list["CanonicalEvidenceModel"]] = relationship(
        "CanonicalEvidenceModel", back_populates="investigation", cascade="all, delete-orphan"
    )
    disagreements: Mapped[list["DisagreementRecordModel"]] = relationship(
        "DisagreementRecordModel", back_populates="investigation", cascade="all, delete-orphan"
    )


class VerificationWorkPackageModel(Base):
    """Specific delegated task package assigned by Leads to Specialists."""

    __tablename__ = "verification_work_packages"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: f"WP-{uuid4().hex[:8].upper()}")
    investigation_id: Mapped[str] = mapped_column(String(64), ForeignKey("verification_investigations.id"), nullable=False)
    assigned_lead_role: Mapped[str] = mapped_column(String(64), nullable=False)
    assigned_agent_id: Mapped[str] = mapped_column(String(64), nullable=False)
    assigned_agent_role: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    objective: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(64), nullable=False, default=WorkPackageStatus.ASSIGNED.value)
    review_cycle: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=lambda: datetime.now(UTC))

    investigation: Mapped[VerificationInvestigationModel] = relationship(
        "VerificationInvestigationModel", back_populates="work_packages"
    )
    findings: Mapped[list["VerificationFindingModel"]] = relationship(
        "VerificationFindingModel", back_populates="work_package", cascade="all, delete-orphan"
    )


class VerificationFindingModel(Base):
    """Structured submission from a specialist containing claims, observations, and limits."""

    __tablename__ = "verification_findings"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: f"FND-{uuid4().hex[:8].upper()}")
    work_package_id: Mapped[str] = mapped_column(String(64), ForeignKey("verification_work_packages.id"), nullable=False)
    investigation_id: Mapped[str] = mapped_column(String(64), nullable=False)
    agent_id: Mapped[str] = mapped_column(String(64), nullable=False)
    agent_role: Mapped[str] = mapped_column(String(64), nullable=False)
    claim: Mapped[str] = mapped_column(Text, nullable=False)
    methodology: Mapped[str] = mapped_column(Text, nullable=False)
    observed_result: Mapped[str] = mapped_column(Text, nullable=False)
    expected_result: Mapped[str] = mapped_column(Text, nullable=False)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False, default=0.5)
    uncertainty_factors: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    limitations: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    recommended_action: Mapped[str] = mapped_column(Text, nullable=False)
    lead_review_status: Mapped[str] = mapped_column(String(64), nullable=False, default="PENDING")
    lead_feedback: Mapped[str | None] = mapped_column(Text, nullable=True)
    qa_challenge_status: Mapped[str] = mapped_column(String(64), nullable=False, default="UNCONTESTED")
    qa_critique: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_mandatory_failure: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=lambda: datetime.now(UTC))

    work_package: Mapped[VerificationWorkPackageModel] = relationship(
        "VerificationWorkPackageModel", back_populates="findings"
    )


class CanonicalEvidenceModel(Base):
    """Canonical Evidence Record shared across all agents with SHA-256 integrity hash."""

    __tablename__ = "canonical_evidence_records"

    evidence_id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: f"EVD-{uuid4().hex[:8].upper()}")
    investigation_id: Mapped[str] = mapped_column(String(64), ForeignKey("verification_investigations.id"), nullable=False)
    finding_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    task_id: Mapped[str] = mapped_column(String(64), nullable=False)
    claim: Mapped[str] = mapped_column(Text, nullable=False)
    product_name: Mapped[str] = mapped_column(String(128), nullable=False)
    product_version: Mapped[str] = mapped_column(String(64), nullable=False)
    test_environment: Mapped[str] = mapped_column(String(255), nullable=False)
    source_or_test_case: Mapped[str] = mapped_column(String(128), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(UTCDateTime, nullable=False, default=lambda: datetime.now(UTC))
    raw_observation: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    sanitized_event: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    expected_behavior: Mapped[str] = mapped_column(Text, nullable=False)
    actual_behavior: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_provenance: Mapped[str] = mapped_column(String(255), nullable=False)
    validation_status: Mapped[str] = mapped_column(String(64), nullable=False, default=EvidenceValidationStatus.UNVERIFIED.value)
    related_findings: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)
    reviewer_comments: Mapped[list[dict[str, Any]]] = mapped_column(JSON, nullable=False, default=list)
    tamper_hash: Mapped[str] = mapped_column(String(64), nullable=False)

    investigation: Mapped[VerificationInvestigationModel] = relationship(
        "VerificationInvestigationModel", back_populates="evidence_records"
    )

    @staticmethod
    def calculate_hash(payload: dict[str, Any]) -> str:
        serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        return hashlib.sha256(serialized).hexdigest()


class DisagreementRecordModel(Base):
    """Preserves conflicting findings between agents without majority voting."""

    __tablename__ = "disagreement_records"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, default=lambda: f"DISAGREE-{uuid4().hex[:8].upper()}")
    investigation_id: Mapped[str] = mapped_column(String(64), ForeignKey("verification_investigations.id"), nullable=False)
    disputed_claim: Mapped[str] = mapped_column(Text, nullable=False)
    agent_a_id: Mapped[str] = mapped_column(String(64), nullable=False)
    agent_a_role: Mapped[str] = mapped_column(String(64), nullable=False)
    agent_a_position: Mapped[str] = mapped_column(Text, nullable=False)
    agent_a_evidence_id: Mapped[str] = mapped_column(String(64), nullable=False)
    agent_b_id: Mapped[str] = mapped_column(String(64), nullable=False)
    agent_b_role: Mapped[str] = mapped_column(String(64), nullable=False)
    agent_b_position: Mapped[str] = mapped_column(Text, nullable=False)
    agent_b_evidence_id: Mapped[str] = mapped_column(String(64), nullable=False)
    resolution_method: Mapped[str] = mapped_column(String(128), nullable=False)
    resolution_outcome: Mapped[str | None] = mapped_column(Text, nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(UTCDateTime, nullable=True)

    investigation: Mapped[VerificationInvestigationModel] = relationship(
        "VerificationInvestigationModel", back_populates="disagreements"
    )


# ============================================================================
# Pydantic Request / Response Schemas
# ============================================================================


class InvestigationCreateRequest(BaseModel):
    title: str = Field(..., min_length=3, max_length=255)
    target_product_name: str = Field(..., min_length=2, max_length=128)
    target_product_version: str = Field(..., min_length=1, max_length=64)
    environment_profile: str = Field("Banking Core Testbed (Isolated VPC, Air-Gapped)", max_length=255)
    max_iterations: int = Field(5, ge=1, le=10)
    budget_limit: int = Field(50, ge=5, le=200)


class FindingSubmissionRequest(BaseModel):
    work_package_id: str
    claim: str
    methodology: str
    observed_result: str
    expected_result: str
    confidence_score: float = Field(0.5, ge=0.0, le=1.0)
    uncertainty_factors: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    recommended_action: str
    evidence_payload: dict[str, Any]
    source_test_case: str
    is_mandatory_failure: bool = False


class LeadReviewActionRequest(BaseModel):
    finding_id: str
    approve: bool
    feedback: str


class QAChallengeActionRequest(BaseModel):
    finding_id: str
    challenge: bool
    counterexample_evidence_id: str | None = None
    critique: str


class CanonicalEvidenceSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    evidence_id: str
    investigation_id: str
    finding_id: str | None
    task_id: str
    claim: str
    product_name: str
    product_version: str
    test_environment: str
    source_or_test_case: str
    timestamp: datetime
    raw_observation: dict[str, Any]
    sanitized_event: dict[str, Any]
    expected_behavior: str
    actual_behavior: str
    evidence_provenance: str
    validation_status: str
    related_findings: list[str]
    reviewer_comments: list[dict[str, Any]]
    tamper_hash: str


class InvestigationDetailResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    title: str
    target_product_name: str
    target_product_version: str
    environment_profile: str
    current_phase: str
    iteration_count: int
    max_iterations: int
    budget_limit: int
    budget_used: int
    final_verdict: str
    deterministic_rules_triggered: list[dict[str, Any]]
    summary: str
    created_at: datetime
    completed_at: datetime | None
    work_packages_count: int
    evidence_count: int
    disagreements_count: int


# ============================================================================
# LLM Multi-Agent Output Schemas (Qwen 2.5 Coder Local Integration)
# ============================================================================


class TriageSpecialistOutput(BaseModel):
    model_config = ConfigDict(extra="ignore")

    agent: str = "TriageSpecialist"
    severity: str = Field(default="high", description="Normalized severity: critical, high, medium, low")
    tactic: str = Field(default="Unknown", description="MITRE ATT&CK tactic category")
    technique: str = Field(default="Unknown", description="MITRE ATT&CK technique code/name")
    affected_critical_systems: list[str] = Field(default_factory=list)
    triage_disposition: str = Field(
        default="ESCALATE_TO_INCIDENT",
        description="ESCALATE_TO_INCIDENT, SUPPRESS_BENIGN, or REQUIRES_DEEP_INSPECTION",
    )
    summary: str = Field(default="", description="Executive triage summary")
    confidence: float = Field(default=0.90, ge=0.0, le=1.0)


class RegulatoryClauseMatcherOutput(BaseModel):
    model_config = ConfigDict(extra="ignore")

    agent: str = "RegulatoryClauseMatcher"
    is_reportable: bool = Field(default=True, description="Whether alert triggers mandatory regulatory reporting")
    primary_statute: str = Field(default="CERT-In Directions 2022", description="Primary statutory framework")
    deadline_hours: int = Field(default=6, description="Statutory disclosure deadline window in hours")
    matched_clauses: list[str] = Field(default_factory=list)
    reasoning: str = Field(default="", description="Statutory reasoning for applicability")
    confidence: float = Field(default=0.95, ge=0.0, le=1.0)


class ToolPassportInspectorOutput(BaseModel):
    model_config = ConfigDict(extra="ignore")

    agent: str = "ToolPassportInspector"
    tool_id: str = Field(default="tool-generic", description="Identifier of originating security tool")
    trust_status: str = Field(default="VERIFIED", description="VERIFIED, DEGRADED, or UNVERIFIED")
    vapt_valid: bool = Field(default=True, description="Whether VAPT certification is valid under RBI Para 90")
    is_telemetry_unverified: bool = Field(default=False, description="Flag indicating degraded telemetry")
    observations: list[str] = Field(default_factory=list)
    risk_level: str = Field(default="low", description="Operational risk level")


class MultiAgentTriageBundle(BaseModel):
    model_config = ConfigDict(extra="ignore")

    investigation_id: str
    event_id: str
    source_tool: str
    model_used: str = "qwen2.5-coder"
    triage: TriageSpecialistOutput
    regulatory: RegulatoryClauseMatcherOutput
    passport: ToolPassportInspectorOutput
    final_verdict: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))
