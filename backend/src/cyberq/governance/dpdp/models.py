"""Pydantic data models for DPDP Rule 7 Personal Data Breach Notification reports."""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


class AudienceType(StrEnum):
    """Target audience for DPDP breach notification report."""

    INTERNAL = "internal"  # Internal CISO, DPO, Board review (Sections 1–10 + checklist)
    DPB = "dpb"  # Data Protection Board official filing (Sections 1–6 only)


class DpdpBreachReportData(BaseModel):
    """Normalized data payload binding to the DPDP Rule 7 report template."""

    # Core Identifiers & Metadata
    incident_id: str = Field(..., description="Unique incident identifier")
    certin_id: str = Field(..., description="Linked CERT-In filing identifier")
    target_audience: AudienceType = Field(default=AudienceType.INTERNAL)
    include_internal_sections: bool = Field(default=True)
    submission_time_ist: str = Field(default="[DD-MM-YYYY HH:MM]")

    # 1. Data Fiduciary Details
    bank_legal_name: str = Field(default="Apex Bank of India Ltd.")
    dpb_portal_id: str = Field(default="DPB-FID-2026-IN-00891")
    dpo_details: str = Field(default="Kavita Deshmukh, Data Protection Officer, dpo@apexbank.in, +91-22-67890123")
    board_accountability: str = Field(default="Risk Management Committee of the Board (RMCB) & CISO")
    breach_contact_24x7: str = Field(default="SOC Command Desk, soc@apexbank.in, +91-22-67890999")
    sdf_status: str = Field(default="Yes (Scheduled Commercial Bank)")

    # 2. Breach Identification (DPDP Lens)
    became_aware_ist: str = Field(default="[DD-MM-YYYY HH:MM]")
    deadline_72h_ist: str = Field(default="[DD-MM-YYYY HH:MM]")
    breach_nature: str = Field(
        default="Unauthorised access to ISO-8583 message broker; potential accidental disclosure of customer telemetry"
    )
    affected_systems: str = Field(default="Core Banking Switch Gateway; ISO-8583 Message Broker")
    personal_data_affected: str = Field(
        default="Customer account numbers, masked card tokens, transaction payloads (scrubbed at ingestion boundary)"
    )
    data_principal_categories: str = Field(default="Commercial retail and corporate banking customers")
    data_principal_count: str = Field(default="Under continuous forensic assessment (provisional: ~1,250 accounts)")
    children_data_involved: str = Field(default="No (corporate and adult retail accounts only)")
    initial_access_vector: str = Field(default="Provisional: Compromised API gateway access token / credential stuffing")
    likely_consequences: str = Field(
        default="Provisional risk of phishing and credential spraying; transactional integrity preserved"
    )
    ai_agent_involvement: str = Field(default="No autonomous agent lateral escalation detected")
    ai_advisory_ref: str = Field(default="CERT-In Advisory 2026/A-09 (Agentic AI Resilience)")

    # Three impacts kept separate
    fund_loss_status: str = Field(default="₹0 confirmed (Reconciled with payment switch settlement reports)")
    personal_data_impact_status: str = Field(default="Under assessment (PII scrubbing active at ingestion boundary)")
    transaction_integrity_risk: str = Field(default="Zero tampering detected; message hash parity verified")

    # 3. Initial Intimation to DPB (Without Delay)
    intimation_nature: str = Field(default="Suspicious credential usage on internal message broker")
    intimation_extent: str = Field(default="Isolated to Switch Gateway node SG-04; data categories under assessment")
    occurred_time_ist: str = Field(default="[DD-MM-YYYY HH:MM]")
    breach_location: str = Field(default="Mumbai Primary On-Premise Data Centre (MeitY empaneled, India residency confirmed)")
    provisional_impact: str = Field(default="Contained access attempt; no customer fund exfiltration")
    containment_status: str = Field(default="Completed (Network segment isolated and credentials rotated)")
    forensic_clearance_status: str = Field(default="In progress (Empanelled CERT-In auditor conducting disk forensics)")

    # 4. Detailed Report to DPB (72-Hour Requirement)
    detailed_updated_facts: str = Field(default="Boundary controls held; all logs exported to WORM audit ledger")
    detailed_circumstances: str = Field(default="API credential leakage traced to third-party vendor test client script")
    detailed_remedial_measures: str = Field(default="Gateway token revoked, firewall rules updated, dual-control enforced")
    breach_causers: str = Field(default="Under forensic investigation; no malicious insider collusion established")
    principal_notices_sent: str = Field(default="Decision pending CISO & DPO joint determination per Section 5")
    api_inventory_status: str = Field(default="Completed; all dormant test endpoints terminated")
    credential_rotation_status: str = Field(default="100% of privileged and service tokens rotated")
    mfa_enforcement_status: str = Field(default="Enforced with hardware FIDO2 tokens on all administrative interfaces")
    least_privilege_status: str = Field(default="IAM roles restricted strictly to minimal required RBAC scopes")
    api_monitoring_status: str = Field(default="Real-time rate-limiting and burst anomaly detection enabled")

    # 5. Notification to Affected Data Principals
    principal_notification_decision: str = Field(default="not_yet")  # notify, not_yet, no_breach
    notification_decision_reason: str = Field(default="Forensic data reconciliation ongoing; no verified PII exfiltration")
    ciso_approver_name: str = Field(default="Maya Sundaram (CISO)")
    ciso_decision_datetime: str = Field(default="[DD-MM-YYYY HH:MM]")
    principal_notice_channel: str = Field(default="Registered email and secure net banking inbox alert")
    principal_notice_target_time: str = Field(default="Within 24 hours of forensic confirmation if breach is established")
    principal_notice_draft_text: str = Field(
        default="Dear Customer, we detected an unauthorized attempt on our payment switch. Your account and funds are completely safe. As a precaution, please ensure multi-factor authentication is active."
    )

    # 6. Regulatory Interplay Note
    certin_filing_status: str = Field(default="Filed within 6 hours (Annexure I verified)")
    dpdp_filing_status: str = Field(default="Initial intimation completed; 72-hour detailed report draft generated")
    rbi_filing_status: str = Field(default="DAKSH incident intimation submitted")

    # Sections 7–10 Internal Metadata & Sign-offs
    prepared_by_name: str = Field(default="Arjun Rao (Senior Lead Incident Analyst)")
    prepared_at_ist: str = Field(default="[DD-MM-YYYY HH:MM]")
    validated_by_name: str = Field(default="Vikram Malhotra (Lead Regulatory Model Validator)")
    validated_at_ist: str = Field(default="[DD-MM-YYYY HH:MM]")
    approved_by_name: str = Field(default="Maya Sundaram (Chief Information Security Officer)")
    approved_at_ist: str = Field(default="[DD-MM-YYYY HH:MM]")

    # Cryptographic Sealing
    verification_code: str = Field(default="", description="Statutory Verification Code e.g. CQ-DPDP-...")
    packet_hash: str = Field(default="", description="SHA-256 hash of generated document")


class EmergencyTriggerRequest(BaseModel):
    """Payload for manual emergency DPDP report generation trigger."""

    reason: str | None = Field(default=None, description="Operational justification for manual emergency generation")
    target_audience: AudienceType = Field(
        default=AudienceType.INTERNAL, description="Audience filter: 'internal' or 'dpb'"
    )


class EmergencyTriggerResponse(BaseModel):
    """API response acknowledging emergency trigger execution."""

    status: str = "triggered"
    incident_id: str
    incident_number: str
    trigger_type: str = "emergency_manual"
    triggered_by: str
    triggered_at: str
    verification_code: str
    packet_hash: str
    timer_status: dict[str, Any]
