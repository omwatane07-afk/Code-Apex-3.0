"""Statutory Filing Packet Generators for CERT-In, RBI DAKSH, and DPDP."""

from __future__ import annotations

from datetime import datetime
from typing import Any


def generate_certin_packet(
    incident_number: str,
    title: str,
    summary: str,
    severity: str,
    occurred_at: datetime,
    organization_name: str = "Commercial Bank of India Ltd.",
    contact_email: str = "ciso-office@bank.internal",
    compromised_systems: list[str] | None = None,
    cve_ids: list[str] | None = None,
    containment_actions: str = "Isolated compromised segments and revoked affected service tokens.",
) -> dict[str, Any]:
    """Generates CERT-In Initial/Follow-up Statutory Intimation Packet (6h from noticed)."""
    return {
        "regulator": "CERT-In",
        "instrument": "CERT-In Directions (28 April 2022) Section 70B",
        "form_type": "Initial Incident Intimation (Annexure I)",
        "statutory_deadline_hours": 6,
        "reporting_entity": {
            "name": organization_name,
            "entity_category": "Banking / Critical Financial Infrastructure",
            "contact_email": contact_email,
        },
        "incident_details": {
            "internal_incident_id": incident_number,
            "statutory_trigger": "noticed",
            "noticed_at_utc": occurred_at.isoformat(),
            "incident_classification": "Malicious code attacks / unauthorized access to critical systems",
            "severity_level": severity.upper(),
            "affected_assets": compromised_systems or ["Core Banking Gateway / RTGS Interface"],
            "cve_references": cve_ids or [],
            "executive_summary": summary,
        },
        "technical_assessment": {
            "indicators_of_compromise": ["Suspicious outbound TLS connections", "Unauthorized process injection"],
            "containment_actions_taken": containment_actions,
            "business_impact": f"Assessed as {severity.upper()} severity with zero customer account fund leakage",
        },
    }


def generate_rbi_daksh_packet(
    incident_number: str,
    title: str,
    summary: str,
    severity: str,
    occurred_at: datetime,
    bank_license_code: str = "RBI-CB-4019",
    bank_name: str = "Commercial Bank of India Ltd.",
    critical_cbs_affected: bool = False,
    estimated_loss_lakhs: str = "0.00",
) -> dict[str, Any]:
    """Generates RBI DAKSH Platform Statutory Incident Report (6h from detected, Para 182)."""
    return {
        "regulator": "RBI",
        "instrument": "RBI Cybersecurity Framework Directions 2026 (Para 182)",
        "platform": "DAKSH (https://daksh.rbi.org.in)",
        "statutory_deadline_hours": 6,
        "bank_metadata": {
            "bank_name": bank_name,
            "bank_license_code": bank_license_code,
            "entity_type": "Commercial Scheduled Bank",
        },
        "supervisory_incident_data": {
            "incident_reference": incident_number,
            "statutory_trigger": "detected",
            "detected_at_utc": occurred_at.isoformat(),
            "category": "Cyber Attack / Operational Disruption",
            "severity": severity.upper(),
            "cbs_rtgs_swift_impacted": critical_cbs_affected,
            "estimated_financial_loss_inr_lakhs": estimated_loss_lakhs,
            "customer_service_disruption": False,
            "root_cause_preliminary": summary,
        },
        "assurance_and_mitigation": {
            "immediate_corrective_action": "Port isolation and administrative credential rotation completed.",
            "soc_monitoring_status": "Heightened 24/7 telemetry watch active.",
            "reporting_officer": "Chief Information Security Officer (CISO)",
        },
    }


def generate_dpdp_packet(
    incident_number: str,
    summary: str,
    occurred_at: datetime,
    fiduciary_name: str = "Commercial Bank of India Ltd.",
    dpo_email: str = "dpo@bank.internal",
    estimated_impacted_principals: int = 0,
) -> dict[str, Any]:
    """Generates DPDP Board Breach Intimation Packet (72h from aware, Rule 7, Strictly Aggregate-Only)."""
    return {
        "regulator": "DPDP",
        "instrument": "Digital Personal Data Protection Act & Rules 2025 (Rule 7)",
        "target_authority": "Data Protection Board of India",
        "statutory_deadline_hours": 72,
        "data_fiduciary": {
            "name": fiduciary_name,
            "dpo_contact": dpo_email,
        },
        "breach_assessment_aggregate_only": {
            "incident_reference": incident_number,
            "statutory_trigger": "aware",
            "aware_at_utc": occurred_at.isoformat(),
            "nature_of_breach": "Confidentiality / Integrity Security Incident",
            "estimated_impacted_principals_count": estimated_impacted_principals,
            "customer_pii_ingested": False,  # Strict banking invariant: zero PII
            "remedial_measures": "Security controls reinforced; no customer credentials leaked.",
        },
    }
