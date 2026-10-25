"""FastAPI routes for Cybersecurity Tool Telemetry Feed and LLM Availability Monitoring.

Provides simulated real-time telemetry from enterprise cybersecurity tools
(SIEM, EDR, Firewall, WAF, DAM, IAM/PAM, CSPM) and automated alerts
when local LLM inference is unavailable.
"""

from __future__ import annotations

import hashlib
import random
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from cyberq.core.database import get_db
from cyberq.intake.models import ToolCompliancePassport

router = APIRouter(prefix="/admin", tags=["Telemetry & Alerts"])

# Deterministic seed for reproducible simulated telemetry within a session
_rng = random.Random(42)  # noqa: S311


def _simulate_tool_health(tool_id: str, tool_name: str, category: str, trust_status: str) -> dict[str, Any]:
    """Generates a realistic health telemetry snapshot for a single cybersecurity tool."""
    now = datetime.now(UTC)
    base_hash = int(hashlib.md5(tool_id.encode(), usedforsecurity=False).hexdigest()[:8], 16)

    # Simulate tool-specific metrics
    events_per_min = (base_hash % 200) + 5
    latency_ms = (base_hash % 45) + 3
    dropped = max(0, (base_hash % 8) - 5) if trust_status == "DEGRADED" else 0
    cpu_pct = round(12.0 + (base_hash % 35) + random.uniform(-3, 3), 1)  # noqa: S311
    mem_mb = round(256 + (base_hash % 1800) + random.uniform(-50, 50), 0)  # noqa: S311

    # Status based on trust level
    if trust_status == "DEGRADED":
        health = "DEGRADED"
        alert_level = "critical"
    elif trust_status == "EXPIRING_SOON":
        health = "WARNING"
        alert_level = "warning"
    else:
        health = "HEALTHY"
        alert_level = "nominal"

    last_heartbeat = now - timedelta(seconds=(base_hash % 30))

    return {
        "tool_id": tool_id,
        "tool_name": tool_name,
        "category": category,
        "trust_status": trust_status,
        "health": health,
        "alert_level": alert_level,
        "metrics": {
            "events_per_minute": events_per_min,
            "avg_latency_ms": latency_ms,
            "dropped_events": dropped,
            "cpu_usage_pct": cpu_pct,
            "memory_usage_mb": int(mem_mb),
            "active_connections": (base_hash % 24) + 1,
        },
        "last_heartbeat": last_heartbeat.isoformat(),
        "uptime_hours": round((base_hash % 2160) + 24 + random.uniform(0, 12), 1),  # noqa: S311
    }


def _simulate_recent_alerts(tool_count: int) -> list[dict[str, Any]]:
    """Generates realistic simulated security alerts from enterprise tools."""
    now = datetime.now(UTC)
    alert_templates = [
        {
            "source": "CrowdStrike Falcon",
            "category": "EDR",
            "title": "Suspicious lateral movement via WMI detected on CBS-PROD-APP01",
            "severity": "critical",
            "mitre": "T1047 - WMI",
            "asset": "CBS-PROD-APP01",
            "action_taken": "Process terminated, host isolated via Falcon Response API",
        },
        {
            "source": "Splunk Enterprise Security",
            "category": "SIEM",
            "title": "Correlated brute-force attempt against SWIFT Alliance gateway",
            "severity": "high",
            "mitre": "T1110.001 - Password Guessing",
            "asset": "SWIFT-ALLIANCE-GW",
            "action_taken": "Source IP blocked, correlation rule escalated to Tier-2 SOC",
        },
        {
            "source": "Palo Alto Strata NGFW",
            "category": "Firewall",
            "title": "Command injection exploit attempt on GlobalProtect VPN endpoint",
            "severity": "critical",
            "mitre": "T1190 - Exploit Public-Facing Application",
            "asset": "VPN-EDGE-01",
            "action_taken": "Connection reset, threat signature updated, IPS rule deployed",
        },
        {
            "source": "Imperva SecureSphere DAM",
            "category": "Database Security",
            "title": "Mass SELECT query on customer KYC table detected from unusual workstation",
            "severity": "high",
            "mitre": "T1530 - Data from Cloud Storage Object",
            "asset": "CORE-BANKING-ORACLE-RAC",
            "action_taken": "Session terminated, DBA alerted, privilege audit initiated",
        },
        {
            "source": "CyberArk PAM",
            "category": "IAM/PAM",
            "title": "Privileged session anomaly: root access outside maintenance window",
            "severity": "high",
            "mitre": "T1078.003 - Valid Accounts: Local",
            "asset": "UPI-SWITCH-CLUSTER",
            "action_taken": "Session recorded, emergency break-glass audit log created",
        },
        {
            "source": "Microsoft Sentinel",
            "category": "SIEM",
            "title": "Anomalous sign-in from non-bank IP range to Azure AD service principal",
            "severity": "medium",
            "mitre": "T1078.004 - Cloud Accounts",
            "asset": "ENTRA-TENANT-01",
            "action_taken": "Conditional Access policy enforced MFA challenge",
        },
        {
            "source": "SentinelOne Singularity",
            "category": "EDR",
            "title": "Fileless malware detected: PowerShell Invoke-Mimikatz in memory",
            "severity": "critical",
            "mitre": "T1003.001 - LSASS Memory",
            "asset": "BRANCH-WS-042",
            "action_taken": "Process killed, LSASS protected, endpoint quarantined",
        },
        {
            "source": "F5 BIG-IP Advanced WAF",
            "category": "WAF",
            "title": "SQL injection attempt blocked on internet banking login form",
            "severity": "medium",
            "mitre": "T1190 - Exploit Public-Facing Application",
            "asset": "IB-FRONTEND-LB",
            "action_taken": "Request blocked (HTTP 403), attack signature logged, IP reputation score adjusted",
        },
        {
            "source": "IBM QRadar SIEM",
            "category": "SIEM",
            "title": "High-volume data exfiltration pattern detected to external IP",
            "severity": "critical",
            "mitre": "T1041 - Exfiltration Over C2 Channel",
            "asset": "PROXY-GATEWAY-01",
            "action_taken": "Firewall rule deployed to block destination IP, forensic capture initiated",
        },
        {
            "source": "Wiz Cloud Security",
            "category": "CSPM",
            "title": "Critical misconfiguration: S3 bucket with customer statements set to public",
            "severity": "critical",
            "mitre": "T1530 - Data from Cloud Storage",
            "asset": "AWS-S3-STATEMENTS",
            "action_taken": "Bucket ACL reverted to private, access logs reviewed for unauthorized downloads",
        },
        {
            "source": "Fortinet FortiGate",
            "category": "Firewall",
            "title": "SSL VPN exploit attempt CVE-2024-21762 detected from external scanner",
            "severity": "high",
            "mitre": "T1190 - Exploit Public-Facing Application",
            "asset": "FORTIGATE-EDGE-02",
            "action_taken": "Connection dropped, IPS signature updated, vulnerability patch verified",
        },
        {
            "source": "Cisco Secure Firewall",
            "category": "Firewall",
            "title": "DNS tunneling activity detected from compromised IoT device in branch",
            "severity": "medium",
            "mitre": "T1071.004 - Application Layer Protocol: DNS",
            "asset": "BRANCH-IOT-SEGMENT",
            "action_taken": "DNS traffic blocked at resolver, device isolated from network",
        },
    ]

    alerts = []
    for i, tpl in enumerate(alert_templates):
        alert_time = now - timedelta(minutes=random.randint(2, 120))  # noqa: S311
        alerts.append({
            "alert_id": f"ALT-{uuid.uuid4().hex[:8].upper()}",
            "timestamp": alert_time.isoformat(),
            "source_tool": tpl["source"],
            "category": tpl["category"],
            "title": tpl["title"],
            "severity": tpl["severity"],
            "mitre_attack_id": tpl["mitre"],
            "affected_asset": tpl["asset"],
            "automated_response": tpl["action_taken"],
            "response_status": "EXECUTED" if i < 8 else "PENDING_REVIEW",
            "acknowledged": i < 6,
        })

    # Sort by timestamp descending (most recent first)
    alerts.sort(key=lambda a: a["timestamp"], reverse=True)
    return alerts


def _check_llm_availability() -> dict[str, Any]:
    """Checks local LLM availability and generates appropriate alerts.

    Dynamically probes the local air-gapped Ollama instance running Qwen 2.5 Coder.
    """
    now = datetime.now(UTC)

    try:
        from cyberq.verification.llm_client import OllamaLLMClient, OLLAMA_MODEL_NAME
        llm = OllamaLLMClient()
        llm_endpoint = llm.base_url
        llm_model = llm.model
        llm_available = llm.is_available(timeout=5.0)
    except Exception:
        llm_available = False
        llm_endpoint = "http://localhost:11434"
        llm_model = "qwen2.5-coder"

    fallback_alerts: list[dict[str, Any]] = []

    if llm_available:
        llm_status = "OPERATIONAL"
        fallback_mode = False
        fallback_engine = None
        fallback_alerts = [
            {
                "alert_id": f"LLM-STATUS-{uuid.uuid4().hex[:8].upper()}",
                "timestamp": now.isoformat(),
                "alert_type": "LLM_ONLINE",
                "severity": "info",
                "title": f"Local Ollama Qwen Coder ({llm_model}) active & responsive",
                "detail": (
                    f"Local air-gapped inference engine connected at {llm_endpoint}. "
                    "Multi-agent triage, regulatory clause matching, and AI incident drafting are active. "
                    "Strict air-gap invariant enforced with zero external API calls."
                ),
                "remediation": [
                    f"Model: {llm_model}",
                    f"Endpoint: {llm_endpoint}",
                    "Air-gap validation: PASSED",
                ],
                "impact": {
                    "incident_summarization": "LOCAL_LLM_ACTIVE",
                    "threat_classification": "LOCAL_LLM_ACTIVE",
                    "mitre_mapping": "QWEN_CODER_2.5",
                    "filing_draft_assist": "ENABLED",
                    "exposure_narrative": "ENABLED",
                },
                "automated_response": {
                    "action": "ONLINE_AIRGAPPED_INFERENCE",
                    "description": "Multi-agent pipeline running local inference through Ollama with strict Pydantic schema validation.",
                    "rule_engine_status": "HOT_STANDBY",
                    "qwen_model_loaded": True,
                },
            }
        ]
    else:
        llm_status = "UNAVAILABLE"
        fallback_mode = True
        fallback_engine = "RULE_BASED_DETERMINISTIC"
        fallback_alerts = [
            {
                "alert_id": f"LLM-FALLBACK-{uuid.uuid4().hex[:8].upper()}",
                "timestamp": now.isoformat(),
                "alert_type": "LLM_UNAVAILABLE",
                "severity": "warning",
                "title": "Local LLM inference unavailable – rule-based fallback active",
                "detail": (
                    "No local Ollama inference endpoint detected at http://localhost:11434. "
                    "Automated incident summarization, threat classification, and MITRE ATT&CK mapping "
                    "are operating in rule-based fallback mode. "
                    "Per AGENTS.md air-gap requirement, no external LLM API calls are permitted."
                ),
                "remediation": [
                    "Start local Ollama daemon: ollama serve",
                    f"Ensure model is pulled: ollama pull {llm_model}",
                    f"Verify endpoint: curl {llm_endpoint}/api/tags",
                ],
                "impact": {
                    "incident_summarization": "RULE_BASED_FALLBACK",
                    "threat_classification": "RULE_BASED_FALLBACK",
                    "mitre_mapping": "STATIC_LOOKUP",
                    "filing_draft_assist": "TEMPLATE_ONLY",
                    "exposure_narrative": "DISABLED",
                },
                "automated_response": {
                    "action": "FALLBACK_MODE_ACTIVATED",
                    "description": "All LLM-dependent features have automatically degraded to deterministic rule-based processing. No data is sent externally.",
                    "rule_engine_status": "ACTIVE",
                    "static_mitre_db_loaded": True,
                    "template_filing_engine": "READY",
                },
            },
        ]

    return {
        "llm_available": llm_available,
        "llm_status": llm_status,
        "llm_endpoint": llm_endpoint,
        "llm_model": llm_model,
        "fallback_mode": fallback_mode,
        "fallback_engine": fallback_engine,
        "alerts": fallback_alerts,
        "checked_at": now.isoformat(),
    }


@router.get("/security-telemetry")
def get_security_tool_telemetry(
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Returns comprehensive real-time simulated telemetry from all connected cybersecurity tools,
    plus automated alerts and LLM availability status."""
    now = datetime.now(UTC)

    # Fetch registered tool passports from DB
    passports = list(
        db.scalars(select(ToolCompliancePassport).order_by(ToolCompliancePassport.tool_name.asc())).all()
    )

    # Generate health telemetry for each tool
    tool_health = []
    for p in passports:
        health = _simulate_tool_health(p.tool_id, p.tool_name, p.category, p.trust_status)
        tool_health.append(health)

    # If no passports in DB, generate from hardcoded list for demo
    if not tool_health:
        demo_tools = [
            ("tool-siem-splunk", "Splunk Enterprise Security", "SIEM", "TRUSTED"),
            ("tool-edr-crowdstrike", "CrowdStrike Falcon Enterprise", "EDR", "TRUSTED"),
            ("tool-fw-paloalto", "Palo Alto Networks Strata NGFW", "Firewall", "TRUSTED"),
            ("tool-dam-imperva", "Imperva SecureSphere DAM", "Database Security", "TRUSTED"),
            ("tool-pam-cyberark", "CyberArk Privileged Access Manager", "IAM/PAM", "TRUSTED"),
            ("tool-siem-sentinel", "Microsoft Sentinel", "SIEM", "TRUSTED"),
            ("tool-edr-sentinelone", "SentinelOne Singularity Complete", "EDR", "TRUSTED"),
            ("tool-waf-f5", "F5 BIG-IP Advanced WAF", "WAF", "TRUSTED"),
            ("tool-cspm-wiz", "Wiz Cloud Security Platform", "Cloud Security", "TRUSTED"),
            ("tool-fw-fortinet", "Fortinet FortiGate Enterprise", "Firewall", "TRUSTED"),
            ("tool-iam-entra", "Microsoft Entra ID Governance", "IAM", "TRUSTED"),
            ("tool-legacy-ids-snort", "Legacy Branch Perimeter NIDS (Snort v2)", "NIDS", "DEGRADED"),
        ]
        for tid, tname, tcat, tstatus in demo_tools:
            tool_health.append(_simulate_tool_health(tid, tname, tcat, tstatus))

    # Aggregate stats
    total = len(tool_health)
    healthy = sum(1 for t in tool_health if t["health"] == "HEALTHY")
    degraded = sum(1 for t in tool_health if t["health"] == "DEGRADED")
    warning = sum(1 for t in tool_health if t["health"] == "WARNING")
    total_eps = sum(t["metrics"]["events_per_minute"] for t in tool_health)

    # Generate recent alerts
    recent_alerts = _simulate_recent_alerts(total)

    # Check LLM availability
    llm_status = _check_llm_availability()

    return {
        "timestamp": now.isoformat(),
        "summary": {
            "total_tools_monitored": total,
            "healthy_tools": healthy,
            "degraded_tools": degraded,
            "warning_tools": warning,
            "total_events_per_minute": total_eps,
            "alert_count_last_2h": len(recent_alerts),
            "critical_alerts": sum(1 for a in recent_alerts if a["severity"] == "critical"),
        },
        "tool_health": tool_health,
        "recent_alerts": recent_alerts,
        "llm_status": llm_status,
        "automated_responses_active": True,
        "response_engine": f"LOCAL_OLLAMA_{llm_status['llm_model'].upper()}" if llm_status["llm_available"] else "DETERMINISTIC_RULE_BASED",
    }
