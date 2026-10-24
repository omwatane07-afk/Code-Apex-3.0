"""Normalized multi-tool parser for 20+ enterprise banking security tools.

Supports both structured JSON webhooks and RFC 5424 / CEF (Common Event Format) Syslog.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from cyberq.intake.models import NormalizedSecurityEvent


def _parse_cef_extension(ext_str: str) -> dict[str, str]:
    """Parses key=value pairs from a CEF extension string."""
    pattern = re.compile(r"([a-zA-Z0-9_-]+)=((?:\\=|[^= ])+)(?:\s+|$)")
    matches = pattern.findall(ext_str)
    return {k: v.strip().replace(r"\=", "=") for k, v in matches}


def parse_cef_syslog(raw_line: str) -> NormalizedSecurityEvent:
    """Parses a CEF (Common Event Format) RFC 5424 line:

    CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|Extension
    """
    clean_line = raw_line.strip()
    # ReDoS defense: reject CEF lines exceeding 64KB to bound regex processing
    if len(clean_line) > 65_536:
        raise ValueError("CEF payload exceeds maximum allowed length of 64KB")
    match = re.search(r"CEF:\s*0\s*\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)", clean_line)
    if not match:
        raise ValueError("Invalid CEF header structure. Must follow CEF:0|Vendor|Product|Version|ClassID|Name|Severity|Extension")

    vendor, product, version, class_id, name, severity_raw, extension_str = match.groups()
    ext = _parse_cef_extension(extension_str)

    # Normalize severity
    sev_map = {
        "0": "low", "1": "low", "2": "low", "3": "low",
        "4": "medium", "5": "medium", "6": "medium",
        "7": "high", "8": "high", "9": "critical", "10": "critical",
        "low": "low", "medium": "medium", "high": "high", "critical": "critical",
    }
    normalized_sev = sev_map.get(severity_raw.strip().lower(), "medium")

    # Extract standard fields from CEF extensions
    src_ip = ext.get("src") or ext.get("sourceAddress")
    dst_ip = ext.get("dst") or ext.get("destinationAddress")
    src_host = ext.get("shost") or ext.get("sourceHostName")
    dst_host = ext.get("dhost") or ext.get("destinationHostName")
    msg = ext.get("msg") or name

    # Extract CVE identifiers
    cves: list[str] = []
    if "cve" in ext:
        cves.append(ext["cve"].strip().upper())
    found_cves = re.findall(r"\bCVE-\d{4}-\d{4,7}\b", raw_line, re.IGNORECASE)
    for c in found_cves:
        if c.upper() not in cves:
            cves.append(c.upper())

    # Timestamp extraction
    ts = datetime.now(UTC)
    if "rt" in ext:
        try:
            # Unix millisecond timestamp or ISO
            val = ext["rt"].strip()
            if val.isdigit():
                ts = datetime.fromtimestamp(int(val) / 1000.0, UTC)
            else:
                parsed_dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
                ts = parsed_dt if parsed_dt.tzinfo else parsed_dt.replace(tzinfo=UTC)
        except (ValueError, OSError):
            ts = datetime.now(UTC)

    return NormalizedSecurityEvent(
        event_id=ext.get("externalId") or ext.get("id") or f"CEF-{int(ts.timestamp() * 1000)}",
        source_tool=f"{vendor.strip()} {product.strip()}",
        vendor=vendor.strip(),
        category="CEF_Syslog",
        timestamp=ts,
        source_ip=src_ip,
        destination_ip=dst_ip,
        source_hostname=src_host,
        destination_hostname=dst_host,
        cve_ids=cves,
        signature_id=class_id.strip(),
        event_name=name.strip(),
        severity=normalized_sev,
        raw_message=msg.strip(),
        attributes=ext,
    )


# 20+ Tool Specific JSON Normalizers
def parse_json_event(tool_identifier: str, data: dict[str, Any]) -> NormalizedSecurityEvent:
    """Normalizes JSON security event payloads across 20+ banking tool profiles."""
    tid = tool_identifier.lower().replace("-", "_").replace(" ", "_")
    ts = datetime.now(UTC)

    # 1. SIEM Tools
    if "splunk" in tid:
        # Splunk ES Alert schema
        result = data.get("result", data)
        return NormalizedSecurityEvent(
            event_id=str(result.get("sid") or result.get("_bkt") or f"SPL-{int(ts.timestamp() * 1000)}"),
            source_tool="Splunk Enterprise Security",
            vendor="Splunk",
            category="SIEM",
            timestamp=ts,
            source_ip=result.get("src_ip") or result.get("src"),
            destination_ip=result.get("dest_ip") or result.get("dest"),
            source_hostname=result.get("src_host"),
            destination_hostname=result.get("dest_host"),
            signature_id=str(result.get("search_name") or "SPLUNK-ES-RULE"),
            event_name=str(result.get("search_name") or "Splunk Correlation Search Alert"),
            severity=str(result.get("urgency") or result.get("severity") or "high").lower(),
            raw_message=str(result.get("_raw") or result.get("description") or "Splunk ES correlation rule triggered"),
            attributes=data,
        )

    elif "qradar" in tid:
        # IBM QRadar Offense schema
        return NormalizedSecurityEvent(
            event_id=f"QR-{data.get('id', int(ts.timestamp() * 1000))}",
            source_tool="IBM QRadar SIEM",
            vendor="IBM",
            category="SIEM",
            timestamp=ts,
            source_ip=data.get("offense_source") or data.get("source_network"),
            destination_ip=data.get("local_destination_address"),
            signature_id=str(data.get("offense_type", "QRADAR-OFFENSE")),
            event_name=str(data.get("description", "QRadar Security Offense")),
            severity="critical" if data.get("magnitude", 5) >= 8 else "high",
            raw_message=str(data.get("description", "QRadar offense fired")),
            attributes=data,
        )

    elif "sentinel" in tid:
        # Microsoft Sentinel Incident schema
        props = data.get("properties", data)
        return NormalizedSecurityEvent(
            event_id=str(data.get("name") or f"MS-SENTINEL-{int(ts.timestamp() * 1000)}"),
            source_tool="Microsoft Sentinel",
            vendor="Microsoft",
            category="SIEM",
            timestamp=ts,
            signature_id=str(props.get("incidentNumber", "SENTINEL-RULE")),
            event_name=str(props.get("title", "Microsoft Sentinel Incident")),
            severity=str(props.get("severity", "High")).lower(),
            raw_message=str(props.get("description", "Microsoft Sentinel incident created")),
            attributes=data,
        )

    elif "logrhythm" in tid:
        return NormalizedSecurityEvent(
            event_id=f"LR-{data.get('alarmId', int(ts.timestamp() * 1000))}",
            source_tool="LogRhythm SIEM",
            vendor="LogRhythm",
            category="SIEM",
            timestamp=ts,
            source_ip=data.get("sourceIp"),
            destination_ip=data.get("destIp"),
            signature_id=str(data.get("alarmRuleId", "LR-ALARM")),
            event_name=str(data.get("alarmRuleName", "LogRhythm Alarm")),
            severity="high" if data.get("riskScore", 50) >= 70 else "medium",
            raw_message=str(data.get("comments", "LogRhythm alarm notification")),
            attributes=data,
        )

    elif "arcsight" in tid:
        return NormalizedSecurityEvent(
            event_id=f"AS-{data.get('eventId', int(ts.timestamp() * 1000))}",
            source_tool="Micro Focus ArcSight",
            vendor="Micro Focus",
            category="SIEM",
            timestamp=ts,
            source_ip=data.get("sourceAddress"),
            destination_ip=data.get("destinationAddress"),
            signature_id=str(data.get("deviceEventClassId", "ARCSIGHT-EVENT")),
            event_name=str(data.get("name", "ArcSight ESM Event")),
            severity="high" if data.get("priority", 5) >= 7 else "medium",
            raw_message=str(data.get("message", "ArcSight ESM alert")),
            attributes=data,
        )

    # 2. EDR / XDR Tools
    elif "crowdstrike" in tid:
        # CrowdStrike Falcon Detection schema
        event = data.get("event", data)
        return NormalizedSecurityEvent(
            event_id=str(data.get("composite_id") or f"CS-{int(ts.timestamp() * 1000)}"),
            source_tool="CrowdStrike Falcon",
            vendor="CrowdStrike",
            category="EDR/XDR",
            timestamp=ts,
            source_ip=event.get("LocalIP"),
            destination_ip=event.get("RemoteIP"),
            source_hostname=event.get("ComputerName"),
            signature_id=str(event.get("DetectId") or "FALCON-DETECT"),
            event_name=str(event.get("DetectDescription") or "CrowdStrike Falcon Endpoint Alert"),
            severity=str(event.get("SeverityName") or "critical").lower(),
            raw_message=str(event.get("Tactic") or event.get("Technique") or "CrowdStrike detection triggered"),
            attributes=data,
        )

    elif "sentinelone" in tid:
        # SentinelOne Singularity Threat schema
        threat = data.get("data", data)
        return NormalizedSecurityEvent(
            event_id=str(threat.get("id") or f"S1-{int(ts.timestamp() * 1000)}"),
            source_tool="SentinelOne Singularity",
            vendor="SentinelOne",
            category="EDR/XDR",
            timestamp=ts,
            source_ip=threat.get("agentIp"),
            source_hostname=threat.get("agentComputerName"),
            signature_id=str(threat.get("classification") or "S1-THREAT"),
            event_name=str(threat.get("threatName") or "SentinelOne Malicious Activity"),
            severity="critical" if threat.get("confidenceLevel") == "malicious" else "high",
            raw_message=str(threat.get("description") or "SentinelOne Singularity endpoint quarantine"),
            attributes=data,
        )

    elif "defender" in tid:
        # Microsoft Defender for Endpoint
        return NormalizedSecurityEvent(
            event_id=str(data.get("id") or f"MDE-{int(ts.timestamp() * 1000)}"),
            source_tool="Microsoft Defender for Endpoint",
            vendor="Microsoft",
            category="EDR/XDR",
            timestamp=ts,
            source_ip=data.get("machineIp"),
            source_hostname=data.get("computerDnsName"),
            signature_id=str(data.get("alertId") or "DEFENDER-ALERT"),
            event_name=str(data.get("title") or "Microsoft Defender Endpoint Alert"),
            severity=str(data.get("severity", "High")).lower(),
            raw_message=str(data.get("description") or "Microsoft Defender detection alert"),
            attributes=data,
        )

    elif "vision_one" in tid or "trend" in tid:
        return NormalizedSecurityEvent(
            event_id=str(data.get("uuid") or f"TM-{int(ts.timestamp() * 1000)}"),
            source_tool="Trend Micro Vision One",
            vendor="Trend Micro",
            category="EDR/XDR",
            timestamp=ts,
            source_ip=data.get("endpointIp"),
            signature_id=str(data.get("ruleId", "VISION-ONE-RULE")),
            event_name=str(data.get("incidentName", "Trend Micro Vision One Alert")),
            severity=str(data.get("scoreLevel", "critical")).lower(),
            raw_message=str(data.get("description", "Trend Micro detected malicious execution")),
            attributes=data,
        )

    elif "carbon_black" in tid:
        return NormalizedSecurityEvent(
            event_id=str(data.get("id") or f"CB-{int(ts.timestamp() * 1000)}"),
            source_tool="VMware Carbon Black",
            vendor="VMware",
            category="EDR/XDR",
            timestamp=ts,
            source_ip=data.get("device_ip"),
            source_hostname=data.get("device_name"),
            signature_id=str(data.get("threat_id", "CB-THREAT")),
            event_name=str(data.get("reason", "Carbon Black Threat Alert")),
            severity="high",
            raw_message=str(data.get("threat_cause", "Malicious process activity blocked")),
            attributes=data,
        )

    # 3. Network / Firewall / WAF
    elif "palo_alto" in tid:
        # Palo Alto Networks PAN-OS Threat Log
        return NormalizedSecurityEvent(
            event_id=str(data.get("seqno") or f"PAN-{int(ts.timestamp() * 1000)}"),
            source_tool="Palo Alto Networks Next-Gen Firewall",
            vendor="Palo Alto Networks",
            category="Firewall",
            timestamp=ts,
            source_ip=data.get("src") or data.get("source_ip"),
            destination_ip=data.get("dst") or data.get("destination_ip"),
            signature_id=str(data.get("threatid") or "PAN-THREAT"),
            event_name=str(data.get("threat_name") or "Palo Alto Threat Prevention Alert"),
            severity=str(data.get("severity") or "high").lower(),
            raw_message=str(data.get("misc") or "Palo Alto NGFW blocked exploit payload"),
            attributes=data,
        )

    elif "cisco" in tid:
        return NormalizedSecurityEvent(
            event_id=str(data.get("eventId") or f"CSCO-{int(ts.timestamp() * 1000)}"),
            source_tool="Cisco Firepower / ASA",
            vendor="Cisco",
            category="Firewall",
            timestamp=ts,
            source_ip=data.get("sourceAddress"),
            destination_ip=data.get("destinationAddress"),
            signature_id=str(data.get("signatureId", "CISCO-IPS")),
            event_name=str(data.get("signatureName", "Cisco Firepower Intrusion Event")),
            severity="high",
            raw_message=str(data.get("impact", "Intrusion prevention signature fired")),
            attributes=data,
        )

    elif "fortinet" in tid:
        return NormalizedSecurityEvent(
            event_id=str(data.get("logid") or f"FTNT-{int(ts.timestamp() * 1000)}"),
            source_tool="Fortinet FortiGate",
            vendor="Fortinet",
            category="Firewall",
            timestamp=ts,
            source_ip=data.get("srcip"),
            destination_ip=data.get("dstip"),
            signature_id=str(data.get("attackid", "FORTIGATE-IPS")),
            event_name=str(data.get("attack", "FortiGate IPS Detection")),
            severity=str(data.get("level", "high")).lower(),
            raw_message=str(data.get("msg", "FortiGate security policy violation")),
            attributes=data,
        )

    elif "checkpoint" in tid:
        return NormalizedSecurityEvent(
            event_id=str(data.get("uid") or f"CP-{int(ts.timestamp() * 1000)}"),
            source_tool="Check Point Quantum",
            vendor="Check Point",
            category="Firewall",
            timestamp=ts,
            source_ip=data.get("src"),
            destination_ip=data.get("dst"),
            signature_id=str(data.get("protection_name", "CHECKPOINT-IPS")),
            event_name=str(data.get("attack", "Check Point Threat Emulation Alert")),
            severity="critical" if data.get("severity") == "critical" else "high",
            raw_message=str(data.get("description", "Malicious network packet dropped")),
            attributes=data,
        )

    elif "f5" in tid:
        return NormalizedSecurityEvent(
            event_id=str(data.get("support_id") or f"F5-{int(ts.timestamp() * 1000)}"),
            source_tool="F5 BIG-IP Advanced WAF",
            vendor="F5",
            category="WAF",
            timestamp=ts,
            source_ip=data.get("client_ip"),
            destination_ip=data.get("virtual_server"),
            signature_id=str(data.get("violation_details", "F5-WAF-VIOLATION")),
            event_name="F5 WAF Security Policy Violation",
            severity="high",
            raw_message=str(data.get("violations", "SQL injection or XSS violation blocked")),
            attributes=data,
        )

    elif "cloudflare" in tid:
        return NormalizedSecurityEvent(
            event_id=str(data.get("ray_id") or f"CF-{int(ts.timestamp() * 1000)}"),
            source_tool="Cloudflare Enterprise WAF",
            vendor="Cloudflare",
            category="WAF",
            timestamp=ts,
            source_ip=data.get("client_ip"),
            signature_id=str(data.get("rule_id", "CLOUDFLARE-WAF")),
            event_name="Cloudflare Managed Ruleset Trigger",
            severity="high",
            raw_message=str(data.get("action", "Blocked malicious HTTP payload")),
            attributes=data,
        )

    # 4. DAM (Database Activity Monitoring)
    elif "imperva" in tid:
        return NormalizedSecurityEvent(
            event_id=str(data.get("alertId") or f"IMP-{int(ts.timestamp() * 1000)}"),
            source_tool="Imperva SecureSphere DAM",
            vendor="Imperva",
            category="DAM",
            timestamp=ts,
            source_ip=data.get("clientIp"),
            destination_ip=data.get("serverIp"),
            signature_id=str(data.get("policyName", "IMPERVA-DAM-POLICY")),
            event_name="Imperva Database Activity Violation",
            severity="critical",
            raw_message=str(data.get("description", "Unauthorized mass data extraction from core banking DB")),
            attributes=data,
        )

    elif "guardium" in tid:
        return NormalizedSecurityEvent(
            event_id=str(data.get("policyViolationId") or f"GRD-{int(ts.timestamp() * 1000)}"),
            source_tool="IBM Security Guardium",
            vendor="IBM",
            category="DAM",
            timestamp=ts,
            source_ip=data.get("clientIp"),
            destination_ip=data.get("serverIp"),
            signature_id=str(data.get("policyName", "GUARDIUM-POLICY")),
            event_name="IBM Guardium Sensitive Data Access Alert",
            severity="critical",
            raw_message=str(data.get("sqlStatement", "Restricted table SELECT queried without approval")),
            attributes=data,
        )

    # 5. IAM & PAM
    elif "cyberark" in tid:
        return NormalizedSecurityEvent(
            event_id=str(data.get("IncidentId") or f"CYB-{int(ts.timestamp() * 1000)}"),
            source_tool="CyberArk Privileged Access Manager",
            vendor="CyberArk",
            category="IAM/PAM",
            timestamp=ts,
            source_ip=data.get("SourceAddress"),
            signature_id=str(data.get("ActivityType", "CYBERARK-PAM-ANOMALY")),
            event_name="CyberArk Privileged Session Anomaly",
            severity="critical",
            raw_message=str(data.get("Details", "Unmanaged domain controller credential checkout")),
            attributes=data,
        )

    elif "vault" in tid:
        return NormalizedSecurityEvent(
            event_id=f"VLT-{int(ts.timestamp() * 1000)}",
            source_tool="HashiCorp Vault",
            vendor="HashiCorp",
            category="IAM/PAM",
            timestamp=ts,
            source_ip=data.get("request", {}).get("remote_address"),
            signature_id="VAULT-AUTH-FAILURE",
            event_name="HashiCorp Vault Token Misuse Anomaly",
            severity="high",
            raw_message="Repeated unauthorized token creation on root PKI mount",
            attributes=data,
        )

    elif "okta" in tid:
        return NormalizedSecurityEvent(
            event_id=str(data.get("uuid") or f"OKTA-{int(ts.timestamp() * 1000)}"),
            source_tool="Okta Identity Threat Protection",
            vendor="Okta",
            category="IAM/PAM",
            timestamp=ts,
            source_ip=data.get("client", {}).get("ipAddress"),
            signature_id=str(data.get("eventType", "OKTA-THREAT-EVENT")),
            event_name="Okta Suspicious Login & MFA Bypass Attempt",
            severity="high",
            raw_message=str(data.get("displayMessage", "Session hijacking attempt detected")),
            attributes=data,
        )

    elif "entra" in tid or "adfs" in tid:
        return NormalizedSecurityEvent(
            event_id=str(data.get("id") or f"ENTRA-{int(ts.timestamp() * 1000)}"),
            source_tool="Microsoft Entra ID / AD FS",
            vendor="Microsoft",
            category="IAM/PAM",
            timestamp=ts,
            source_ip=data.get("ipAddress"),
            signature_id=str(data.get("riskEventType", "ENTRA-RISK")),
            event_name="Microsoft Entra Risky User Detection",
            severity="high",
            raw_message=str(data.get("riskDetail", "Impossible travel or anomalous token replay")),
            attributes=data,
        )

    # Generic Fallback Normalizer
    return NormalizedSecurityEvent(
        event_id=str(data.get("id", f"GEN-{int(ts.timestamp() * 1000)}")),
        source_tool=tool_identifier,
        vendor=data.get("vendor", "Generic Security Tool"),
        category=data.get("category", "General"),
        timestamp=ts,
        source_ip=data.get("source_ip") or data.get("src"),
        destination_ip=data.get("dest_ip") or data.get("dst"),
        source_hostname=data.get("source_hostname"),
        destination_hostname=data.get("destination_hostname"),
        signature_id=str(data.get("signature_id", "GENERIC-SIGNATURE")),
        event_name=str(data.get("title", data.get("name", "Generic Security Alert"))),
        severity=str(data.get("severity", "medium")).lower(),
        raw_message=str(data.get("message", data.get("summary", "Generic security telemetry"))),
        attributes=data,
    )
