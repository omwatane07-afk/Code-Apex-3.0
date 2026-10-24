"""CERT-In Directions (28 April 2022) Mandatory Incident Category Correlation Engine.

Maps incoming CVE identifiers, attack signatures, and tool alert names to the 20 statutory
CERT-In reportable incident types defined under Section 70B of the IT Act, 2000.
"""

from __future__ import annotations

import re
from typing import Any

CERTIN_INCIDENT_CATEGORIES: dict[str, dict[str, Any]] = {
    "RANSOMWARE": {
        "category_id": "CERTIN-CAT-05",
        "name": "Malicious code attacks (Ransomware / Cryptominers / Worms)",
        "deadline_hours": 6,
        "keywords": ["ransomware", "encryptor", "locker", "cryptolocker", "shadow copy", "vssadmin"],
        "severity": "critical",
    },
    "DATA_BREACH": {
        "category_id": "CERTIN-CAT-11",
        "name": "Data Breach or Unlawful Data Exfiltration",
        "deadline_hours": 6,
        "keywords": ["data breach", "exfiltration", "mass dump", "database dump", "unauthorized query", "dam violation"],
        "severity": "critical",
    },
    "PAYMENT_SYSTEM_ATTACK": {
        "category_id": "CERTIN-CAT-13",
        "name": "Attacks or Incidents Affecting Digital Payment Systems (RTGS / NEFT / UPI / ATM)",
        "deadline_hours": 6,
        "keywords": ["rtgs", "neft", "upi", "switch", "iso8583", "atm switch", "core banking switch"],
        "severity": "critical",
    },
    "UNAUTHORIZED_ACCESS": {
        "category_id": "CERTIN-CAT-03",
        "name": "Unauthorized Access of Critical Banking IT Systems / Active Directory",
        "deadline_hours": 6,
        "keywords": ["credential checkout", "golden ticket", "pass the hash", "privilege escalation", "domain admin"],
        "severity": "high",
    },
    "DDOS": {
        "category_id": "CERTIN-CAT-08",
        "name": "Denial of Service (DoS) and Distributed Denial of Service (DDoS) Attacks",
        "deadline_hours": 6,
        "keywords": ["ddos", "syn flood", "amplification", "rate limit exceeded", "traffic saturation"],
        "severity": "high",
    },
    "CRITICAL_INFRASTRUCTURE": {
        "category_id": "CERTIN-CAT-09",
        "name": "Attacks on Critical Information Infrastructure (CII / SWIFT / HSM)",
        "deadline_hours": 6,
        "keywords": ["swift", "hsm", "pkcs11", "core switch", "data center core"],
        "severity": "critical",
    },
    "SUPPLY_CHAIN": {
        "category_id": "CERTIN-CAT-19",
        "name": "High-Impact Software Supply Chain Attacks",
        "deadline_hours": 6,
        "keywords": ["supply chain", "ci/cd compromise", "trojanized dependency", "vendor breach"],
        "severity": "high",
    },
    "TARGETED_SCANNING": {
        "category_id": "CERTIN-CAT-01",
        "name": "Targeted Scanning / Probing of Critical Banking Networks",
        "deadline_hours": 6,
        "keywords": ["port scan", "reconnaissance", "vulnerability probe", "masscan"],
        "severity": "medium",
    },
}

# High-profile CVEs mapped to statutory CERT-In advisories
KNOWN_CERTIN_CVE_ADVISORIES: dict[str, str] = {
    "CVE-2024-21413": "CIVN-2024-0089: Critical Outlook NTLM Credential Theft & RCE",
    "CVE-2023-34362": "CIVN-2023-0182: Critical MOVEit Transfer SQL Injection Vulnerability",
    "CVE-2023-4966": "CIVN-2023-0312: Citrix Bleed Sensitive Memory Disclosure Vulnerability",
    "CVE-2024-3400": "CIVN-2024-0131: Palo Alto Networks PAN-OS GlobalProtect Command Injection",
    "CVE-2024-1709": "CIVN-2024-0094: ScreenConnect Authentication Bypass Vulnerability",
    "CVE-2021-44228": "CIVN-2021-0428: Apache Log4j2 JNDI Remote Code Execution Vulnerability",
    "CVE-2024-6387": "CIVN-2024-0211: regreSSHion OpenSSH Pre-Auth Remote Code Execution",
}


def correlate_certin_reportability(
    raw_text: str,
    cve_ids: list[str],
    signature_name: str = "",
) -> tuple[bool, list[str], str]:
    """Correlates an incoming event against CERT-In advisory definitions.

    Returns: (is_statutory_reportable, matched_advisories, recommended_severity).
    """
    corpus = f"{raw_text} {signature_name}".lower()
    matched_advisories: list[str] = []
    max_severity = "low"

    # 1. Correlate CVE IDs
    for cve in cve_ids:
        cve_upper = cve.upper().strip()
        if cve_upper in KNOWN_CERTIN_CVE_ADVISORIES:
            advisory = KNOWN_CERTIN_CVE_ADVISORIES[cve_upper]
            matched_advisories.append(f"CERT-In Advisory: {advisory}")
            max_severity = "critical"

    # 2. Correlate statutory incident categories
    for _cat_key, cat_meta in CERTIN_INCIDENT_CATEGORIES.items():
        for kw in cat_meta["keywords"]:
            if re.search(r"\b" + re.escape(kw) + r"\b", corpus):
                advisory_label = f"{cat_meta['category_id']}: {cat_meta['name']}"
                if advisory_label not in matched_advisories:
                    matched_advisories.append(advisory_label)
                if cat_meta["severity"] == "critical":
                    max_severity = "critical"
                elif cat_meta["severity"] == "high" and max_severity != "critical":
                    max_severity = "high"
                break

    is_reportable = len(matched_advisories) > 0
    return is_reportable, matched_advisories, max_severity
