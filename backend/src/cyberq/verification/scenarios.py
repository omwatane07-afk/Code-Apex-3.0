"""Cybersecurity Tool Verification Lab Scenarios and Crash Test Suites.

Controlled, repeatable synthetic attack and telemetry scenarios:
1. Suspicious Authentication (Credential stuffing & impossible travel)
2. Malware-like Behavior (Process hollowing & AMSI memory patching)
3. Unauthorized Privilege Changes (Domain Admin escalation)
4. Network Intrusion (Lateral SMB movement & C2 beaconing)
5. Phishing Indicators (Homograph banking domain & weaponized macro)
6. Data Exfiltration (DNS tunneling of masked banking records)
7. Vulnerability Detection (Critical CVE identification)
8. Logging & Alert Delivery (Telemetry drop under stress)
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class ThreatCategory(StrEnum):
    CREDENTIAL_ACCESS = "Credential Access"
    DEFENSE_EVASION = "Defense Evasion"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    LATERAL_MOVEMENT = "Lateral Movement"
    INITIAL_ACCESS = "Initial Access"
    EXFILTRATION = "Exfiltration"
    VULNERABILITY = "Vulnerability Management"
    OBSERVABILITY = "Telemetry & Logging"


@dataclass
class VerificationTestScenario:
    test_id: str
    name: str
    category: ThreatCategory
    mitre_attack_id: str
    nist_csf_id: str
    rbi_clause: str
    certin_clause: str
    description: str
    synthetic_payload: dict[str, Any]
    expected_event_pattern: dict[str, Any]
    ground_truth: str  # "MALICIOUS" or "BENIGN"
    is_mandatory: bool  # If mandatory test fails, verdict CANNOT be PASS
    repeat_count: int = 3
    timeout_seconds: int = 30


# Canonical Suite of 8 Automotive Crash Test Scenarios
VERIFICATION_TEST_SUITE: dict[str, VerificationTestScenario] = {
    "SCEN-AUTH-01": VerificationTestScenario(
        test_id="SCEN-AUTH-01",
        name="Distributed Credential Stuffing & Impossible Travel",
        category=ThreatCategory.CREDENTIAL_ACCESS,
        mitre_attack_id="T1110.004",
        nist_csf_id="PR.AC-01",
        rbi_clause="Para 88 (MFA & Anomaly Auth)",
        certin_clause="Annexure I (Unauthorized Access)",
        description=(
            "Simulates rapid successive login attempts for core teller accounts originating from disparate "
            "geo-locations (Mumbai -> Frankfurt within 4 minutes), testing authentication anomaly detection."
        ),
        synthetic_payload={
            "source_ips": ["103.21.244.12", "194.26.29.112"],
            "target_account": "teller_blr_092@bankcore.internal",
            "attempt_frequency_hz": 18,
            "geo_delta_km": 6800,
            "time_delta_seconds": 240,
        },
        expected_event_pattern={
            "alert_name": "Impossible Travel Velocity Breached",
            "severity": "HIGH",
            "action_taken": "SESSION_CHALLENGED_MFA",
        },
        ground_truth="MALICIOUS",
        is_mandatory=True,
    ),
    "SCEN-MALWARE-01": VerificationTestScenario(
        test_id="SCEN-MALWARE-01",
        name="Process Hollowing & AMSI In-Memory Tampering",
        category=ThreatCategory.DEFENSE_EVASION,
        mitre_attack_id="T1055.012",
        nist_csf_id="DE.CM-01",
        rbi_clause="Para 45(a) (Continuous Monitoring)",
        certin_clause="Annexure I (Compromise of Systems)",
        description=(
            "Simulates unhooking and memory injection into a benign svchost.exe parent process, "
            "evaluating whether EDR kernel callbacks detect anomalous unbacked memory pages."
        ),
        synthetic_payload={
            "target_process": "svchost.exe",
            "injection_technique": "NtCreateSection_VirtualAllocEx",
            "memory_protection": "PAGE_EXECUTE_READWRITE",
            "amsi_patch": "AmsiScanBuffer_Ret_Patch",
        },
        expected_event_pattern={
            "alert_name": "Memory Injection / Process Hollowing Detected",
            "severity": "CRITICAL",
            "action_taken": "PROCESS_TERMINATED",
        },
        ground_truth="MALICIOUS",
        is_mandatory=True,
    ),
    "SCEN-PRIVESC-01": VerificationTestScenario(
        test_id="SCEN-PRIVESC-01",
        name="Unauthorized Active Directory Enterprise Admin Elevation",
        category=ThreatCategory.PRIVILEGE_ESCALATION,
        mitre_attack_id="T1078.002",
        nist_csf_id="PR.AC-01",
        rbi_clause="Para 88 (Privileged Access Monitoring)",
        certin_clause="Annexure I (Unauthorized Privilege)",
        description=(
            "Simulates modification of Domain Admins group membership via unauthenticated LDAP injection "
            "or DCSync replication request outside scheduled change control windows."
        ),
        synthetic_payload={
            "target_group": "CN=Enterprise Admins,CN=Users,DC=bankcore,DC=internal",
            "added_principal": "svc_test_service",
            "caller_sid": "S-1-5-21-392817293-1001",
            "replication_guid": "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",
        },
        expected_event_pattern={
            "alert_name": "Privileged Group Membership Tampered",
            "severity": "CRITICAL",
            "action_taken": "ALERT_DISPATCHED_TO_SOC",
        },
        ground_truth="MALICIOUS",
        is_mandatory=True,
    ),
    "SCEN-LATERAL-01": VerificationTestScenario(
        test_id="SCEN-LATERAL-01",
        name="Lateral SMB Movement & C2 DNS Beaconing",
        category=ThreatCategory.LATERAL_MOVEMENT,
        mitre_attack_id="T1021.002",
        nist_csf_id="DE.AE-02",
        rbi_clause="Para 45(a) (Network Segregation Audit)",
        certin_clause="Annexure I (Compromise of IT Systems)",
        description=(
            "Simulates PsExec-style named pipe creation across internal VLAN boundaries followed by "
            "low-and-slow DNS TXT record beaconing with jitter to an external non-banking domain."
        ),
        synthetic_payload={
            "source_host": "10.20.10.45",
            "destination_host": "10.40.8.12",
            "named_pipe": "\\\\pipe\\\\psexecsvc",
            "beacon_interval_seconds": 120,
            "jitter_percent": 15,
            "c2_query_pattern": "x[0-9a-f]{8}.sync-cdn-update.net",
        },
        expected_event_pattern={
            "alert_name": "Lateral Movement via Administrative Share / DNS C2",
            "severity": "HIGH",
            "action_taken": "VLAN_ISOLATION_REQUESTED",
        },
        ground_truth="MALICIOUS",
        is_mandatory=True,
    ),
    "SCEN-PHISH-01": VerificationTestScenario(
        test_id="SCEN-PHISH-01",
        name="Spear-Phishing with Weaponized Macro & Domain Homograph",
        category=ThreatCategory.INITIAL_ACCESS,
        mitre_attack_id="T1566.001",
        nist_csf_id="DE.CM-01",
        rbi_clause="Para 182 (Proactive Reporting)",
        certin_clause="Annexure I (Phishing Attacks)",
        description=(
            "Simulates an inbound email purporting to be from RBI DAKSH supervisory division with a "
            "Cyrillic homograph domain and an attached macro-enabled .docm requesting wire transfer sign-off."
        ),
        synthetic_payload={
            "sender": "circulars@rbı-supervisory.org",  # Latin dotless i homograph
            "recipient": "ciso-office@bankcore.internal",
            "attachment_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "macro_payload": "AutoOpen() -> powershell -enc JAB...",
        },
        expected_event_pattern={
            "alert_name": "Homograph Spoof & Weaponized Macro Quarantined",
            "severity": "HIGH",
            "action_taken": "EMAIL_QUARANTINED",
        },
        ground_truth="MALICIOUS",
        is_mandatory=False,
    ),
    "SCEN-EXFIL-01": VerificationTestScenario(
        test_id="SCEN-EXFIL-01",
        name="Encrypted DNS Tunneling of Synthetic Customer Records",
        category=ThreatCategory.EXFILTRATION,
        mitre_attack_id="T1048.003",
        nist_csf_id="DE.AE-02",
        rbi_clause="Para 45(a) (Data Leak Prevention)",
        certin_clause="Annexure I (Data Breach)",
        description=(
            "Simulates encoding of synthetic 16-digit credit card PANs and IFSC codes into base32 subdomains "
            "queried against an external authoritative nameserver."
        ),
        synthetic_payload={
            "records_count": 500,
            "synthetic_pattern": "4111-XXXX-XXXX-1234",
            "tunnel_protocol": "DNS_NULL_QUERY",
            "egress_bytes": 128000,
        },
        expected_event_pattern={
            "alert_name": "High Volume DNS Tunneling Detected",
            "severity": "CRITICAL",
            "action_taken": "PORT_53_QUERY_BLOCKED",
        },
        ground_truth="MALICIOUS",
        is_mandatory=True,
    ),
    "SCEN-VULN-01": VerificationTestScenario(
        test_id="SCEN-VULN-01",
        name="Detection of Remote Code Execution CVE-2024-6387 (RegreSSHion)",
        category=ThreatCategory.VULNERABILITY,
        mitre_attack_id="T1190",
        nist_csf_id="DE.CM-01",
        rbi_clause="Para 45(a) (Vulnerability Remediation)",
        certin_clause="Annexure I (Compromise of Critical Systems)",
        description=(
            "Evaluates whether vulnerability scanner identifies unpatched OpenSSH 8.5p1 servers vulnerable "
            "to glibc signal handler race condition (RegreSSHion) in DMZ servers."
        ),
        synthetic_payload={
            "banner": "SSH-2.0-OpenSSH_8.5p1 Ubuntu-3ubuntu0.4",
            "cve": "CVE-2024-6387",
            "cvss_score": 8.1,
            "target_ip": "172.16.1.15",
        },
        expected_event_pattern={
            "alert_name": "Critical Vulnerability Identified: CVE-2024-6387",
            "severity": "HIGH",
            "action_taken": "PATCH_ADVISORY_FILED",
        },
        ground_truth="MALICIOUS",
        is_mandatory=True,
    ),
    "SCEN-LOGGING-01": VerificationTestScenario(
        test_id="SCEN-LOGGING-01",
        name="High-Throughput Syslog Stress & Connector Buffer Resilience",
        category=ThreatCategory.OBSERVABILITY,
        mitre_attack_id="T1070",
        nist_csf_id="DE.CM-01",
        rbi_clause="Para 45(a) (180-Day Tamper-Resistant Logging)",
        certin_clause="Clause (i) (180-Day Mandatory Log Retention)",
        description=(
            "Sends 25,000 synthetic CEF events/second to test whether SIEM and connector buffers maintain "
            "zero packet loss, sequence continuity, and cryptographic audit integrity under heavy load."
        ),
        synthetic_payload={
            "event_rate_eps": 25000,
            "total_events": 50000,
            "format": "CEF:0|Banking|CoreSwitch|1.0|200|TX_COMMITTED|1|",
            "simulated_drop_risk": True,
        },
        expected_event_pattern={
            "alert_name": "Telemetry Ingestion Rate Nominal (0% Drop)",
            "severity": "INFO",
            "action_taken": "INDEXED_AND_CHAINED",
        },
        ground_truth="BENIGN",
        is_mandatory=True,
    ),
}


def get_all_test_scenarios() -> list[dict[str, Any]]:
    return [
        {
            "test_id": s.test_id,
            "name": s.name,
            "category": s.category.value,
            "mitre_attack_id": s.mitre_attack_id,
            "nist_csf_id": s.nist_csf_id,
            "rbi_clause": s.rbi_clause,
            "certin_clause": s.certin_clause,
            "description": s.description,
            "is_mandatory": s.is_mandatory,
            "repeat_count": s.repeat_count,
        }
        for s in VERIFICATION_TEST_SUITE.values()
    ]
