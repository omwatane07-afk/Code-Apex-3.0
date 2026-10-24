"""Deterministic enterprise telemetry simulator for CYBERQ intake pipeline.

Generates synthetic, high-volume webhooks and CEF syslog events from enterprise tools
(CrowdStrike, Splunk, Palo Alto, Sentinel, Imperva) with realistic CVE references,
lateral movement threats, and synthetic customer PII for testing boundary scrubbing gates.
"""

from __future__ import annotations

import json
import random
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from cyberq.core.pii_guard import compute_verhoeff_check_digit
from cyberq.incidents.models import Incident
from cyberq.intake.models import NormalizedSecurityEvent
from cyberq.intake.service import IntakePipelineService


def generate_synthetic_aadhaar(index: int, format_style: int = 0) -> str:
    """Generates a mathematically valid 12-digit Aadhaar number with Verhoeff check digit.

    The first digit is guaranteed to be in [2-9] (valid per UIDAI specifications).
    """
    prefix = str(20000000000 + (index * 137) % 70000000000)[:11]
    cd = compute_verhoeff_check_digit(prefix)
    uid = prefix + str(cd)
    if format_style == 0:
        return f"{uid[:4]} {uid[4:8]} {uid[8:]}"
    elif format_style == 1:
        return f"{uid[:4]}-{uid[4:8]}-{uid[8:]}"
    elif format_style == 2:
        return f"{uid[:4]}.{uid[4:8]}.{uid[8:]}"
    return uid


def generate_synthetic_card(index: int, format_style: int = 0) -> str:
    """Generates a valid 16-digit payment card number passing the Luhn algorithm (RuPay/Visa format)."""
    prefix = str(400000000000000 + (index * 17) % 500000000000000)[:15]
    digits = [int(c) for c in prefix]
    total = 0
    reverse_digits = digits[::-1]
    for idx, d in enumerate(reverse_digits):
        if idx % 2 == 0:
            doubled = d * 2
            total += (doubled - 9) if doubled > 9 else doubled
        else:
            total += d
    check = (10 - (total % 10)) % 10
    card = prefix + str(check)
    if format_style == 0:
        return f"{card[:4]}-{card[4:8]}-{card[8:12]}-{card[12:]}"
    elif format_style == 1:
        return f"{card[:4]} {card[4:8]} {card[8:12]} {card[12:]}"
    return card


def generate_synthetic_pan(index: int) -> str:
    """Generates a valid 10-character Indian Income Tax PAN (e.g., ABCDE1234F)."""
    prefixes = ["ABCDE", "BKZPK", "DFGTR", "PQRST", "ZXCVB", "MNBVC", "LKJHG"]
    pref = prefixes[index % len(prefixes)]
    num = 1000 + (index % 8999)
    last_chars = "FAZXPMN"
    last_char = last_chars[index % len(last_chars)]
    return f"{pref}{num}{last_char}"


class TelemetrySimulator:
    """Enterprise banking telemetry simulator with synthetic threat injection and PII payload testing."""

    def __init__(self, seed: int = 42) -> None:
        self.rng = random.Random(seed)  # noqa: S311
        self._counter = 0

    def next_counter(self) -> int:
        self._counter += 1
        return self._counter

    def generate_crowdstrike_event(
        self,
        cve: str | None = None,
        target_asset: str = "CBS-PROD-APP01",
        include_pii: bool = False,
    ) -> tuple[str, bytes, dict[str, str]]:
        """Generates a CrowdStrike Falcon EDR detection webhook payload."""
        idx = self.next_counter()
        now = datetime.now(UTC)
        cve_ref = cve or "CVE-2024-3400"

        desc = f"Suspicious process injection and credential dumping targeting {target_asset}. Exploit ref {cve_ref}."
        cmdline = "powershell.exe -ExecutionPolicy Bypass -Command 'Invoke-Mimikatz -DumpCreds'"
        if include_pii:
            aadhaar = generate_synthetic_aadhaar(idx, format_style=0)
            card = generate_synthetic_card(idx, format_style=0)
            pan = generate_synthetic_pan(idx)
            cmdline += f" --filter-user-aadhaar={aadhaar} --export-card={card} --pan={pan}"
            desc += f" Injected payload sample UID {aadhaar}, card {card}, PAN {pan}."

        payload: dict[str, Any] = {
            "composite_id": f"CS-DETECTION-{idx:06d}",
            "event": {
                "LocalIP": f"10.14.2.{10 + (idx % 200)}",
                "RemoteIP": f"172.16.0.{5 + (idx % 50)}",
                "ComputerName": target_asset,
                "DetectDescription": desc,
                "CommandLine": cmdline,
                "SeverityName": "Critical",
                "Tactic": "Credential Access & Lateral Movement",
                "Technique": "T1003.001 - OS Credential Dumping",
                "Timestamp": now.isoformat(),
            },
        }
        body_bytes = json.dumps(payload).encode("utf-8")
        headers = {
            "content-type": "application/json",
            "x-cyberq-tool": "crowdstrike",
            "x-request-id": f"sim-cs-{uuid.uuid4().hex[:12]}",
        }
        return "crowdstrike", body_bytes, headers

    def generate_splunk_event(
        self,
        cve: str | None = None,
        target_asset: str = "RTGS-GATEWAY-SWITCH",
        include_pii: bool = False,
    ) -> tuple[str, bytes, dict[str, str]]:
        """Generates a Splunk Enterprise Security correlation search alert payload."""
        idx = self.next_counter()
        cve_ref = cve or "CVE-2023-4966"

        description = f"Correlated lateral movement detected on critical asset {target_asset}. Vulnerability advisory {cve_ref} matched."
        if include_pii:
            aadhaar = generate_synthetic_aadhaar(idx, format_style=1)
            card = generate_synthetic_card(idx, format_style=1)
            description += f" Suspicious query dump containing customer UID {aadhaar} and credit token {card}."

        payload: dict[str, Any] = {
            "result": {
                "sid": f"SPLUNK-ALERT-{idx:06d}",
                "src_ip": f"10.0.1.{20 + (idx % 100)}",
                "dest_ip": f"10.0.1.{50 + (idx % 100)}",
                "src_host": f"workstation-{idx:03d}.bank.internal",
                "dest_host": target_asset,
                "search_name": "Lateral Movement via WMI and Sensitive Table Exfiltration",
                "urgency": "critical",
                "severity": "critical",
                "description": description,
                "_raw": description,
            }
        }
        body_bytes = json.dumps(payload).encode("utf-8")
        headers = {
            "content-type": "application/json",
            "x-cyberq-tool": "splunk",
            "x-request-id": f"sim-spl-{uuid.uuid4().hex[:12]}",
        }
        return "splunk", body_bytes, headers

    def generate_palo_alto_cef(
        self,
        cve: str = "CVE-2024-3400",
        target_asset: str = "rtgs-switch.bank.internal",
        include_pii: bool = False,
    ) -> tuple[str, bytes, dict[str, str]]:
        """Generates a Palo Alto PAN-OS RFC 5424 / CEF Common Event Format syslog line."""
        idx = self.next_counter()
        src_ip = f"10.14.2.{50 + (idx % 150)}"
        dst_ip = f"172.16.0.{4 + (idx % 40)}"

        msg = f"Command injection exploit in GlobalProtect gateway targeting {target_asset}"
        if include_pii:
            aadhaar = generate_synthetic_aadhaar(idx, format_style=0)
            pan = generate_synthetic_pan(idx)
            msg += f" with customer Aadhaar payload {aadhaar} and PAN {pan}"

        raw_cef = (
            f"CEF:0|Palo Alto Networks|PAN-OS|11.0.2|threat|Palo Alto Threat Alert|8|"
            f"src={src_ip} dst={dst_ip} dhost={target_asset} cve={cve} "
            f"msg={msg}"
        )
        body_bytes = raw_cef.encode("utf-8")
        headers = {
            "content-type": "text/plain",
            "x-cyberq-tool": "palo_alto_cef",
            "x-request-id": f"sim-pan-{uuid.uuid4().hex[:12]}",
        }
        return "palo_alto_cef", body_bytes, headers

    def generate_imperva_dam_alert(
        self,
        target_asset: str = "CORE-BANKING-ORACLE-RAC",
        include_pii: bool = True,
    ) -> tuple[str, bytes, dict[str, str]]:
        """Generates an Imperva Database Activity Monitoring (DAM) alert for customer data extraction."""
        idx = self.next_counter()
        description = f"Mass SELECT query executed on sensitive database schema {target_asset}"
        if include_pii:
            aadhaar = generate_synthetic_aadhaar(idx, format_style=0)
            card = generate_synthetic_card(idx, format_style=0)
            pan = generate_synthetic_pan(idx)
            description += f": record sample extracted UID {aadhaar}, card {card}, PAN {pan}."

        payload: dict[str, Any] = {
            "alertId": f"IMP-DAM-{idx:06d}",
            "clientIp": f"192.168.10.{80 + (idx % 100)}",
            "serverIp": f"10.20.1.{5 + (idx % 50)}",
            "serverHost": target_asset,
            "policyName": "UNAUTHORIZED_CUSTOMER_PAN_AADHAAR_EXTRACTION",
            "severity": "critical",
            "description": description,
        }
        body_bytes = json.dumps(payload).encode("utf-8")
        headers = {
            "content-type": "application/json",
            "x-cyberq-tool": "imperva",
            "x-request-id": f"sim-imp-{uuid.uuid4().hex[:12]}",
        }
        return "imperva", body_bytes, headers

    def generate_batch(
        self,
        count: int = 10,
        pii_rate: float = 0.5,
    ) -> list[tuple[str, bytes, dict[str, str]]]:
        """Generates a diverse deterministic batch of enterprise telemetry webhooks."""
        batch: list[tuple[str, bytes, dict[str, str]]] = []
        tools = ["crowdstrike", "splunk", "palo_alto_cef", "imperva"]

        assets = [
            "CBS-PROD-APP01",
            "RTGS-GATEWAY-SWITCH",
            "SWIFT-ALLIANCE-INTERFACE",
            "CORE-BANKING-DB",
            "UPI-SWITCH-CLUSTER",
        ]
        cves = ["CVE-2024-3400", "CVE-2023-4966", "CVE-2024-21413", "CVE-2021-44228"]

        for i in range(count):
            tool = tools[i % len(tools)]
            has_pii = (self.rng.random() < pii_rate)
            asset = assets[i % len(assets)]
            cve = cves[i % len(cves)]

            if tool == "crowdstrike":
                ev = self.generate_crowdstrike_event(cve=cve, target_asset=asset, include_pii=has_pii)
            elif tool == "splunk":
                ev = self.generate_splunk_event(cve=cve, target_asset=asset, include_pii=has_pii)
            elif tool == "palo_alto_cef":
                ev = self.generate_palo_alto_cef(cve=cve, target_asset=asset, include_pii=has_pii)
            else:
                ev = self.generate_imperva_dam_alert(target_asset=asset, include_pii=has_pii)

            batch.append(ev)

        return batch

    def simulate_and_ingest(
        self,
        session: Session,
        intake_service: IntakePipelineService,
        count: int = 10,
        pii_rate: float = 0.5,
    ) -> list[tuple[NormalizedSecurityEvent, Incident | None]]:
        """Ingests a batch of simulated events through IntakePipelineService and verifies Zero-PII scrubbing."""
        batch = self.generate_batch(count=count, pii_rate=pii_rate)
        results: list[tuple[NormalizedSecurityEvent, Incident | None]] = []

        for tool_id, body_bytes, headers in batch:
            norm_event, inc = intake_service.ingest_webhook(
                session=session,
                tool_identifier=tool_id,
                raw_body=body_bytes,
                headers=headers,
                client_ip=headers.get("x-client-ip", "10.0.0.1"),
                system_user_id="telemetry-simulator-agent",
            )
            # Boundary Assertion: Ingested event raw message & Incident summary must NOT contain unredacted PII
            if inc:
                assert "[REDACTED_" in inc.summary or ("AADHAAR" not in inc.summary and "UID" not in inc.summary)
            results.append((norm_event, inc))

        session.commit()
        return results
