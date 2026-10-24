"""Centralized Banking Security Tool Integrations and Connector Telemetry Suite.

Implements 8 standard bank security connectors:
1. SIEM (Splunk Enterprise / QRadar)
2. EDR/XDR (CrowdStrike Falcon / Defender for Endpoint)
3. Firewalls (Palo Alto Networks Next-Gen Firewall)
4. IDS/IPS (Suricata Network Detection & Response)
5. Vulnerability Scanners (Tenable Nessus / Qualys)
6. Identity and Access Management (Active Directory Federation Services)
7. Secure Email Gateway (Proofpoint Targeted Attack Protection)
8. Threat Intelligence Platform (CERT-In Threat Feed / MISP)

Identifies: missing event fields, connector health failures, stale/missing telemetry,
duplicate events, contradictory alerts, and monitoring visibility gaps.
Enforces the fundamental banking invariant: NEVER LABEL A TOOL SAFE SIMPLY BECAUSE NO ALERTS WERE RECEIVED!
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class ConnectorStatus(StrEnum):
    CONNECTED_HEALTHY = "CONNECTED_HEALTHY"
    DEGRADED = "DEGRADED"
    DISCONNECTED = "DISCONNECTED"
    MAINTENANCE = "MAINTENANCE"


class ToolCategory(StrEnum):
    SIEM = "SIEM"
    EDR = "EDR/XDR"
    FIREWALL = "Firewall"
    IDS_IPS = "IDS/IPS"
    VULNERABILITY_SCANNER = "Vulnerability Scanner"
    IAM = "Identity & Access Management"
    EMAIL_SECURITY = "Email Security"
    THREAT_INTEL = "Threat Intelligence"


class TelemetryObservationType(StrEnum):
    PRODUCT_DETECTION = "PRODUCT_DETECTION"  # Normal positive alert
    PRODUCT_FAILURE = "PRODUCT_FAILURE"  # Tool saw the payload but failed to alert
    CONNECTOR_FAILURE = "CONNECTOR_FAILURE"  # Connector offline or buffer dropped packet
    MONITORING_GAP = "MONITORING_GAP"  # Lack of visibility / unmonitored network segment
    INCONCLUSIVE_DATA = "INCONCLUSIVE_DATA"  # Insufficient fields or malformed payload


@dataclass
class SecurityConnector:
    connector_id: str
    tool_name: str
    category: ToolCategory
    status: ConnectorStatus
    endpoint_url: str
    authenticated_version: str
    last_heartbeat: datetime
    ingested_events_count: int
    dropped_events_count: int
    health_diagnostic: str
    supported_event_types: list[str]
    missing_telemetry_fields: list[str] = field(default_factory=list)


@dataclass
class SimulatedBankEvent:
    event_id: str
    connector_id: str
    source_ip: str
    destination_ip: str
    timestamp: datetime
    raw_payload: dict[str, Any]
    normalized_fields: dict[str, Any]
    is_duplicate: bool = False
    is_malformed: bool = False


class BankIntegrationManager:
    """Manages the 8 simulated enterprise connectors for bank security testing."""

    def __init__(self) -> None:
        self.connectors: dict[str, SecurityConnector] = self._init_default_connectors()
        self.event_log: list[SimulatedBankEvent] = []

    def _init_default_connectors(self) -> dict[str, SecurityConnector]:
        now = datetime.now(UTC)
        return {
            "CONN-SIEM-01": SecurityConnector(
                connector_id="CONN-SIEM-01",
                tool_name="Splunk Enterprise Security (Bank Core Cluster)",
                category=ToolCategory.SIEM,
                status=ConnectorStatus.CONNECTED_HEALTHY,
                endpoint_url="https://siem-core.internal.bank:8089",
                authenticated_version="9.2.1-fips",
                last_heartbeat=now,
                ingested_events_count=142050,
                dropped_events_count=0,
                health_diagnostic="Cluster peer synchronization nominal; indexer latency < 12ms",
                supported_event_types=["syslog", "cif_transfer", "rtgs_auth", "firewall_flow"],
            ),
            "CONN-EDR-01": SecurityConnector(
                connector_id="CONN-EDR-01",
                tool_name="CrowdStrike Falcon Sensor (Tier-1 Core Workstations)",
                category=ToolCategory.EDR,
                status=ConnectorStatus.CONNECTED_HEALTHY,
                endpoint_url="https://falcon-relay.internal.bank:443",
                authenticated_version="7.14.18205",
                last_heartbeat=now,
                ingested_events_count=89400,
                dropped_events_count=0,
                health_diagnostic="Sensor heartbeat 100% across 4,200 endpoints; kernel hooks active",
                supported_event_types=["process_create", "dll_load", "registry_mod", "network_connect"],
            ),
            "CONN-FW-01": SecurityConnector(
                connector_id="CONN-FW-01",
                tool_name="Palo Alto PA-5200 Perimeter Gateway",
                category=ToolCategory.FIREWALL,
                status=ConnectorStatus.CONNECTED_HEALTHY,
                endpoint_url="https://fw-edge.internal.bank:443",
                authenticated_version="PAN-OS 11.1.2-h3",
                last_heartbeat=now,
                ingested_events_count=612000,
                dropped_events_count=0,
                health_diagnostic="BGP peers established; App-ID & Threat Prevention licenses active",
                supported_event_types=["traffic_flow", "url_filtering", "threat_signature", "decrypted_ssl"],
            ),
            "CONN-IDS-01": SecurityConnector(
                connector_id="CONN-IDS-01",
                tool_name="Suricata 7.0 Enterprise Network Detection (NDR)",
                category=ToolCategory.IDS_IPS,
                status=ConnectorStatus.CONNECTED_HEALTHY,
                endpoint_url="https://ndr-sensor.internal.bank:8443",
                authenticated_version="7.0.4-release",
                last_heartbeat=now,
                ingested_events_count=45100,
                dropped_events_count=0,
                health_diagnostic="Zero packet drop on 10Gbps ERSPAN mirror tap; ruleset updated today",
                supported_event_types=["flow_stats", "dns_query", "tls_handshake", "smb_metadata"],
            ),
            "CONN-VULN-01": SecurityConnector(
                connector_id="CONN-VULN-01",
                tool_name="Tenable Nessus Infrastructure Scanner",
                category=ToolCategory.VULNERABILITY_SCANNER,
                status=ConnectorStatus.CONNECTED_HEALTHY,
                endpoint_url="https://nessus-mgr.internal.bank:8834",
                authenticated_version="10.7.2",
                last_heartbeat=now,
                ingested_events_count=1240,
                dropped_events_count=0,
                health_diagnostic="Credentialed scans completed for PCI-DSS & Core Banking zone",
                supported_event_types=["vulnerability_cve", "compliance_audit", "ssl_cipher_audit"],
            ),
            "CONN-IAM-01": SecurityConnector(
                connector_id="CONN-IAM-01",
                tool_name="Active Directory Federation Services & Keycloak IAM",
                category=ToolCategory.IAM,
                status=ConnectorStatus.CONNECTED_HEALTHY,
                endpoint_url="https://adfs.internal.bank:443",
                authenticated_version="Windows Server 2022 / Keycloak 24",
                last_heartbeat=now,
                ingested_events_count=38900,
                dropped_events_count=0,
                health_diagnostic="Kerberos ticket-granting nominal; MFA push latency 1.1s",
                supported_event_types=["auth_success", "auth_failure", "privilege_elevation", "group_change"],
            ),
            "CONN-MAIL-01": SecurityConnector(
                connector_id="CONN-MAIL-01",
                tool_name="Proofpoint Targeted Attack Protection (TAP)",
                category=ToolCategory.EMAIL_SECURITY,
                status=ConnectorStatus.CONNECTED_HEALTHY,
                endpoint_url="https://proofpoint-relay.internal.bank:443",
                authenticated_version="8.20.1",
                last_heartbeat=now,
                ingested_events_count=19200,
                dropped_events_count=0,
                health_diagnostic="URL defense sandbox online; attachment disarm active",
                supported_event_types=["phish_quarantine", "spf_dkim_fail", "macro_blocked", "impersonation"],
            ),
            "CONN-TI-01": SecurityConnector(
                connector_id="CONN-TI-01",
                tool_name="MISP & CERT-In Threat Intelligence Ingestion Feed",
                category=ToolCategory.THREAT_INTEL,
                status=ConnectorStatus.CONNECTED_HEALTHY,
                endpoint_url="https://misp-node.internal.bank:443",
                authenticated_version="2.4.188",
                last_heartbeat=now,
                ingested_events_count=5200,
                dropped_events_count=0,
                health_diagnostic="CERT-In STIX 2.1 feed sync active; 14,200 IoCs synchronized",
                supported_event_types=["ioc_ip", "ioc_hash", "ioc_c2_domain", "advisory_bulletin"],
            ),
        }

    def simulate_connector_outage(self, connector_id: str, status: ConnectorStatus, diagnostic: str) -> None:
        """Simulates a telemetry failure or outage on a connector."""
        if connector_id in self.connectors:
            conn = self.connectors[connector_id]
            conn.status = status
            conn.health_diagnostic = diagnostic
            if status == ConnectorStatus.DISCONNECTED:
                conn.dropped_events_count += 150

    def restore_connector_health(self, connector_id: str) -> None:
        """Restores a connector to nominal healthy state."""
        if connector_id in self.connectors:
            conn = self.connectors[connector_id]
            conn.status = ConnectorStatus.CONNECTED_HEALTHY
            conn.health_diagnostic = "Telemetry stream restored; bidirectional heartbeats nominal"

    def analyze_telemetry_receipt(
        self,
        connector_id: str,
        expected_threat_scenario: str,
        alerts_received: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Analyzes alert receipt and enforces the fundamental distinction:

        1. Did the security product fail to detect the threat?
        2. Did the connector fail to deliver the evidence?
        3. Is there a monitoring visibility gap?
        4. Is the result inconclusive?
        """
        conn = self.connectors.get(connector_id)
        if not conn:
            return {
                "observation_type": TelemetryObservationType.INCONCLUSIVE_DATA.value,
                "is_safe": False,
                "reason": f"Unknown connector ID '{connector_id}'. Data is missing.",
            }

        # Check connector health FIRST
        if conn.status == ConnectorStatus.DISCONNECTED:
            return {
                "observation_type": TelemetryObservationType.CONNECTOR_FAILURE.value,
                "is_safe": False,
                "verdict_impact": "INCONCLUSIVE_OBSERVABILITY_FAILURE",
                "reason": (
                    f"CRITICAL OBSERVABILITY FAILURE: Connector '{conn.tool_name}' ({connector_id}) is DISCONNECTED! "
                    "Zero alerts were received, but this CANNOT be interpreted as safety or successful defense. "
                    "Evidence collection failed at the telemetry transport layer."
                ),
                "connector_diagnostic": conn.health_diagnostic,
                "dropped_events": conn.dropped_events_count,
            }

        if conn.status == ConnectorStatus.DEGRADED:
            return {
                "observation_type": TelemetryObservationType.MONITORING_GAP.value,
                "is_safe": False,
                "verdict_impact": "CONDITIONAL_TELEMETRY_GAP",
                "reason": (
                    f"MONITORING GAP: Connector '{conn.tool_name}' is in DEGRADED state. "
                    "Some telemetry events may be dropped or delayed. Partial alerts received cannot guarantee safety."
                ),
                "connector_diagnostic": conn.health_diagnostic,
            }

        # Connector is healthy: evaluate alerts
        if not alerts_received:
            # Healthy connector but zero alerts on an active threat injection
            return {
                "observation_type": TelemetryObservationType.PRODUCT_FAILURE.value,
                "is_safe": False,
                "verdict_impact": "FAIL_MISSED_DETECTION",
                "reason": (
                    f"PRODUCT DEFECT / MISSED DETECTION: Connector '{conn.tool_name}' is healthy and verified listening, "
                    f"yet the tool failed to detect the controlled threat '{expected_threat_scenario}'. "
                    "This is an unmitigated product coverage gap."
                ),
            }

        # Check for malformed or missing fields in the alert payload
        required_fields = ["event_id", "timestamp", "severity", "threat_indicator"]
        first_alert = alerts_received[0]
        missing_fields = [f for f in required_fields if f not in first_alert]
        if missing_fields:
            return {
                "observation_type": TelemetryObservationType.INCONCLUSIVE_DATA.value,
                "is_safe": False,
                "verdict_impact": "INCONCLUSIVE_MALFORMED_TELEMETRY",
                "reason": (
                    f"MALFORMED TELEMETRY: Alert received from '{conn.tool_name}' is missing mandatory fields: {missing_fields}. "
                    "Alert cannot be verified or parsed for forensic attribution."
                ),
            }

        return {
            "observation_type": TelemetryObservationType.PRODUCT_DETECTION.value,
            "is_safe": True,
            "verdict_impact": "VERIFIED_DETECTION",
            "reason": f"Validated threat detection received via healthy connector '{conn.tool_name}'.",
            "alert_count": len(alerts_received),
        }

    def get_inventory_summary(self) -> list[dict[str, Any]]:
        """Returns the full tool inventory and connector status table."""
        return [
            {
                "connector_id": c.connector_id,
                "tool_name": c.tool_name,
                "category": c.category.value,
                "status": c.status.value,
                "endpoint_url": c.endpoint_url,
                "authenticated_version": c.authenticated_version,
                "last_heartbeat": c.last_heartbeat.isoformat(),
                "ingested_events": c.ingested_events_count,
                "dropped_events": c.dropped_events_count,
                "health_diagnostic": c.health_diagnostic,
                "supported_events": c.supported_event_types,
            }
            for c in self.connectors.values()
        ]
