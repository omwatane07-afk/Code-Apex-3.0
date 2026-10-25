/**
 * Live Cybersecurity Telemetry Engine & Anomaly Scenario Catalog.
 *
 * Simulates real-time telemetry from enterprise cybersecurity tools (SIEM, EDR,
 * Firewall, DAM, PAM, WAF) and injects realistic banking crisis anomalies.
 */

export interface LiveAnomalyAlert {
  id: string
  tool_id: string
  tool_name: string
  category: string
  severity: "critical" | "high" | "warning" | "medium" | "low"
  title: string
  description: string
  timestamp: string
  anomalous_metric: string
  mitre_attack_id: string
  affected_asset: string
  response_status: "EXECUTED" | "PENDING_REVIEW" | "ENFORCED"
  automated_response: string
  acknowledged?: boolean
}

export interface ToolTelemetryMetrics {
  events_per_minute: number
  avg_latency_ms: number
  dropped_events: number
  cpu_usage_pct: number
  memory_usage_mb: number
  active_connections: number
}

export interface ToolTelemetryHealth {
  tool_id: string
  tool_name: string
  category: string
  trust_status: "TRUSTED" | "VERIFIED" | "EXPIRING_SOON" | "DEGRADED"
  health: "HEALTHY" | "WARNING" | "DEGRADED"
  alert_level: string
  active_anomaly?: string | null
  metrics: ToolTelemetryMetrics
  last_heartbeat: string
  uptime_hours: number
}

export const ANOMALY_SCENARIOS: LiveAnomalyAlert[] = [
  {
    id: "ANOM-CS-001",
    tool_id: "tool-edr-crowdstrike",
    tool_name: "CrowdStrike Falcon Enterprise",
    category: "EDR",
    severity: "critical",
    title: "Suspicious lateral movement via WMI detected on CBS-PROD-APP01",
    description: "svchost.exe spawned unauthorized powershell.exe attempting Mimikatz memory dump on RTGS payment gateway switch.",
    timestamp: new Date().toISOString(),
    anomalous_metric: "Memory read spike: 42,000 req/sec on LSASS",
    mitre_attack_id: "T1047 - WMI Execution",
    affected_asset: "RTGS-SWITCH-01 / CBS-PROD-APP01",
    response_status: "EXECUTED",
    automated_response: "Process terminated immediately. Host isolated via Falcon Containment API.",
  },
  {
    id: "ANOM-SPLUNK-002",
    tool_id: "tool-siem-splunk",
    tool_name: "Splunk Enterprise Security",
    category: "SIEM",
    severity: "critical",
    title: "Correlated credential brute-force against SWIFT Alliance Gateway",
    description: "Multi-origin authentication failure flood exceeding 10,000 attempts in 30 seconds targeting SWIFT SAG endpoints.",
    timestamp: new Date().toISOString(),
    anomalous_metric: "Auth failure rate: 334 events/sec (>10x baseline)",
    mitre_attack_id: "T1110.001 - Password Guessing",
    affected_asset: "SWIFT-ALLIANCE-GATEWAY",
    response_status: "EXECUTED",
    automated_response: "Offending subnets blacklisted on perimeter firewalls. Security Director alerted.",
  },
  {
    id: "ANOM-PAN-003",
    tool_id: "tool-fw-paloalto",
    tool_name: "Palo Alto Networks Strata NGFW",
    category: "Firewall",
    severity: "critical",
    title: "CVE-2024-3400 GlobalProtect Command Injection Exploit",
    description: "Inbound malicious payload exploiting arbitrary file creation on internet-facing edge firewall controller.",
    timestamp: new Date().toISOString(),
    anomalous_metric: "Inbound TCP RST spike on VPN interface",
    mitre_attack_id: "T1190 - Exploit Public-Facing Application",
    affected_asset: "PERIMETER-NGFW-PRIMARY",
    response_status: "EXECUTED",
    automated_response: "Connection reset, dynamic IPS signature deployed, edge interface isolated.",
  },
  {
    id: "ANOM-IMPERVA-004",
    tool_id: "tool-dam-imperva",
    tool_name: "Imperva SecureSphere DAM",
    category: "Database Security",
    severity: "high",
    title: "Mass SELECT query on customer KYC database table",
    description: "Unindexed bulk SELECT of 250,000 customer records from internal subnet outside core business banking hours.",
    timestamp: new Date().toISOString(),
    anomalous_metric: "DAM query rate: 1,450 rows/sec from single workstation",
    mitre_attack_id: "T1530 - Data from Cloud/Local Storage",
    affected_asset: "CORE-BANKING-ORACLE-RAC",
    response_status: "EXECUTED",
    automated_response: "Database session terminated. Account locked. DBA on-call paged.",
  },
  {
    id: "ANOM-CYBERARK-005",
    tool_id: "tool-pam-cyberark",
    tool_name: "CyberArk Privileged Access Manager",
    category: "IAM/PAM",
    severity: "high",
    title: "Privileged break-glass root access outside scheduled maintenance window",
    description: "Domain root credential retrieved from vault without emergency change ticket reference for UPI Switch core cluster.",
    timestamp: new Date().toISOString(),
    anomalous_metric: "Unapproved Vault Retrieval: domain_admin",
    mitre_attack_id: "T1078.003 - Valid Accounts: Local",
    affected_asset: "UPI-SWITCH-CLUSTER",
    response_status: "PENDING_REVIEW",
    automated_response: "Session keystroke recording initiated. CISO emergency notification dispatched.",
  },
  {
    id: "ANOM-S1-006",
    tool_id: "tool-edr-sentinelone",
    tool_name: "SentinelOne Singularity Complete",
    category: "EDR",
    severity: "critical",
    title: "Fileless memory malware detected: Invoke-Mimikatz in PowerShell",
    description: "In-memory AMSI bypass followed by reflective DLL injection in core banking workstation cluster.",
    timestamp: new Date().toISOString(),
    anomalous_metric: "EDR suspicious API call: VirtualAllocEx execute-write",
    mitre_attack_id: "T1003.001 - OS Credential Dumping: LSASS Memory",
    affected_asset: "BRANCH-WS-042",
    response_status: "EXECUTED",
    automated_response: "Process killed immediately. Network quarantine applied via SentinelOne agent.",
  },
  {
    id: "ANOM-F5-007",
    tool_id: "tool-waf-f5",
    tool_name: "F5 BIG-IP Advanced WAF",
    category: "WAF",
    severity: "medium",
    title: "SQL injection payload blocked on Internet Banking Login portal",
    description: "UNION SELECT statement injected into username parameter blocked at application proxy tier.",
    timestamp: new Date().toISOString(),
    anomalous_metric: "WAF Signature 200001478 triggered",
    mitre_attack_id: "T1190 - Exploit Public-Facing Application",
    affected_asset: "NETBANK-FRONTEND-VIP",
    response_status: "EXECUTED",
    automated_response: "HTTP 403 Forbidden returned to client. Source IP flagged in reputation feed.",
  },
  {
    id: "ANOM-SNORT-008",
    tool_id: "tool-legacy-ids-snort",
    tool_name: "Legacy Branch Perimeter NIDS (Snort v2)",
    category: "NIDS",
    severity: "warning",
    title: "Unverified telemetry: VAPT certificate expired under RBI Para 90",
    description: "Legacy perimeter sensor VAPT certification has expired. Tool trust status degraded to UNVERIFIED per statutory mandate.",
    timestamp: new Date().toISOString(),
    anomalous_metric: "Telemetry trust status: DEGRADED",
    mitre_attack_id: "T1595.002 - Vulnerability Scanning",
    affected_asset: "BRANCH-PERIMETER-NIDS",
    response_status: "PENDING_REVIEW",
    automated_response: "Telemetry flagged as unverified in evidence chain. Compliance review requested.",
  },
]

export const INITIAL_DEMO_TOOLS: ToolTelemetryHealth[] = [
  {
    tool_id: "tool-siem-splunk",
    tool_name: "Splunk Enterprise Security",
    category: "SIEM",
    trust_status: "TRUSTED",
    health: "HEALTHY",
    alert_level: "nominal",
    metrics: { events_per_minute: 1420, avg_latency_ms: 18, dropped_events: 0, cpu_usage_pct: 34.2, memory_usage_mb: 4096, active_connections: 24 },
    last_heartbeat: new Date().toISOString(),
    uptime_hours: 720,
  },
  {
    tool_id: "tool-edr-crowdstrike",
    tool_name: "CrowdStrike Falcon Enterprise",
    category: "EDR",
    trust_status: "TRUSTED",
    health: "HEALTHY",
    alert_level: "nominal",
    metrics: { events_per_minute: 2180, avg_latency_ms: 8, dropped_events: 0, cpu_usage_pct: 22.5, memory_usage_mb: 2048, active_connections: 18 },
    last_heartbeat: new Date().toISOString(),
    uptime_hours: 1440,
  },
  {
    tool_id: "tool-fw-paloalto",
    tool_name: "Palo Alto Networks Strata NGFW",
    category: "Firewall",
    trust_status: "TRUSTED",
    health: "HEALTHY",
    alert_level: "nominal",
    metrics: { events_per_minute: 5400, avg_latency_ms: 4, dropped_events: 0, cpu_usage_pct: 48.0, memory_usage_mb: 8192, active_connections: 42 },
    last_heartbeat: new Date().toISOString(),
    uptime_hours: 2160,
  },
  {
    tool_id: "tool-dam-imperva",
    tool_name: "Imperva SecureSphere DAM",
    category: "Database Security",
    trust_status: "TRUSTED",
    health: "HEALTHY",
    alert_level: "nominal",
    metrics: { events_per_minute: 890, avg_latency_ms: 12, dropped_events: 0, cpu_usage_pct: 28.4, memory_usage_mb: 3072, active_connections: 14 },
    last_heartbeat: new Date().toISOString(),
    uptime_hours: 960,
  },
  {
    tool_id: "tool-pam-cyberark",
    tool_name: "CyberArk Privileged Access Manager",
    category: "IAM/PAM",
    trust_status: "TRUSTED",
    health: "HEALTHY",
    alert_level: "nominal",
    metrics: { events_per_minute: 120, avg_latency_ms: 24, dropped_events: 0, cpu_usage_pct: 15.1, memory_usage_mb: 1536, active_connections: 8 },
    last_heartbeat: new Date().toISOString(),
    uptime_hours: 480,
  },
  {
    tool_id: "tool-siem-sentinel",
    tool_name: "Microsoft Sentinel",
    category: "SIEM",
    trust_status: "TRUSTED",
    health: "HEALTHY",
    alert_level: "nominal",
    metrics: { events_per_minute: 1650, avg_latency_ms: 22, dropped_events: 0, cpu_usage_pct: 31.0, memory_usage_mb: 3840, active_connections: 20 },
    last_heartbeat: new Date().toISOString(),
    uptime_hours: 1200,
  },
  {
    tool_id: "tool-edr-sentinelone",
    tool_name: "SentinelOne Singularity Complete",
    category: "EDR",
    trust_status: "TRUSTED",
    health: "HEALTHY",
    alert_level: "nominal",
    metrics: { events_per_minute: 1850, avg_latency_ms: 10, dropped_events: 0, cpu_usage_pct: 19.8, memory_usage_mb: 2048, active_connections: 16 },
    last_heartbeat: new Date().toISOString(),
    uptime_hours: 840,
  },
  {
    tool_id: "tool-waf-f5",
    tool_name: "F5 BIG-IP Advanced WAF",
    category: "WAF",
    trust_status: "TRUSTED",
    health: "HEALTHY",
    alert_level: "nominal",
    metrics: { events_per_minute: 3200, avg_latency_ms: 6, dropped_events: 0, cpu_usage_pct: 42.1, memory_usage_mb: 4096, active_connections: 32 },
    last_heartbeat: new Date().toISOString(),
    uptime_hours: 1800,
  },
  {
    tool_id: "tool-cspm-wiz",
    tool_name: "Wiz Cloud Security Platform",
    category: "Cloud Security",
    trust_status: "TRUSTED",
    health: "HEALTHY",
    alert_level: "nominal",
    metrics: { events_per_minute: 450, avg_latency_ms: 35, dropped_events: 0, cpu_usage_pct: 14.0, memory_usage_mb: 1024, active_connections: 6 },
    last_heartbeat: new Date().toISOString(),
    uptime_hours: 600,
  },
  {
    tool_id: "tool-fw-fortinet",
    tool_name: "Fortinet FortiGate Enterprise",
    category: "Firewall",
    trust_status: "TRUSTED",
    health: "HEALTHY",
    alert_level: "nominal",
    metrics: { events_per_minute: 4100, avg_latency_ms: 5, dropped_events: 0, cpu_usage_pct: 38.6, memory_usage_mb: 6144, active_connections: 36 },
    last_heartbeat: new Date().toISOString(),
    uptime_hours: 2400,
  },
  {
    tool_id: "tool-iam-entra",
    tool_name: "Microsoft Entra ID Governance",
    category: "IAM",
    trust_status: "TRUSTED",
    health: "HEALTHY",
    alert_level: "nominal",
    metrics: { events_per_minute: 980, avg_latency_ms: 19, dropped_events: 0, cpu_usage_pct: 21.3, memory_usage_mb: 2560, active_connections: 12 },
    last_heartbeat: new Date().toISOString(),
    uptime_hours: 1680,
  },
  {
    tool_id: "tool-legacy-ids-snort",
    tool_name: "Legacy Branch Perimeter NIDS (Snort v2)",
    category: "NIDS",
    trust_status: "DEGRADED",
    health: "DEGRADED",
    alert_level: "warning",
    metrics: { events_per_minute: 340, avg_latency_ms: 68, dropped_events: 12, cpu_usage_pct: 82.4, memory_usage_mb: 1024, active_connections: 4 },
    last_heartbeat: new Date().toISOString(),
    uptime_hours: 320,
  },
]
