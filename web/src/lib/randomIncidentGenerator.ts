/**
 * Dynamic Banking Cyber Crisis Incident Generator for CYBERQ.
 *
 * Synthesizes authentic Indian commercial banking cyber crisis incidents with
 * realistic IOCs, MITRE ATT&CK techniques, affected core assets, and statutory
 * obligations under CERT-In Directions 2022, RBI Master Directions 2026, and DPDP Rules 2025.
 */

import type { IncidentItem, ObligationItem, TriggerItem } from "../features/incidents/types"

export interface BankingCrisisTemplate {
  title: string
  summary: string
  severity: "low" | "medium" | "high" | "critical"
  affected_asset: string
  tool_source: string
  mitre_attack: string
  has_personal_data: boolean
  is_major: boolean
  auto_assert_trigger: boolean
  trigger_minutes_ago?: number
}

export const BANKING_INCIDENT_TEMPLATES: BankingCrisisTemplate[] = [
  {
    title: "UPI Switch API gateway timeout & suspicious callback flood",
    summary: "NPCI UPI payment gateway interface reporting >3,400 failed settlement callbacks per minute from unauthorized staging IP range 10.42.18.0/24. Circuit breaker tripped on Core Switch VIP to prevent ledger discrepancy. Memory dump initiated on payment orchestrator.",
    severity: "critical",
    affected_asset: "UPI-SWITCH-CORE-01",
    tool_source: "F5 BIG-IP WAF & Splunk SIEM",
    mitre_attack: "T1499.004 - Endpoint Denial of Service: Application Exhaustion",
    has_personal_data: false,
    is_major: true,
    auto_assert_trigger: true,
    trigger_minutes_ago: 12,
  },
  {
    title: "Unauthorized RMA message staging on SWIFT Alliance Gateway",
    summary: "Dual-custody bypass alert triggered on SWIFT Alliance Gateway SAG-02. An unapproved RMA (Relationship Management Application) key exchange message was staged outside treasury operating hours without secondary maker-checker authentication. SAG HSM link suspended.",
    severity: "critical",
    affected_asset: "SWIFT-SAG-02 / TREASURY-VLAN",
    tool_source: "Imperva DAM & CyberArk PAM",
    mitre_attack: "T1078.002 - Valid Accounts: Domain Accounts",
    has_personal_data: false,
    is_major: true,
    auto_assert_trigger: true,
    trigger_minutes_ago: 24,
  },
  {
    title: "ATM Switch ISO-8583 message response code tampering",
    summary: "Anomalous ISO-8583 Field 39 (Response Code) manipulation observed across 24 terminal endpoints in Western Region. Stand-in processing rules activated; terminal network quarantined by Switch HSM controller to avert unauthorized cash dispense.",
    severity: "high",
    affected_asset: "ATM-SWITCH-HSM-WR01",
    tool_source: "CrowdStrike Falcon & Switch Monitor",
    mitre_attack: "T1565.002 - Data Manipulation: Transmitted Data Manipulation",
    has_personal_data: false,
    is_major: false,
    auto_assert_trigger: true,
    trigger_minutes_ago: 35,
  },
  {
    title: "Bulk export of customer CIF and masked Aadhaar records via replica DB",
    summary: "Database Activity Monitoring (DAM) identified unindexed bulk SELECT query extracting 64,500 customer CIF records, registered mobile numbers, and masked Aadhaar references from CBS reporting replica. Personal data intimation clock under DPDP Rules 2025 initiated.",
    severity: "critical",
    affected_asset: "CORE-ORACLE-RAC-REPLICA",
    tool_source: "IBM Security Guardium DAM",
    mitre_attack: "T1530 - Data from Cloud/Local Storage Repositories",
    has_personal_data: true,
    is_major: true,
    auto_assert_trigger: true,
    trigger_minutes_ago: 8,
  },
  {
    title: "Active Directory Kerberoasting targeting Core Banking database service account",
    summary: "CrowdStrike Falcon detected Kerberos TGS-REQ ticket requests with legacy RC4 encryption targeting SPN 'MSSQLSvc/CBS-DB01.bank.local'. Immediate service account ticket revocation enforced; domain controller event ID 4769 flagged for forensic review.",
    severity: "high",
    affected_asset: "AD-DC-PRIMARY-01",
    tool_source: "CrowdStrike Falcon Enterprise",
    mitre_attack: "T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting",
    has_personal_data: false,
    is_major: false,
    auto_assert_trigger: false,
  },
  {
    title: "Corporate NetBanking login portal obfuscated SQL injection probe",
    summary: "High-entropy SQL injection vectors targeting session token verification endpoint /corp/auth/verifyToken detected across 1,200 distributed residential proxies. Cloudflare WAF and edge firewall applied dynamic rate-limiting; zero data breach confirmed.",
    severity: "medium",
    affected_asset: "NETBANK-PORTAL-VIP",
    tool_source: "Cloudflare Magic Transit & WAF",
    mitre_attack: "T1190 - Exploit Public-Facing Application",
    has_personal_data: false,
    is_major: false,
    auto_assert_trigger: false,
  },
  {
    title: "BGP route announcement hijack targeting Bank Forex Settlement API",
    summary: "External routing telemetry identified unauthorized AS-PATH advertisement for /24 public subnet allocated to Bank Forex Settlement gateway. Flow diverted to offshore autonomous system. Inbound peering dropped; route filtering re-advertised with upstream ISP.",
    severity: "critical",
    affected_asset: "BGP-BORDER-ROUTER-DC1",
    tool_source: "Palo Alto Networks Strata NGFW",
    mitre_attack: "T1584.004 - Compromise Infrastructure: Server",
    has_personal_data: false,
    is_major: true,
    auto_assert_trigger: true,
    trigger_minutes_ago: 18,
  },
  {
    title: "Ransomware precursor beaconing & PsExec lateral movement on Branch Subnet",
    summary: "SentinelOne agent flagged PsExec remote service creation on 14 regional branch workstations originating from loan processing terminal WS-BLR-041. Cobalt Strike beacon payload signature identified and quarantined via endpoint network isolation.",
    severity: "high",
    affected_asset: "BRANCH-LAN-BLR-ZONE",
    tool_source: "SentinelOne Singularity",
    mitre_attack: "T1021.002 - Remote Services: SMB/Windows Admin Shares",
    has_personal_data: false,
    is_major: false,
    auto_assert_trigger: true,
    trigger_minutes_ago: 40,
  },
  {
    title: "Payment Card Industry (PCI) HSM crypto zone master key sync timeout",
    summary: "Thales payShield HSM cluster failed periodic heartbeat key synchronization for RuPay Card Verification Value (CVV) generation. Fallback secondary HSM activated; diagnostic trace indicates packet jitter on optical interconnect.",
    severity: "medium",
    affected_asset: "HSM-CLUSTER-DC2",
    tool_source: "Internal HSM Cryptographic Monitor",
    mitre_attack: "T1499 - Endpoint Denial of Service",
    has_personal_data: false,
    is_major: false,
    auto_assert_trigger: false,
  },
  {
    title: "Production JWT bearer token discovered in public code repository",
    summary: "Automated secret scanner flagged hardcoded production JWT for third-party fintech lending partner on public git repository. Token invalidated immediately; IP whitelist enforced; access audit confirmed no unauthorized calls during exposure window.",
    severity: "medium",
    affected_asset: "LOAN-ORIGINATION-MICROSERVICE",
    tool_source: "GitHub Secret Scanning & Microsoft Sentinel",
    mitre_attack: "T1552.001 - Unsecured Credentials: Credentials In Files",
    has_personal_data: false,
    is_major: false,
    auto_assert_trigger: false,
  },
  {
    title: "RTGS message queue depth threshold breach during EOD settlement",
    summary: "Surge in high-value corporate RTGS settlement requests caused message broker queue depth to reach 94% capacity. Secondary message broker node brought online to balance partition load; zero payment failures recorded.",
    severity: "low",
    affected_asset: "RTGS-MQ-BROKER-01",
    tool_source: "IBM MQ Monitor & Splunk",
    mitre_attack: "T1499.003 - Endpoint Denial of Service",
    has_personal_data: false,
    is_major: false,
    auto_assert_trigger: false,
  },
  {
    title: "Volumetric UDP amplification DDoS probe against authoritative DNS",
    summary: "Inbound UDP 53 packet flood peaking at 68 Gbps directed at ns1.bank.co.in authoritative nameserver. ISP upstream scrubbers and Anycast edge filtering absorbed traffic; customer DNS resolution latency remained within 38ms SLA.",
    severity: "low",
    affected_asset: "AUTH-DNS-NS1",
    tool_source: "Cloudflare DDoS Protection",
    mitre_attack: "T1498.002 - Network Denial of Service: Reflection Amplification",
    has_personal_data: false,
    is_major: false,
    auto_assert_trigger: false,
  },
]

/**
 * Creates a brand new randomized incident with realistic statutory obligations
 * and timestamps.
 */
export function generateRandomIncident(
  existingIncidents: IncidentItem[],
  currentUserId: string = "analyst-01"
): IncidentItem {
  // Determine next incident sequence number
  const nextNum = existingIncidents.length + 1
  const incNumber = `INC-2026-${String(nextNum).padStart(4, "0")}`
  const now = new Date()
  const nowIso = now.toISOString()
  const uniqueId = `inc-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`

  // Pick a random template, avoiding the immediate last one if possible
  const templateIdx = Math.floor(Math.random() * BANKING_INCIDENT_TEMPLATES.length)
  const template = BANKING_INCIDENT_TEMPLATES[templateIdx]

  // Calculate occurred time (either just now or a few minutes in past)
  const minutesAgo = template.trigger_minutes_ago || Math.floor(Math.random() * 20) + 2
  const occurredDate = new Date(now.getTime() - minutesAgo * 60000)
  const occurredIso = occurredDate.toISOString()

  // 6h statutory deadline calculation for CERT-In & RBI
  const certinDeadlineIso = new Date(occurredDate.getTime() + 6 * 3600000).toISOString()
  const certinNextDueIso = new Date(new Date(certinDeadlineIso).getTime() - 4 * 3600000).toISOString()

  // 72h DPDP deadline calculation
  const dpdpDeadlineIso = new Date(occurredDate.getTime() + 72 * 3600000).toISOString()
  const dpdpNextDueIso = new Date(new Date(dpdpDeadlineIso).getTime() - 6 * 3600000).toISOString()

  const shouldAssert = template.auto_assert_trigger

  const triggers: TriggerItem[] = []
  if (shouldAssert) {
    triggers.push({
      id: `trig-not-${Date.now()}`,
      incident_id: uniqueId,
      trigger_type: "noticed",
      occurred_at: occurredIso,
      recorded_at: nowIso,
      asserted_by_id: currentUserId,
      evidence_summary: `Automated alert correlation from ${template.tool_source} confirmed operational impairment on ${template.affected_asset}.`,
      rationale: `Mandatory statutory notification trigger under CERT-In Directions 2022 Section 70B asserted.`,
      is_disputed: false,
    })
    triggers.push({
      id: `trig-det-${Date.now() + 1}`,
      incident_id: uniqueId,
      trigger_type: "detected",
      occurred_at: occurredIso,
      recorded_at: nowIso,
      asserted_by_id: currentUserId,
      evidence_summary: `Forensic detection telemetry from ${template.tool_source} verified security anomaly.`,
      rationale: `Statutory cyber incident reporting clock under RBI Master Direction 2026 Para 53 engaged.`,
      is_disputed: false,
    })

    if (template.has_personal_data) {
      triggers.push({
        id: `trig-awa-${Date.now() + 2}`,
        incident_id: uniqueId,
        trigger_type: "aware",
        occurred_at: occurredIso,
        recorded_at: nowIso,
        asserted_by_id: currentUserId,
        evidence_summary: `Personal data access alert confirmed potential exposure of customer records on ${template.affected_asset}.`,
        rationale: `Statutory data breach intimation obligation under DPDP Rules 2025 Rule 7 initiated.`,
        is_disputed: false,
      })
    }
  }

  const obligations: ObligationItem[] = [
    {
      id: `obl-certin-${uniqueId}`,
      incident_id: uniqueId,
      pack_id: "certin-directions-2022",
      regulator: "CERT-In",
      status: shouldAssert ? "running" : "pending_trigger",
      deadline_at: shouldAssert ? certinDeadlineIso : null,
      disputed_deadline_at: null,
      active_deadline_at: shouldAssert ? certinDeadlineIso : null,
      next_due_at: shouldAssert ? certinNextDueIso : null,
      escalation_level: 0,
      applicability_status: "assumed_applicable",
    },
    {
      id: `obl-rbi-${uniqueId}`,
      incident_id: uniqueId,
      pack_id: "rbi-cybersecurity-directions-2026",
      regulator: "RBI",
      status: shouldAssert ? "running" : "pending_trigger",
      deadline_at: shouldAssert ? certinDeadlineIso : null,
      disputed_deadline_at: null,
      active_deadline_at: shouldAssert ? certinDeadlineIso : null,
      next_due_at: shouldAssert ? certinNextDueIso : null,
      escalation_level: 0,
      applicability_status: "assumed_applicable",
    },
    {
      id: `obl-dpdp-${uniqueId}`,
      incident_id: uniqueId,
      pack_id: "dpdp-rules-2025",
      regulator: "DPDP",
      status: template.has_personal_data && shouldAssert ? "running" : "pending_trigger",
      deadline_at: template.has_personal_data && shouldAssert ? dpdpDeadlineIso : null,
      disputed_deadline_at: null,
      active_deadline_at: template.has_personal_data && shouldAssert ? dpdpDeadlineIso : null,
      next_due_at: template.has_personal_data && shouldAssert ? dpdpNextDueIso : null,
      escalation_level: 0,
      applicability_status: template.has_personal_data ? "assumed_applicable" : "not_in_force",
    },
  ]

  const newIncident: IncidentItem = {
    id: uniqueId,
    incident_number: incNumber,
    title: template.title,
    summary: `${template.summary}\n\n[Automated Telemetry Intake]\nSource: ${template.tool_source}\nTarget: ${template.affected_asset}\nMITRE: ${template.mitre_attack}`,
    severity: template.severity,
    status: shouldAssert ? "triaged" : "new",
    created_at: nowIso,
    updated_at: nowIso,
    created_by_id: currentUserId,
    is_major: template.is_major,
    major_declared_at: template.is_major ? nowIso : null,
    major_declared_by_id: template.is_major ? "ciso-01" : null,
    major_reason: template.is_major ? `High-impact commercial banking disruption on ${template.affected_asset}` : null,
    triggers,
    obligations,
  }

  return newIncident
}
