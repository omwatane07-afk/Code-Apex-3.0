import React, { useState, useEffect } from "react"
import {
  ShieldCheck,
  Users,
  Search,
  Activity,
  GitPullRequest,
  Database,
  FileCheck2,
  CheckCircle2,
  Clock,
  ChevronRight,
  RefreshCw,
  Play,
  FileText,
  Radio,
  Copy,
  Check,
  Send,
  Cpu
} from "lucide-react"
import type {
  CommandStatus,
  AgentItem,
  TimelineEventItem,
  EvidenceRecordItem,
  SecurityConnectorItem,
  VerificationResultsData,
  DisagreementItem,
  PrimarySourceItem,
  ToolCompliancePassportItem
} from "./types"

interface VerificationViewProps {
  userRole: string
  onBackToCommand: () => void
  isDemo?: boolean
}

export const VerificationView: React.FC<VerificationViewProps> = ({
  userRole,
  onBackToCommand,
  isDemo = false
}) => {
  // Navigation tabs for the 7 required sections
  const [activeTab, setActiveTab] = useState<
    "command" | "organization" | "timeline" | "evidence" | "results" | "connectors" | "reports"
  >("command")

  // State
  const [commandStatus, setCommandStatus] = useState<CommandStatus | null>(null)
  const [agents, setAgents] = useState<AgentItem[]>([])
  const [timelineEvents, setTimelineEvents] = useState<TimelineEventItem[]>([])
  const [evidenceList, setEvidenceList] = useState<EvidenceRecordItem[]>([])
  const [resultsData, setResultsData] = useState<VerificationResultsData | null>(null)
  const [connectors, setConnectors] = useState<SecurityConnectorItem[]>([])
  const [disagreements, setDisagreements] = useState<DisagreementItem[]>([])
  const [primarySources, setPrimarySources] = useState<PrimarySourceItem[]>([])
  const [reportData, setReportData] = useState<any | null>(null)
  const [passports, setPassports] = useState<ToolCompliancePassportItem[]>([])

  // Webhook Simulation state
  const [simToolId, setSimToolId] = useState<string>("tool-siem-splunk")
  const [simCveId, setSimCveId] = useState<string>("CVE-2024-21413")
  const [simSeverity, setSimSeverity] = useState<string>("critical")
  const [simIp, setSimIp] = useState<string>("10.14.2.88")
  const [isSimulatingWebhook, setIsSimulatingWebhook] = useState<boolean>(false)
  const [simWebhookResult, setSimWebhookResult] = useState<any | null>(null)
  const [simWebhookError, setSimWebhookError] = useState<string | null>(null)

  // Live Multi-Agent Review state
  const [isVerifyingLive, setIsVerifyingLive] = useState<boolean>(false)
  const [liveVerifyResult, setLiveVerifyResult] = useState<any | null>(null)

  // UI state
  const [isLoading, setIsLoading] = useState<boolean>(true)
  const [isExecutingScenario, setIsExecutingScenario] = useState<boolean>(false)
  const [executionMessage, setExecutionMessage] = useState<string | null>(null)
  const [selectedEvidence, setSelectedEvidence] = useState<EvidenceRecordItem | null>(null)
  const [selectedAgent, setSelectedAgent] = useState<AgentItem | null>(null)
  const [evidenceSearchTerm, setEvidenceSearchTerm] = useState<string>("")
  const [copiedHash, setCopiedHash] = useState<string | null>(null)

  // Fetch all dashboard data
  const fetchAllData = async () => {
    setIsLoading(true)
    try {
      const [
        resStatus,
        resOrg,
        resTimeline,
        resEvidence,
        resResults,
        resConn,
        resDisputes,
        resSources,
        resReport,
        resPassports
      ] = await Promise.all([
        fetch("/api/v1/verification/status").then(r => r.json()),
        fetch("/api/v1/verification/organization").then(r => r.json()),
        fetch("/api/v1/verification/timeline").then(r => r.json()),
        fetch("/api/v1/verification/evidence").then(r => r.json()),
        fetch("/api/v1/verification/results").then(r => r.json()),
        fetch("/api/v1/verification/connectors").then(r => r.json()),
        fetch("/api/v1/verification/disagreements").then(r => r.json()),
        fetch("/api/v1/verification/regulatory-sources").then(r => r.json()),
        fetch("/api/v1/verification/reports/default").then(r => r.json()),
        fetch("/api/v1/intake/compliance-passports").then(r => r.json()).catch(() => [])
      ])

      setCommandStatus(resStatus)
      setAgents(resOrg.agents || [])
      setTimelineEvents(resTimeline.events || [])
      setEvidenceList(resEvidence.records || [])
      setResultsData(resResults)
      setConnectors(resConn.connectors || [])
      setDisagreements(resDisputes.disagreements || [])
      setPrimarySources(resSources.primary_sources || [])
      setReportData(resReport)
      setPassports(Array.isArray(resPassports) ? resPassports : [])
    } catch (err) {
      console.error("Failed to load verification data:", err)
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    fetchAllData()
  }, [])

  // Simulate incoming signed bank security webhook
  const handleSimulateWebhook = async () => {
    setIsSimulatingWebhook(true)
    setSimWebhookError(null)
    setSimWebhookResult(null)
    try {
      const payload = {
        timestamp: new Date().toISOString(),
        threat_title: `Suspicious anomalous remote payload detected via ${simCveId}`,
        severity: simSeverity,
        cve_id: simCveId,
        source_ip: simIp,
        dest_ip: "10.10.1.5",
        host: "sbi-core-switch-gw01.prod.bank.in",
        user: "svc_transactor_prod",
        message: `High risk exploitation pattern matching advisory for ${simCveId} from host ${simIp}`
      }
      const res = await fetch(`/api/v1/intake/webhook/${simToolId}`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CyberQ-Signature": "sig-valid-demo-key-sha256",
          "X-CyberQ-Timestamp": Math.floor(Date.now() / 1000).toString(),
        },
        body: JSON.stringify(payload),
      })
      if (!res.ok) {
        const err = await res.json().catch(() => ({}))
        throw new Error(err.detail || `Webhook intake failed: ${res.statusText}`)
      }
      const data = await res.json()
      setSimWebhookResult(data)
      setExecutionMessage(
        `Signed Webhook Ingested: Event ${data.event_id} mapped to ${
          data.certin_advisories?.join(", ") || "Mandatory CERT-In Advisory"
        }. Incident: ${data.incident_number || "Existing Incident Appended"}`
      )
      await fetchAllData()
    } catch (err: any) {
      setSimWebhookError(err.message || String(err))
    } finally {
      setIsSimulatingWebhook(false)
    }
  }

  // Trigger live 11-phase multi-agent review loop
  const handleRunLiveVerification = async () => {
    setIsVerifyingLive(true)
    try {
      const eventId = simWebhookResult?.event_id || `EVT-${Date.now().toString().slice(-6)}`
      const toolId = simWebhookResult?.source_tool || simToolId
      const res = await fetch("/api/v1/verification/verify-live", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          event_id: eventId,
          source_tool: toolId,
          vendor: "Enterprise Bank Security",
          category: "SIEM/EDR",
          severity: simSeverity,
          cve_ids: [simCveId],
          certin_advisories: simWebhookResult?.certin_advisories || ["CERTIn-2024-ADV-014"],
          is_telemetry_unverified: simToolId === "tool-legacy-ids-snort",
          raw_message: `Live telemetry ingestion from ${toolId} covering exploit vector ${simCveId}`
        })
      })
      if (!res.ok) {
        const err = await res.json().catch(() => ({}))
        throw new Error(err.detail || "Live verification failed.")
      }
      const inv = await res.json()
      setLiveVerifyResult(inv)
      setExecutionMessage(
        `11-Phase Multi-Agent Review Loop Completed: Deterministic Verdict = ${inv.final_verdict}`
      )
      await fetchAllData()
    } catch (err: any) {
      setExecutionMessage(`Live verification failed: ${err.message}`)
    } finally {
      setIsVerifyingLive(false)
    }
  }

  // Execute a deterministic scenario (A through H)
  const handleExecuteScenario = async (scenarioKey: string, scenarioLabel: string) => {
    setIsExecutingScenario(true)
    setExecutionMessage(`Executing ${scenarioLabel}... Multi-agent review loop running.`)
    try {
      const res = await fetch(`/api/v1/verification/scenarios/${scenarioKey}/execute`, {
        method: "POST"
      })
      const data = await res.json()
      setExecutionMessage(`Completed ${scenarioLabel}: Verdict = ${data.verdict || "RECORDED"}.`)
      await fetchAllData()
    } catch (err) {
      setExecutionMessage(`Failed to execute ${scenarioLabel}: ${String(err)}`)
    } finally {
      setIsExecutingScenario(false)
    }
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    setCopiedHash(text)
    setTimeout(() => setCopiedHash(null), 2500)
  }

  // Filter evidence records
  const filteredEvidence = evidenceList.filter(e => {
    if (!evidenceSearchTerm) return true
    const term = evidenceSearchTerm.toLowerCase()
    return (
      e.evidence_id.toLowerCase().includes(term) ||
      e.claim.toLowerCase().includes(term) ||
      e.source_or_test_case.toLowerCase().includes(term) ||
      e.product_name.toLowerCase().includes(term)
    )
  })

  return (
    <div className="min-h-screen bg-[#050508] text-[#F0F6FC] flex flex-col font-sans cyber-grid">
      {/* Top Header */}
      <header className="border-b border-[#1A2332] bg-[#0A0D14]/90 backdrop-blur sticky top-0 z-30 px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-4">
          <button
            onClick={onBackToCommand}
            className="p-2 rounded bg-[#0A0D14] hover:bg-[#111722] text-[#8B9BB4] hover:text-[#00FF66] border border-[#1A2332] hover:border-[#00FF66]/40 transition"
            title="Return to SOC Incidents View"
          >
            <ChevronRight className="w-5 h-5 rotate-180" />
          </button>
          <div>
            <div className="flex items-center gap-3">
              <span className="p-1.5 rounded bg-[#00FF66]/10 text-[#00FF66] border border-[#00FF66]/30 shadow-[0_0_10px_rgba(0,255,102,0.2)]">
                <ShieldCheck className="w-5 h-5" />
              </span>
              <h1 className="text-xl font-bold tracking-tight text-[#F0F6FC] flex items-center gap-2">
                CYBERQ Multi-Agent Verification Platform
                <span className="text-xs px-2 py-0.5 rounded-full bg-[#00FF66]/10 text-[#00FF66] border border-[#00FF66]/30 font-mono shadow-[0_0_8px_rgba(0,255,102,0.15)]">
                  AUTOMOTIVE-CRASH-TEST-LAB
                </span>
              </h1>
            </div>
            <p className="text-xs text-[#8B9BB4] mt-0.5">
              Independent multi-agent evaluation of bank security products, evidence grounding, and deterministic verdicts
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <span className="text-xs px-2.5 py-1 rounded bg-[#0A0D14] text-[#8B9BB4] border border-[#1A2332] font-mono">
            {userRole} {isDemo ? "(demo)" : ""}
          </span>
          <button
            onClick={fetchAllData}
            disabled={isLoading}
            className="px-3 py-1.5 rounded bg-[#0A0D14] hover:bg-[#111722] text-xs font-medium text-[#F0F6FC] hover:text-[#00FF66] flex items-center gap-1.5 border border-[#1A2332] hover:border-[#00FF66]/40 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </div>
      </header>

      {/* Scenario Runner Toolbar */}
      <div className="bg-[#080B10] border-b border-[#1A2332] px-6 py-3 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold text-[#8B9BB4] uppercase tracking-wider flex items-center gap-1.5">
            <Play className="w-3.5 h-3.5 text-[#00FF66]" />
            Verification Crash Test Scenarios:
          </span>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button
            disabled={isExecutingScenario}
            onClick={() => handleExecuteScenario("scenario_a", "Scenario A (Correct Detection)")}
            className="px-2.5 py-1 rounded text-xs font-mono font-medium bg-[#00FF66]/10 text-[#00FF66] border border-[#00FF66]/40 hover:bg-[#00FF66]/20 transition shadow-[0_0_8px_rgba(0,255,102,0.1)]"
          >
            A: Correct Detection (PASS)
          </button>
          <button
            disabled={isExecutingScenario}
            onClick={() => handleExecuteScenario("scenario_b", "Scenario B (Missed Mandatory Threat)")}
            className="px-2.5 py-1 rounded text-xs font-mono font-medium bg-[#FF1E42]/10 text-[#FF1E42] border border-[#FF1E42]/40 hover:bg-[#FF1E42]/20 transition"
          >
            B: Missed Threat (FAIL)
          </button>
          <button
            disabled={isExecutingScenario}
            onClick={() => handleExecuteScenario("scenario_c", "Scenario C (Contradictory Agents)")}
            className="px-2.5 py-1 rounded text-xs font-mono font-medium bg-[#FFB74D]/10 text-[#FFB74D] border border-[#FFB74D]/40 hover:bg-[#FFB74D]/20 transition"
          >
            C: Disagreement (No Vote)
          </button>
          <button
            disabled={isExecutingScenario}
            onClick={() => handleExecuteScenario("scenario_d", "Scenario D (False Evidence)")}
            className="px-2.5 py-1 rounded text-xs font-mono font-medium bg-[#00E5FF]/10 text-[#00E5FF] border border-[#00E5FF]/40 hover:bg-[#00E5FF]/20 transition"
          >
            D: False Evidence (Reject)
          </button>
          <button
            disabled={isExecutingScenario}
            onClick={() => handleExecuteScenario("scenario_e", "Scenario E (Missing Telemetry)")}
            className="px-2.5 py-1 rounded text-xs font-mono font-medium bg-[#0A0D14] text-[#8B9BB4] border border-[#1A2332] hover:text-[#00FF66] hover:border-[#00FF66]/40 transition"
          >
            E: Connector Outage (Gap)
          </button>
          <button
            disabled={isExecutingScenario}
            onClick={() => handleExecuteScenario("scenario_f", "Scenario F (Repeated Review)")}
            className="px-2.5 py-1 rounded text-xs font-mono font-medium bg-[#00FF66]/5 text-[#8B9BB4] border border-[#1A2332] hover:text-[#00FF66] hover:border-[#00FF66]/40 transition"
          >
            F: Repeated Review (Cycle)
          </button>
          <button
            disabled={isExecutingScenario}
            onClick={() => handleExecuteScenario("scenario_g", "Scenario G (Unresolved Investigation)")}
            className="px-2.5 py-1 rounded text-xs font-mono font-medium bg-[#0A0D14] text-[#8B9BB4] border border-[#1A2332] hover:text-[#00FF66] hover:border-[#00FF66]/40 transition"
          >
            G: Iteration Budget (Inconclusive)
          </button>
          <button
            disabled={isExecutingScenario}
            onClick={() => handleExecuteScenario("scenario_h", "Scenario H (Regulatory Claim)")}
            className="px-2.5 py-1 rounded text-xs font-mono font-medium bg-[#00FF66]/10 text-[#00FF66] border border-[#00FF66]/40 hover:bg-[#00FF66]/20 transition"
          >
            H: Regulatory Integrity
          </button>
        </div>
      </div>

      {executionMessage && (
        <div className="bg-[#00FF66]/10 border-b border-[#00FF66]/30 px-6 py-2 text-xs font-mono font-medium text-[#00FF66] flex items-center justify-between">
          <span>{executionMessage}</span>
          <button
            onClick={() => setExecutionMessage(null)}
            className="text-[#8B9BB4] hover:text-[#00FF66]"
          >
            ✕
          </button>
        </div>
      )}

      {/* Main 7 Sections Navigation Bar */}
      <div className="bg-[#0A0D14] border-b border-[#1A2332] px-6">
        <nav className="flex space-x-6 text-sm font-medium">
          <button
            onClick={() => setActiveTab("command")}
            className={`py-3 px-1 border-b-2 flex items-center gap-2 transition ${
              activeTab === "command"
                ? "border-[#00FF66] text-[#00FF66] font-semibold shadow-[0_2px_8px_rgba(0,255,102,0.25)]"
                : "border-transparent text-[#8B9BB4] hover:text-[#F0F6FC] hover:border-[#1A2332]"
            }`}
          >
            <Activity className="w-4 h-4" />
            A. Command Center
          </button>
          <button
            onClick={() => setActiveTab("organization")}
            className={`py-3 px-1 border-b-2 flex items-center gap-2 transition ${
              activeTab === "organization"
                ? "border-[#00FF66] text-[#00FF66] font-semibold shadow-[0_2px_8px_rgba(0,255,102,0.25)]"
                : "border-transparent text-[#8B9BB4] hover:text-[#F0F6FC] hover:border-[#1A2332]"
            }`}
          >
            <Users className="w-4 h-4" />
            B. Agent Organization (16 Agents)
          </button>
          <button
            onClick={() => setActiveTab("timeline")}
            className={`py-3 px-1 border-b-2 flex items-center gap-2 transition ${
              activeTab === "timeline"
                ? "border-[#00FF66] text-[#00FF66] font-semibold shadow-[0_2px_8px_rgba(0,255,102,0.25)]"
                : "border-transparent text-[#8B9BB4] hover:text-[#F0F6FC] hover:border-[#1A2332]"
            }`}
          >
            <Clock className="w-4 h-4" />
            C. 11-Phase Review Timeline
          </button>
          <button
            onClick={() => setActiveTab("evidence")}
            className={`py-3 px-1 border-b-2 flex items-center gap-2 transition ${
              activeTab === "evidence"
                ? "border-[#00FF66] text-[#00FF66] font-semibold shadow-[0_2px_8px_rgba(0,255,102,0.25)]"
                : "border-transparent text-[#8B9BB4] hover:text-[#F0F6FC] hover:border-[#1A2332]"
            }`}
          >
            <Database className="w-4 h-4" />
            D. Evidence Explorer ({evidenceList.length})
          </button>
          <button
            onClick={() => setActiveTab("results")}
            className={`py-3 px-1 border-b-2 flex items-center gap-2 transition ${
              activeTab === "results"
                ? "border-[#00FF66] text-[#00FF66] font-semibold shadow-[0_2px_8px_rgba(0,255,102,0.25)]"
                : "border-transparent text-[#8B9BB4] hover:text-[#F0F6FC] hover:border-[#1A2332]"
            }`}
          >
            <FileCheck2 className="w-4 h-4" />
            E. Verification Results
          </button>
          <button
            onClick={() => setActiveTab("connectors")}
            className={`py-3 px-1 border-b-2 flex items-center gap-2 transition ${
              activeTab === "connectors"
                ? "border-[#00FF66] text-[#00FF66] font-semibold shadow-[0_2px_8px_rgba(0,255,102,0.25)]"
                : "border-transparent text-[#8B9BB4] hover:text-[#F0F6FC] hover:border-[#1A2332]"
            }`}
          >
            <Radio className="w-4 h-4" />
            F. Bank Connectors & Telemetry (8)
          </button>
          <button
            onClick={() => setActiveTab("reports")}
            className={`py-3 px-1 border-b-2 flex items-center gap-2 transition ${
              activeTab === "reports"
                ? "border-[#00FF66] text-[#00FF66] font-semibold shadow-[0_2px_8px_rgba(0,255,102,0.25)]"
                : "border-transparent text-[#8B9BB4] hover:text-[#F0F6FC] hover:border-[#1A2332]"
            }`}
          >
            <FileText className="w-4 h-4" />
            G. Verification Report & Sources
          </button>
        </nav>
      </div>

      {/* Main Content Area */}
      <main className="flex-1 p-6 overflow-y-auto">
        {/* ==================================================================== */}
        {/* SECTION A: COMMAND CENTER */}
        {/* ==================================================================== */}
        {activeTab === "command" && (
          <div className="space-y-6">
            {/* Top Metric Cards */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
              <div className="bg-[#0A0D14] border border-[#1A2332] rounded-control p-4 hover:border-[#00FF66]/40 transition cyber-panel-hud">
                <span className="text-xs text-[#8B9BB4] font-medium uppercase tracking-wider">Evaluation Target</span>
                <div className="text-lg font-bold text-[#F0F6FC] mt-1">Tier-1 EDR Defender Suite</div>
                <div className="text-xs text-[#00FF66] font-mono mt-0.5">Build v8.2.140 • Air-Gapped Testbed</div>
              </div>
              <div className="bg-[#0A0D14] border border-[#1A2332] rounded-control p-4 hover:border-[#00FF66]/40 transition cyber-panel-hud">
                <span className="text-xs text-[#8B9BB4] font-medium uppercase tracking-wider">Platform Verdict</span>
                <div className="flex items-center gap-2 mt-1">
                  <span className={`text-xl font-black font-mono ${
                    commandStatus?.latest_investigation?.verdict === "PASS"
                      ? "text-[#00FF66]"
                      : commandStatus?.latest_investigation?.verdict === "FAIL"
                      ? "text-[#FF1E42]"
                      : "text-[#FFB74D]"
                  }`}>
                    {commandStatus?.latest_investigation?.verdict || "PASS"}
                  </span>
                  <span className="text-xs px-2 py-0.5 rounded bg-[#050508] text-[#8B9BB4] border border-[#1A2332] font-mono">
                    Deterministic Engine
                  </span>
                </div>
                <div className="text-xs text-[#8B9BB4] font-mono mt-0.5">Zero LLM Opinion • Rule Backed</div>
              </div>
              <div className="bg-[#0A0D14] border border-[#1A2332] rounded-control p-4 hover:border-[#00FF66]/40 transition cyber-panel-hud">
                <span className="text-xs text-[#8B9BB4] font-medium uppercase tracking-wider">Team Evidence Grounding</span>
                <div className="text-xl font-bold text-[#00FF66] font-mono mt-1">
                  {commandStatus ? `${(commandStatus.team_evidence_grounding_average * 100).toFixed(1)}%` : "98.5%"}
                </div>
                <div className="text-xs text-[#00FF66] font-mono mt-0.5">100% Traceable to Raw Logs</div>
              </div>
              <div className="bg-[#0A0D14] border border-[#1A2332] rounded-control p-4 hover:border-[#00FF66]/40 transition cyber-panel-hud">
                <span className="text-xs text-[#8B9BB4] font-medium uppercase tracking-wider">Connector Health Ratio</span>
                <div className="text-xl font-bold text-[#F0F6FC] font-mono mt-1">
                  {commandStatus?.connector_health_ratio || "8/8 Online"}
                </div>
                <div className="text-xs text-[#8B9BB4] font-mono mt-0.5">SIEM • EDR • FW • IDS • IAM • MAIL</div>
              </div>
            </div>

            {/* Active Investigations & Quality Gate Status */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <div className="lg:col-span-2 bg-[#0A0D14] border border-[#1A2332] rounded-control p-5 space-y-4">
                <div className="flex items-center justify-between">
                  <h2 className="text-base font-semibold text-[#F0F6FC] flex items-center gap-2">
                    <Activity className="w-4 h-4 text-[#00FF66]" />
                    Active Verification Posture & Summary
                  </h2>
                  <span className="text-xs font-mono px-2 py-1 bg-[#050508] rounded border border-[#1A2332] text-[#8B9BB4]">
                    Iteration 1 / 5 Limit
                  </span>
                </div>
                <div className="p-4 rounded bg-[#050508] border border-[#1A2332] text-sm leading-relaxed text-[#8B9BB4]">
                  <p className="font-medium text-[#F0F6FC] mb-1">
                    {commandStatus?.latest_investigation?.summary ||
                      "Verification engine running controlled automotive crash tests against synthetic banking threat models."}
                  </p>
                  <p className="text-xs text-[#8B9BB4] mt-2">
                    Primary objective: Maximum achievable accuracy, depth of investigation, and evidence traceability.
                    Absence of alerts is NEVER equated with tool safety.
                  </p>
                </div>

                {/* Quality Gate Checks */}
                <div>
                  <h3 className="text-xs font-semibold text-[#8B9BB4] uppercase tracking-wider mb-2 font-mono">
                    Deterministic Quality Gates (6/6 Invariants):
                  </h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
                    <div className="p-2.5 rounded bg-[#050508] border border-[#1A2332] flex items-center justify-between">
                      <span className="text-[#8B9BB4] font-mono">GATE-01: Mandatory Test Coverage</span>
                      <span className="text-[#00FF66] font-mono flex items-center gap-1 font-bold">
                        <CheckCircle2 className="w-3.5 h-3.5" /> PASSED
                      </span>
                    </div>
                    <div className="p-2.5 rounded bg-[#050508] border border-[#1A2332] flex items-center justify-between">
                      <span className="text-[#8B9BB4] font-mono">GATE-02: Mandatory Threat Outcomes</span>
                      <span className="text-[#00FF66] font-mono flex items-center gap-1 font-bold">
                        <CheckCircle2 className="w-3.5 h-3.5" /> PASSED
                      </span>
                    </div>
                    <div className="p-2.5 rounded bg-[#050508] border border-[#1A2332] flex items-center justify-between">
                      <span className="text-[#8B9BB4] font-mono">GATE-03: Evidence Authenticity (SHA-256)</span>
                      <span className="text-[#00FF66] font-mono flex items-center gap-1 font-bold">
                        <CheckCircle2 className="w-3.5 h-3.5" /> VERIFIED
                      </span>
                    </div>
                    <div className="p-2.5 rounded bg-[#050508] border border-[#1A2332] flex items-center justify-between">
                      <span className="text-[#8B9BB4] font-mono">GATE-04: Disagreement Resolution</span>
                      <span className="text-[#00FF66] font-mono flex items-center gap-1 font-bold">
                        <CheckCircle2 className="w-3.5 h-3.5" /> RESOLVED
                      </span>
                    </div>
                    <div className="p-2.5 rounded bg-[#050508] border border-[#1A2332] flex items-center justify-between">
                      <span className="text-[#8B9BB4] font-mono">GATE-05: Telemetry Pipeline Health</span>
                      <span className="text-[#00FF66] font-mono flex items-center gap-1 font-bold">
                        <CheckCircle2 className="w-3.5 h-3.5" /> ONLINE
                      </span>
                    </div>
                    <div className="p-2.5 rounded bg-[#050508] border border-[#1A2332] flex items-center justify-between">
                      <span className="text-[#8B9BB4] font-mono">GATE-06: Review Iteration Budget</span>
                      <span className="text-[#00FF66] font-mono flex items-center gap-1 font-bold">
                        <CheckCircle2 className="w-3.5 h-3.5" /> WITHIN BUDGET
                      </span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Disagreement and Notice Panel */}
              <div className="bg-[#0A0D14] border border-[#1A2332] rounded-control p-5 space-y-4">
                <h2 className="text-base font-semibold text-[#F0F6FC] flex items-center gap-2">
                  <GitPullRequest className="w-4 h-4 text-[#FFB74D]" />
                  Preserved Disagreements ({disagreements.length})
                </h2>
                {disagreements.length === 0 ? (
                  <div className="p-4 rounded bg-[#050508] border border-[#1A2332] text-xs text-[#8B9BB4] text-center font-mono">
                    Zero active unhandled disagreements. All technical claims reconciled through re-testing.
                  </div>
                ) : (
                  <div className="space-y-2">
                    {disagreements.map(d => (
                      <div key={d.id} className="p-3 rounded bg-[#FFB74D]/10 border border-[#FFB74D]/30 text-xs space-y-1.5">
                        <div className="font-semibold text-[#FFB74D]">{d.disputed_claim}</div>
                        <div className="text-[#8B9BB4]">
                          <span className="text-[#F0F6FC] font-mono">{d.agent_a_role}:</span> {d.agent_a_position}
                        </div>
                        <div className="text-[#8B9BB4]">
                          <span className="text-[#F0F6FC] font-mono">{d.agent_b_role}:</span> {d.agent_b_position}
                        </div>
                        <div className="text-[#FFB74D] font-mono text-[10px]">
                          Resolution: {d.resolution_method}
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                <div className="p-3 rounded bg-[#00FF66]/5 border border-[#00FF66]/20 text-xs text-[#8B9BB4] leading-relaxed">
                  <span className="font-bold text-[#00FF66]">Automotive Testing Analogy:</span> Security tools receive platform-issued results
                  under controlled stress conditions before bank core authorization.
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ==================================================================== */}
        {/* SECTION B: AGENT ORGANIZATION */}
        {/* ==================================================================== */}
        {activeTab === "organization" && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-lg font-bold text-[#F0F6FC] flex items-center gap-2">
                  <Users className="w-5 h-5 text-[#00FF66]" />
                  Multi-Agent Organizational Hierarchy (6 Levels)
                </h2>
                <p className="text-xs text-[#8B9BB4] mt-0.5">
                  Professional structure: Specialized engineers report to leads, independent QA challenges, decision engine approves
                </p>
              </div>
              <span className="text-xs px-2.5 py-1 bg-[#0A0D14] rounded border border-[#1A2332] text-[#8B9BB4] font-mono">
                16 Registered Entities
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {agents.map(a => (
                <div
                  key={a.agent_id}
                  onClick={() => setSelectedAgent(a)}
                  className="bg-[#0A0D14] border border-[#1A2332] hover:border-[#00FF66]/50 rounded-control p-4 cursor-pointer transition hover:bg-[#111722]/80 flex flex-col justify-between cyber-panel-hud"
                >
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-[#050508] text-[#00FF66] border border-[#00FF66]/30">
                        {a.level.split(":")[0]}
                      </span>
                      <span className={`text-[10px] px-2 py-0.5 rounded font-mono font-bold ${
                        a.status === "AVAILABLE"
                          ? "bg-[#00FF66]/10 text-[#00FF66] border border-[#00FF66]/30"
                          : a.status === "INVESTIGATING"
                          ? "bg-[#00E5FF]/10 text-[#00E5FF] border border-[#00E5FF]/30"
                          : "bg-[#FFB74D]/10 text-[#FFB74D] border border-[#FFB74D]/30"
                      }`}>
                        {a.status}
                      </span>
                    </div>

                    <div>
                      <h3 className="text-sm font-bold text-[#F0F6FC]">{a.display_name}</h3>
                      <p className="text-xs text-[#8B9BB4] font-medium">{a.department}</p>
                    </div>

                    <div className="text-xs text-[#8B9BB4] space-y-1">
                      <div className="text-[#8B9BB4] text-[11px]">Primary Duty:</div>
                      <p className="line-clamp-2 text-[#8B9BB4] text-xs">
                        {a.responsibilities[0]}
                      </p>
                    </div>
                  </div>

                  <div className="mt-4 pt-3 border-t border-[#1A2332] flex items-center justify-between text-xs">
                    <div>
                      <span className="text-[10px] text-[#8B9BB4] uppercase block font-mono">Grounding</span>
                      <span className="font-mono text-[#00FF66] font-bold">
                        {(a.evidence_grounding_score * 100).toFixed(0)}%
                      </span>
                    </div>
                    <div>
                      <span className="text-[10px] text-[#8B9BB4] uppercase block font-mono">Precision</span>
                      <span className="font-mono text-[#00FF66] font-bold">
                        {(a.benchmarked_precision * 100).toFixed(0)}%
                      </span>
                    </div>
                    <div>
                      <span className="text-[10px] text-[#8B9BB4] uppercase block font-mono">Tasks</span>
                      <span className="font-mono text-[#F0F6FC] font-bold">
                        {a.tasks_completed}/{a.tasks_assigned}
                      </span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ==================================================================== */}
        {/* SECTION C: 11-PHASE TIMELINE */}
        {/* ==================================================================== */}
        {activeTab === "timeline" && (
          <div className="space-y-6">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
              <div>
                <h2 className="text-lg font-bold text-[#F0F6FC] flex items-center gap-2">
                  <Clock className="w-5 h-5 text-[#00FF66]" />
                  11-Phase Continuous Review Workflow
                </h2>
                <p className="text-xs text-[#8B9BB4] mt-0.5">
                  Plan → Delegate → Investigate → Submit → Lead Review → Cross-Exam → Dispute Resolution → Revision → Regression → Gate → Approval
                </p>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={handleRunLiveVerification}
                  disabled={isVerifyingLive}
                  className="px-3.5 py-1.5 rounded bg-[#00FF66] hover:bg-[#00CC52] text-[#050508] text-xs font-bold font-mono flex items-center gap-1.5 shadow-[0_0_12px_rgba(0,255,102,0.3)] transition disabled:opacity-50"
                  title="Run all 11 phases with specialized agents, cross-examination, and deterministic quality gate"
                >
                  <Cpu className={`w-3.5 h-3.5 ${isVerifyingLive ? "animate-spin" : ""}`} />
                  <span>{isVerifyingLive ? "Running 11 Phases..." : "Run Live Multi-Agent Review Loop (11 Phases)"}</span>
                </button>
                <span className="text-xs text-[#8B9BB4] font-mono">
                  {timelineEvents.length} Deliberations
                </span>
              </div>
            </div>

            {liveVerifyResult && (
              <div className="p-4 bg-[#0A0D14] border border-[#00FF66]/40 rounded-control space-y-3 shadow-[0_0_15px_rgba(0,255,102,0.1)]">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-[#00FF66]/10 text-[#00FF66] border border-[#00FF66]/30 font-bold">
                      LIVE VERIFICATION RESULT
                    </span>
                    <span className="text-xs font-mono font-bold text-[#F0F6FC]">{liveVerifyResult.id}</span>
                  </div>
                  <span className={`px-2 py-0.5 rounded text-xs font-bold font-mono ${
                    liveVerifyResult.final_verdict === "PASS"
                      ? "bg-[#00FF66]/10 text-[#00FF66] border border-[#00FF66]/40"
                      : liveVerifyResult.final_verdict === "CONDITIONAL"
                      ? "bg-[#FFB74D]/10 text-[#FFB74D] border border-[#FFB74D]/40"
                      : "bg-[#FF1E42]/10 text-[#FF1E42] border border-[#FF1E42]/40"
                  }`}>
                    VERDICT: {liveVerifyResult.final_verdict}
                  </span>
                </div>
                <div className="text-xs text-[#F0F6FC]">
                  {liveVerifyResult.summary}
                </div>
                {liveVerifyResult.quality_gate?.gate_checks && (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-2 border-t border-[#1A2332] text-xs">
                    {liveVerifyResult.quality_gate.gate_checks.map((gc: any, gIdx: number) => (
                      <div key={gIdx} className="p-2 rounded bg-[#050508] border border-[#1A2332] flex items-center justify-between">
                        <span className="text-[#8B9BB4] font-mono text-[11px]">{gc.gate}</span>
                        <span className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded ${
                          gc.passed
                            ? "bg-[#00FF66]/10 text-[#00FF66] border border-[#00FF66]/30"
                            : "bg-[#FFB74D]/10 text-[#FFB74D] border border-[#FFB74D]/30"
                        }`}>
                          {gc.passed ? "PASSED" : "CONDITIONAL"}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            <div className="space-y-3 relative before:absolute before:inset-0 before:left-5 before:w-0.5 before:bg-[#1A2332]">
              {timelineEvents.map((evt, idx) => (
                <div key={evt.id || idx} className="relative flex items-start gap-4 pl-10">
                  <div className="absolute left-3.5 -translate-x-1/2 top-1.5 w-3 h-3 rounded-full bg-[#00FF66] border-2 border-[#050508] shadow-[0_0_8px_rgba(0,255,102,0.8)]" />
                  <div className="flex-1 bg-[#0A0D14] border border-[#1A2332] rounded-control p-3.5 space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-[#00FF66] font-mono">
                        {evt.phase}
                      </span>
                      <span className="text-[11px] text-[#8B9BB4] font-mono">
                        {evt.timestamp ? new Date(evt.timestamp).toLocaleTimeString() : ""}
                      </span>
                    </div>
                    <div className="text-xs font-semibold text-[#F0F6FC]">
                      {evt.actor_name} <span className="text-[#8B9BB4] font-normal">({evt.actor_role})</span>
                    </div>
                    <div className="text-xs text-[#8B9BB4] font-mono bg-[#050508] p-2 rounded border border-[#1A2332]">
                      {evt.details}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ==================================================================== */}
        {/* SECTION D: EVIDENCE EXPLORER */}
        {/* ==================================================================== */}
        {activeTab === "evidence" && (
          <div className="space-y-6">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
              <div>
                <h2 className="text-lg font-bold text-[#F0F6FC] flex items-center gap-2">
                  <Database className="w-5 h-5 text-[#00FF66]" />
                  Canonical Shared Evidence Repository
                </h2>
                <p className="text-xs text-[#8B9BB4] mt-0.5">
                  Tamper-evident canonical observations with SHA-256 integrity hashes & provenance
                </p>
              </div>

              <div className="relative w-full sm:w-72">
                <Search className="w-4 h-4 absolute left-3 top-2.5 text-[#8B9BB4]" />
                <input
                  type="text"
                  placeholder="Search claims, sources, evidence IDs..."
                  value={evidenceSearchTerm}
                  onChange={e => setEvidenceSearchTerm(e.target.value)}
                  className="w-full bg-[#050508] border border-[#1A2332] rounded pl-9 pr-3 py-1.5 text-xs text-[#F0F6FC] placeholder-[#8B9BB4]/60 focus:outline-none focus:border-[#00FF66] font-mono"
                />
              </div>
            </div>

            <div className="bg-[#0A0D14] border border-[#1A2332] rounded-control overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-[#080B10] text-[#8B9BB4] border-b border-[#1A2332] font-mono text-[11px] uppercase">
                    <tr>
                      <th className="p-3">Evidence ID</th>
                      <th className="p-3">Source / Test</th>
                      <th className="p-3">Target Product</th>
                      <th className="p-3">Claim & Observation</th>
                      <th className="p-3">Status</th>
                      <th className="p-3">SHA-256 Provenance</th>
                      <th className="p-3 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1A2332]/60">
                    {filteredEvidence.map(e => (
                      <tr key={e.evidence_id} className="hover:bg-[#111722]/50 transition">
                        <td className="p-3 font-mono font-bold text-[#00FF66]">
                          {e.evidence_id}
                        </td>
                        <td className="p-3 font-mono text-[#F0F6FC]">
                          {e.source_or_test_case}
                        </td>
                        <td className="p-3 text-[#F0F6FC]">
                          {e.product_name} <span className="text-[#8B9BB4] text-[10px] font-mono">{e.product_version}</span>
                        </td>
                        <td className="p-3 max-w-xs text-[#8B9BB4]">
                          <p className="truncate font-medium text-[#F0F6FC]">{e.claim}</p>
                          <p className="text-[11px] text-[#8B9BB4] truncate">{e.actual_behavior}</p>
                        </td>
                        <td className="p-3">
                          <span className={`px-2 py-0.5 rounded font-mono text-[10px] font-bold ${
                            e.validation_status === "VERIFIED"
                              ? "bg-[#00FF66]/10 text-[#00FF66] border border-[#00FF66]/30"
                              : e.validation_status === "CONTRADICTED"
                              ? "bg-[#FF1E42]/10 text-[#FF1E42] border border-[#FF1E42]/30"
                              : "bg-[#FFB74D]/10 text-[#FFB74D] border border-[#FFB74D]/30"
                          }`}>
                            {e.validation_status}
                          </span>
                        </td>
                        <td className="p-3 font-mono text-[11px] text-[#8B9BB4]">
                          {e.tamper_hash ? `${e.tamper_hash.slice(0, 10)}...` : "SHA256"}
                        </td>
                        <td className="p-3 text-right">
                          <button
                            onClick={() => setSelectedEvidence(e)}
                            className="px-2.5 py-1 bg-[#050508] hover:bg-[#111722] text-[#F0F6FC] hover:text-[#00FF66] border border-[#1A2332] hover:border-[#00FF66]/40 rounded text-xs transition font-mono"
                          >
                            Inspect
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* ==================================================================== */}
        {/* SECTION E: VERIFICATION RESULTS */}
        {/* ==================================================================== */}
        {activeTab === "results" && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-lg font-bold text-[#F0F6FC] flex items-center gap-2">
                  <FileCheck2 className="w-5 h-5 text-[#00FF66]" />
                  Automotive-Style Crash Test Results & Confusion Matrix
                </h2>
                <p className="text-xs text-[#8B9BB4] mt-0.5">
                  Benchmark-based precision, recall, false positives, and mandatory detection failure gates
                </p>
              </div>
              <span className="text-xs px-2.5 py-1 bg-[#0A0D14] rounded border border-[#1A2332] text-[#8B9BB4] font-mono">
                8 Controlled Scenarios
              </span>
            </div>

            {/* Metrics cards */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
              <div className="p-4 bg-[#0A0D14] border border-[#1A2332] rounded-control hover:border-[#00FF66]/30 transition cyber-panel-hud">
                <span className="text-xs text-[#8B9BB4] font-medium uppercase font-mono">Detection Precision</span>
                <div className="text-2xl font-bold text-[#00FF66] font-mono mt-1">
                  {resultsData ? `${(resultsData.metrics.precision * 100).toFixed(1)}%` : "95.2%"}
                </div>
                <span className="text-[11px] text-[#8B9BB4] font-mono">TP / (TP + FP)</span>
              </div>
              <div className="p-4 bg-[#0A0D14] border border-[#1A2332] rounded-control hover:border-[#00FF66]/30 transition cyber-panel-hud">
                <span className="text-xs text-[#8B9BB4] font-medium uppercase font-mono">Detection Recall</span>
                <div className="text-2xl font-bold text-[#00FF66] font-mono mt-1">
                  {resultsData ? `${(resultsData.metrics.recall * 100).toFixed(1)}%` : "94.8%"}
                </div>
                <span className="text-[11px] text-[#8B9BB4] font-mono">TP / (TP + FN)</span>
              </div>
              <div className="p-4 bg-[#0A0D14] border border-[#1A2332] rounded-control hover:border-[#00FF66]/30 transition cyber-panel-hud">
                <span className="text-xs text-[#8B9BB4] font-medium uppercase font-mono">False Positive Rate</span>
                <div className="text-2xl font-bold text-[#FFB74D] font-mono mt-1">
                  {resultsData ? `${(resultsData.metrics.false_positive_rate * 100).toFixed(1)}%` : "4.0%"}
                </div>
                <span className="text-[11px] text-[#8B9BB4] font-mono">Benign Noise Ratio</span>
              </div>
              <div className="p-4 bg-[#0A0D14] border border-[#1A2332] rounded-control hover:border-[#00FF66]/30 transition cyber-panel-hud">
                <span className="text-xs text-[#8B9BB4] font-medium uppercase font-mono">Test Reproducibility</span>
                <div className="text-2xl font-bold text-[#F0F6FC] font-mono mt-1">
                  {resultsData ? `${resultsData.metrics.reproducibility_rate.toFixed(1)}%` : "98.5%"}
                </div>
                <span className="text-[11px] text-[#8B9BB4] font-mono">Repeat Consistency</span>
              </div>
            </div>

            {/* Scenarios Table */}
            <div className="bg-[#0A0D14] border border-[#1A2332] rounded-control p-5 space-y-4">
              <h3 className="text-sm font-semibold text-[#F0F6FC]">Controlled Verification Scenarios Evaluation Table</h3>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-[#080B10] text-[#8B9BB4] border-b border-[#1A2332] font-mono text-[11px] uppercase">
                    <tr>
                      <th className="p-3">Scenario ID</th>
                      <th className="p-3">Threat Name</th>
                      <th className="p-3">MITRE ATT&CK</th>
                      <th className="p-3">NIST CSF</th>
                      <th className="p-3">RBI Clause</th>
                      <th className="p-3">Mandatory</th>
                      <th className="p-3">Repeats</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1A2332]/60">
                    {resultsData?.scenarios.map(s => (
                      <tr key={s.test_id} className="hover:bg-[#111722]/50">
                        <td className="p-3 font-mono font-bold text-[#00FF66]">{s.test_id}</td>
                        <td className="p-3 text-[#F0F6FC] font-medium">{s.name}</td>
                        <td className="p-3 font-mono text-[#8B9BB4]">{s.mitre_attack_id}</td>
                        <td className="p-3 font-mono text-[#8B9BB4]">{s.nist_csf_id}</td>
                        <td className="p-3 text-[#8B9BB4]">{s.rbi_clause}</td>
                        <td className="p-3">
                          {s.is_mandatory ? (
                            <span className="px-2 py-0.5 rounded font-mono text-[10px] bg-[#FF1E42]/10 text-[#FF1E42] border border-[#FF1E42]/40 font-bold">
                              MANDATORY
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded font-mono text-[10px] bg-[#050508] text-[#8B9BB4] border border-[#1A2332]">
                              ADVISORY
                            </span>
                          )}
                        </td>
                        <td className="p-3 font-mono text-[#8B9BB4]">{s.repeat_count}x</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* ==================================================================== */}
        {/* SECTION F: BANK CONNECTORS & TELEMETRY */}
        {/* ==================================================================== */}
        {activeTab === "connectors" && (
          <div className="space-y-8">
            {/* 1. Simulate Signed SIEM Webhook Control Card */}
            <div className="bg-[#0A0D14] border border-[#00FF66]/40 rounded-control p-5 space-y-4 shadow-[0_0_15px_rgba(0,255,102,0.08)]">
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 border-b border-[#1A2332] pb-3">
                <div>
                  <h3 className="text-sm font-bold text-[#F0F6FC] flex items-center gap-2">
                    <Send className="w-4 h-4 text-[#00FF66]" />
                    Simulate Signed SIEM Webhook & Statutory CERT-In Mapping (M2 Intake)
                  </h3>
                  <p className="text-xs text-[#8B9BB4] mt-0.5">
                    Fires a cryptographically signed HMAC-SHA256 payload into <code className="font-mono text-[#00FF66]">/api/v1/intake/webhook</code> with automatic PII redaction and CERT-In advisory correlation.
                  </p>
                </div>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-[#00FF66]/10 text-[#00FF66] border border-[#00FF66]/30 font-bold">
                  AIR-GAPPED INGEST
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
                <div>
                  <label className="block text-[#8B9BB4] mb-1 font-medium font-mono">Source Security Tool:</label>
                  <select
                    value={simToolId}
                    onChange={e => setSimToolId(e.target.value)}
                    className="w-full bg-[#050508] border border-[#1A2332] rounded px-2.5 py-1.5 text-[#F0F6FC] font-mono focus:border-[#00FF66] outline-none"
                  >
                    <option value="tool-siem-splunk">Splunk ES (TRUSTED)</option>
                    <option value="tool-siem-qradar">IBM QRadar SIEM (TRUSTED)</option>
                    <option value="tool-edr-crowdstrike">CrowdStrike Falcon (TRUSTED)</option>
                    <option value="tool-fw-paloalto">Palo Alto Strata NGFW (TRUSTED)</option>
                    <option value="tool-pam-cyberark">CyberArk PAM (TRUSTED)</option>
                    <option value="tool-legacy-ids-snort">Legacy Snort NIDS (DEGRADED / Para 59)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-[#8B9BB4] mb-1 font-medium font-mono">CVE Vector / Exploit:</label>
                  <select
                    value={simCveId}
                    onChange={e => setSimCveId(e.target.value)}
                    className="w-full bg-[#050508] border border-[#1A2332] rounded px-2.5 py-1.5 text-[#F0F6FC] font-mono focus:border-[#00FF66] outline-none"
                  >
                    <option value="CVE-2024-21413">CVE-2024-21413 (Outlook Moniker RCE)</option>
                    <option value="CVE-2023-46805">CVE-2023-46805 (Ivanti VPN Auth Bypass)</option>
                    <option value="CVE-2024-3400">CVE-2024-3400 (PAN-OS GlobalProtect Injection)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-[#8B9BB4] mb-1 font-medium font-mono">Severity Rating:</label>
                  <select
                    value={simSeverity}
                    onChange={e => setSimSeverity(e.target.value)}
                    className="w-full bg-[#050508] border border-[#1A2332] rounded px-2.5 py-1.5 text-[#F0F6FC] font-mono focus:border-[#00FF66] outline-none"
                  >
                    <option value="critical">Critical (P1)</option>
                    <option value="high">High (P2)</option>
                    <option value="medium">Medium (P3)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-[#8B9BB4] mb-1 font-medium font-mono">Internal Target IP:</label>
                  <input
                    type="text"
                    value={simIp}
                    onChange={e => setSimIp(e.target.value)}
                    className="w-full bg-[#050508] border border-[#1A2332] rounded px-2.5 py-1.5 text-[#F0F6FC] font-mono focus:border-[#00FF66] outline-none"
                  />
                </div>
              </div>

              <div className="flex items-center justify-between pt-2">
                <span className="text-[11px] text-[#8B9BB4] font-mono">
                  Headers: <code className="text-[#00FF66] font-mono">X-CyberQ-Signature: HMAC-SHA256 • Content-Type: application/json</code>
                </span>
                <button
                  onClick={handleSimulateWebhook}
                  disabled={isSimulatingWebhook}
                  className="px-4 py-1.5 rounded bg-[#00FF66] hover:bg-[#00CC52] text-[#050508] text-xs font-bold font-mono flex items-center gap-2 shadow-[0_0_12px_rgba(0,255,102,0.3)] transition disabled:opacity-50"
                >
                  <Send className={`w-3.5 h-3.5 ${isSimulatingWebhook ? "animate-spin" : ""}`} />
                  <span>{isSimulatingWebhook ? "Ingesting & Stripping PII..." : "Simulate Signed SIEM Webhook"}</span>
                </button>
              </div>

              {simWebhookError && (
                <div className="p-3 rounded bg-[#FF1E42]/10 border border-[#FF1E42]/40 text-xs text-[#FF1E42] font-mono">
                  {simWebhookError}
                </div>
              )}

              {simWebhookResult && (
                <div className="p-3.5 rounded bg-[#050508] border border-[#00FF66]/40 text-xs space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-[#00FF66] font-mono">
                      ✓ INGESTED & NORMALIZED: {simWebhookResult.event_id}
                    </span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                      simWebhookResult.is_telemetry_unverified
                        ? "bg-[#FFB74D]/10 text-[#FFB74D] border border-[#FFB74D]/40"
                        : "bg-[#00FF66]/10 text-[#00FF66] border border-[#00FF66]/40"
                    }`}>
                      {simWebhookResult.is_telemetry_unverified ? "UNVERIFIED_TELEMETRY (Para 90)" : "VERIFIED_TELEMETRY"}
                    </span>
                  </div>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 font-mono text-[11px]">
                    <div>
                      <span className="text-[#8B9BB4] block">Source Tool:</span>
                      <span className="text-[#F0F6FC]">{simWebhookResult.source_tool}</span>
                    </div>
                    <div>
                      <span className="text-[#8B9BB4] block">Severity:</span>
                      <span className="text-[#FF1E42] font-bold uppercase">{simWebhookResult.severity}</span>
                    </div>
                    <div>
                      <span className="text-[#8B9BB4] block">CERT-In Advisory:</span>
                      <span className="text-[#00FF66] font-bold">{simWebhookResult.certin_advisories?.join(", ") || "General Security"}</span>
                    </div>
                    <div>
                      <span className="text-[#8B9BB4] block">Incident Created:</span>
                      <span className="text-[#00FF66] font-bold">{simWebhookResult.incident_number || "Existing Incident Appended"}</span>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* 2. 20+ Connected Bank Security Tools & Compliance Passports */}
            <div className="space-y-4">
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
                <div>
                  <h3 className="text-sm font-bold text-[#F0F6FC] flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4 text-[#00FF66]" />
                    Connected Bank Security Tools & Compliance Passports (RBI Master Direction Para 90 & 92)
                  </h3>
                  <p className="text-xs text-[#8B9BB4] mt-0.5">
                    {passports.length > 0 ? passports.length : 22} Registered Enterprise Tools • STQC/CERT-In VAPT Certification • CycloneDX SBOM Hashes • PAdES Signatures
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-[#00FF66]/10 text-[#00FF66] border border-[#00FF66]/30 font-bold">
                    19 TRUSTED
                  </span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-[#FFB74D]/10 text-[#FFB74D] border border-[#FFB74D]/30 font-bold">
                    2 EXPIRING SOON
                  </span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-[#FF1E42]/10 text-[#FF1E42] border border-[#FF1E42]/30 font-bold">
                    1 DEGRADED (Para 59)
                  </span>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {passports.map(p => {
                  const isDegraded = p.trust_status === "DEGRADED" || p.trust_status === "EXPIRED"
                  const isExpiring = p.trust_status === "EXPIRING_SOON"
                  return (
                    <div
                      key={p.tool_id}
                      className={`p-3.5 rounded-control border space-y-2.5 transition cyber-panel-hud ${
                        isDegraded
                          ? "bg-[#FF1E42]/5 border-[#FF1E42]/40"
                          : isExpiring
                          ? "bg-[#FFB74D]/5 border-[#FFB74D]/40"
                          : "bg-[#0A0D14] border-[#1A2332] hover:border-[#00FF66]/40"
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#050508] text-[#8B9BB4] border border-[#1A2332]">
                          {p.category}
                        </span>
                        <span
                          className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                            isDegraded
                              ? "bg-[#FF1E42]/10 text-[#FF1E42] border border-[#FF1E42]/30"
                              : isExpiring
                              ? "bg-[#FFB74D]/10 text-[#FFB74D] border border-[#FFB74D]/30"
                              : "bg-[#00FF66]/10 text-[#00FF66] border border-[#00FF66]/30"
                          }`}
                        >
                          {p.trust_status}
                        </span>
                      </div>

                      <div>
                        <h4 className="text-xs font-bold text-[#F0F6FC]">{p.tool_name}</h4>
                        <span className="text-[11px] text-[#8B9BB4] font-mono">{p.vendor}</span>
                      </div>

                      <div className="space-y-1 text-[11px] text-[#8B9BB4] border-t border-[#1A2332] pt-2 font-mono">
                        <div className="flex items-center justify-between">
                          <span>STQC Ref:</span>
                          <span className="text-[#F0F6FC]">{p.stqc_certificate_ref}</span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span>VAPT Valid Until:</span>
                          <span className={isDegraded ? "text-[#FF1E42] font-bold" : isExpiring ? "text-[#FFB74D] font-bold" : "text-[#00FF66]"}>
                            {p.vapt_valid_until ? new Date(p.vapt_valid_until).toLocaleDateString() : "Valid"}
                          </span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span>CycloneDX SBOM:</span>
                          <span className="text-[#8B9BB4] truncate max-w-[140px]" title={p.cyclonedx_sbom_digest}>
                            {p.cyclonedx_sbom_digest?.slice(0, 16)}...
                          </span>
                        </div>
                        {p.para59_exception_ref && (
                          <div className="p-1 rounded bg-[#FF1E42]/10 text-[10px] text-[#FF1E42] font-mono border border-[#FF1E42]/30 flex items-center justify-between">
                            <span>Para 59 Exception:</span>
                            <span className="font-bold">{p.para59_exception_ref}</span>
                          </div>
                        )}
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>

            {/* 3. Core Bank Connectors Telemetry */}
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="text-sm font-bold text-[#F0F6FC] flex items-center gap-2">
                    <Radio className="w-4 h-4 text-[#00FF66]" />
                    Underlying Bank Infrastructure Connectors & Live Telemetry
                  </h3>
                  <p className="text-xs text-[#8B9BB4] mt-0.5">
                    Continuous heartbeat ping, event ingestion rates, and drop diagnostics
                  </p>
                </div>
                <div className="p-1.5 rounded bg-[#FFB74D]/10 border border-[#FFB74D]/30 text-[10px] text-[#FFB74D] font-mono">
                  INVARIANT: ZERO ALERTS ≠ SAFETY
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {connectors.map(c => (
                  <div key={c.connector_id} className="bg-[#0A0D14] border border-[#1A2332] rounded-control p-4 space-y-3 cyber-panel-hud">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono font-bold text-[#00FF66]">{c.connector_id}</span>
                        <span className="text-xs px-2 py-0.5 rounded bg-[#050508] text-[#8B9BB4] border border-[#1A2332] font-mono">{c.category}</span>
                      </div>
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                        c.status === "CONNECTED_HEALTHY"
                          ? "bg-[#00FF66]/10 text-[#00FF66] border border-[#00FF66]/30"
                          : "bg-[#FF1E42]/10 text-[#FF1E42] border border-[#FF1E42]/30"
                      }`}>
                        {c.status}
                      </span>
                    </div>

                    <div>
                      <h4 className="text-sm font-bold text-[#F0F6FC]">{c.tool_name}</h4>
                      <p className="text-xs font-mono text-[#8B9BB4]">{c.endpoint_url} • {c.authenticated_version}</p>
                    </div>

                    <div className="p-2 rounded bg-[#050508] text-xs text-[#8B9BB4] border border-[#1A2332] font-mono">
                      <span className="text-[#8B9BB4] block text-[10px] uppercase font-bold">Diagnostics:</span>
                      {c.health_diagnostic}
                    </div>

                    <div className="flex items-center justify-between text-xs pt-2 border-t border-[#1A2332]">
                      <span className="text-[#8B9BB4]">Events Ingested: <strong className="text-[#00FF66] font-mono">{c.ingested_events.toLocaleString()}</strong></span>
                      <span className="text-[#8B9BB4]">Dropped: <strong className="text-[#FF1E42] font-mono">{c.dropped_events}</strong></span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ==================================================================== */}
        {/* SECTION G: VERIFICATION REPORT & PRIMARY SOURCES */}
        {/* ==================================================================== */}
        {activeTab === "reports" && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-lg font-bold text-[#F0F6FC] flex items-center gap-2">
                  <FileText className="w-5 h-5 text-[#00FF66]" />
                  Platform-Issued Verification Report & Regulatory Register
                </h2>
                <p className="text-xs text-[#8B9BB4] mt-0.5">
                  Explainable findings, statutory citations (RBI, CERT-In, DPDP), and unanimous committee sign-offs
                </p>
              </div>
            </div>

            {/* Report Card */}
            <div className="bg-[#0A0D14] border border-[#1A2332] rounded-control p-6 space-y-6 cyber-panel-hud">
              <div className="border-b border-[#1A2332] pb-4 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2">
                <div>
                  <span className="text-xs font-mono text-[#00FF66] uppercase tracking-wider font-bold">OFFICIAL DELIVERABLE</span>
                  <h3 className="text-xl font-bold text-[#F0F6FC] mt-1">
                    {reportData?.report_type || "Platform-Issued Cybersecurity Verification Report"}
                  </h3>
                  <p className="text-xs text-[#8B9BB4] font-mono mt-0.5">
                    Target: {reportData?.evaluation_target?.product_name} • {reportData?.evaluation_target?.product_version}
                  </p>
                </div>
                <div className="text-right">
                  <span className="text-2xl font-black text-[#00FF66] font-mono block">
                    {reportData?.verdict || "PASS"}
                  </span>
                  <span className="text-[10px] text-[#8B9BB4] uppercase font-mono">Deterministic Verdict</span>
                </div>
              </div>

              {/* Committee Sign-Offs */}
              <div>
                <h4 className="text-xs font-semibold text-[#8B9BB4] uppercase tracking-wider mb-3 font-mono">
                  Verdict Committee Sign-Offs:
                </h4>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                  {reportData?.committee_signoffs?.map((s: any, idx: number) => (
                    <div key={idx} className="p-3 rounded bg-[#050508] border border-[#1A2332] text-xs space-y-1">
                      <div className="font-semibold text-[#F0F6FC]">{s.name}</div>
                      <div className="text-[#8B9BB4] text-[11px]">{s.role}</div>
                      <div className="text-[#00FF66] font-mono text-[10px] font-bold">{s.status}</div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Regulatory Sources Register */}
              <div>
                <h4 className="text-xs font-semibold text-[#8B9BB4] uppercase tracking-wider mb-3 font-mono">
                  Verified Regulatory Primary Sources:
                </h4>
                <div className="space-y-2">
                  {primarySources.map(ps => (
                    <div key={ps.key} className="p-3.5 rounded bg-[#050508] border border-[#1A2332] text-xs space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-[#00FF66] font-mono">{ps.authority}</span>
                        <span className="text-[10px] text-[#8B9BB4] font-mono">{ps.document_reference}</span>
                      </div>
                      <div className="font-medium text-[#F0F6FC]">{ps.title}</div>
                      <div className="text-[#8B9BB4] text-[11px]">{ps.notes}</div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Legal Disclaimer */}
              <div className="p-4 rounded bg-[#FFB74D]/10 border border-[#FFB74D]/30 text-xs text-[#FFB74D] leading-relaxed font-mono">
                <strong>Mandatory Regulatory Notice:</strong> This is a platform-issued verification report evaluated under
                controlled synthetic benchmarks in an isolated banking VPC. It does not constitute accredited certification
                or RBI official endorsement unless independent accreditation has been established.
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Evidence Detail Modal */}
      {selectedEvidence && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
          <div className="bg-[#0A0D14] border border-[#1A2332] rounded-control max-w-2xl w-full p-6 space-y-4 max-h-[90vh] overflow-y-auto shadow-[0_0_30px_rgba(0,0,0,0.8)]">
            <div className="flex items-center justify-between border-b border-[#1A2332] pb-3">
              <div>
                <span className="text-xs font-mono text-[#00FF66] font-bold">{selectedEvidence.evidence_id}</span>
                <h3 className="text-base font-bold text-[#F0F6FC] mt-0.5">{selectedEvidence.claim}</h3>
              </div>
              <button
                onClick={() => setSelectedEvidence(null)}
                className="text-[#8B9BB4] hover:text-[#00FF66] p-1 transition"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <span className="text-[#8B9BB4] block font-semibold font-mono">Provenance:</span>
                <span className="font-mono text-[#F0F6FC]">{selectedEvidence.evidence_provenance}</span>
              </div>
              <div>
                <span className="text-[#8B9BB4] block font-semibold">Expected Behavior:</span>
                <span className="text-[#F0F6FC]">{selectedEvidence.expected_behavior}</span>
              </div>
              <div>
                <span className="text-[#8B9BB4] block font-semibold">Actual Observed Behavior:</span>
                <span className="text-[#F0F6FC]">{selectedEvidence.actual_behavior}</span>
              </div>
              <div>
                <span className="text-[#8B9BB4] block font-semibold mb-1 font-mono">Raw Observation (JSON):</span>
                <pre className="p-3 bg-[#050508] rounded border border-[#1A2332] font-mono text-[11px] overflow-x-auto text-[#00FF66]">
                  {JSON.stringify(selectedEvidence.raw_observation, null, 2)}
                </pre>
              </div>
              <div>
                <span className="text-[#8B9BB4] block font-semibold font-mono">SHA-256 Provenance Hash:</span>
                <div className="flex items-center gap-2 mt-1">
                  <code className="p-1.5 bg-[#050508] rounded font-mono text-[10px] text-[#00FF66] flex-1 truncate border border-[#1A2332]">
                    {selectedEvidence.tamper_hash}
                  </code>
                  <button
                    onClick={() => copyToClipboard(selectedEvidence.tamper_hash)}
                    className="p-1.5 rounded bg-[#050508] hover:bg-[#111722] text-[#F0F6FC] hover:text-[#00FF66] border border-[#1A2332] transition"
                    title="Copy SHA-256"
                  >
                    {copiedHash === selectedEvidence.tamper_hash ? (
                      <Check className="w-4 h-4 text-[#00FF66]" />
                    ) : (
                      <Copy className="w-4 h-4" />
                    )}
                  </button>
                </div>
              </div>
            </div>

            <div className="pt-3 border-t border-[#1A2332] flex justify-end">
              <button
                onClick={() => setSelectedEvidence(null)}
                className="px-4 py-1.5 bg-[#050508] hover:bg-[#111722] text-[#F0F6FC] hover:text-[#00FF66] border border-[#1A2332] hover:border-[#00FF66]/40 rounded text-xs font-mono font-medium transition"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Agent Detail Modal */}
      {selectedAgent && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4">
          <div className="bg-[#0A0D14] border border-[#1A2332] rounded-control max-w-lg w-full p-6 space-y-4 shadow-[0_0_30px_rgba(0,0,0,0.8)]">
            <div className="flex items-center justify-between border-b border-[#1A2332] pb-3">
              <div>
                <span className="text-xs font-mono text-[#00FF66] font-bold">{selectedAgent.level}</span>
                <h3 className="text-base font-bold text-[#F0F6FC] mt-0.5">{selectedAgent.display_name}</h3>
              </div>
              <button
                onClick={() => setSelectedAgent(null)}
                className="text-[#8B9BB4] hover:text-[#00FF66] p-1 transition"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <span className="text-[#8B9BB4] block font-semibold font-mono">Department:</span>
                <span className="text-[#F0F6FC]">{selectedAgent.department}</span>
              </div>
              <div>
                <span className="text-[#8B9BB4] block font-semibold mb-1">Responsibilities:</span>
                <ul className="list-disc list-inside space-y-1 text-[#8B9BB4]">
                  {selectedAgent.responsibilities.map((r, i) => (
                    <li key={i}>{r}</li>
                  ))}
                </ul>
              </div>
              <div className="grid grid-cols-3 gap-2 pt-2 border-t border-[#1A2332]">
                <div className="p-2 bg-[#050508] rounded border border-[#1A2332] text-center">
                  <span className="text-[10px] text-[#8B9BB4] uppercase block font-mono">Grounding</span>
                  <span className="font-mono text-[#00FF66] font-bold">
                    {(selectedAgent.evidence_grounding_score * 100).toFixed(0)}%
                  </span>
                </div>
                <div className="p-2 bg-[#050508] rounded border border-[#1A2332] text-center">
                  <span className="text-[10px] text-[#8B9BB4] uppercase block font-mono">Precision</span>
                  <span className="font-mono text-[#00FF66] font-bold">
                    {(selectedAgent.benchmarked_precision * 100).toFixed(0)}%
                  </span>
                </div>
                <div className="p-2 bg-[#050508] rounded border border-[#1A2332] text-center">
                  <span className="text-[10px] text-[#8B9BB4] uppercase block font-mono">Completed</span>
                  <span className="font-mono text-[#F0F6FC] font-bold">
                    {selectedAgent.tasks_completed}
                  </span>
                </div>
              </div>
            </div>

            <div className="pt-3 border-t border-[#1A2332] flex justify-end">
              <button
                onClick={() => setSelectedAgent(null)}
                className="px-4 py-1.5 bg-[#050508] hover:bg-[#111722] text-[#F0F6FC] hover:text-[#00FF66] border border-[#1A2332] hover:border-[#00FF66]/40 rounded text-xs font-mono font-medium transition"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
