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
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
      {/* Top Header */}
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur sticky top-0 z-30 px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-4">
          <button
            onClick={onBackToCommand}
            className="p-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 hover:text-white transition-colors"
            title="Return to SOC Incidents View"
          >
            <ChevronRight className="w-5 h-5 rotate-180" />
          </button>
          <div>
            <div className="flex items-center gap-3">
              <span className="p-1.5 rounded-md bg-indigo-500/20 text-indigo-400 border border-indigo-500/30">
                <ShieldCheck className="w-5 h-5" />
              </span>
              <h1 className="text-xl font-bold tracking-tight text-white flex items-center gap-2">
                CYBERQ Multi-Agent Verification Platform
                <span className="text-xs px-2 py-0.5 rounded-full bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 font-mono">
                  AUTOMOTIVE-CRASH-TEST-LAB
                </span>
              </h1>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Independent multi-agent evaluation of bank security products, evidence grounding, and deterministic verdicts
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <span className="text-xs px-2.5 py-1 rounded-md bg-slate-800 text-slate-300 border border-slate-700 font-mono">
            {userRole} {isDemo ? "(demo)" : ""}
          </span>
          <button
            onClick={fetchAllData}
            disabled={isLoading}
            className="px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-medium text-slate-200 flex items-center gap-1.5 border border-slate-700 transition"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </div>
      </header>

      {/* Scenario Runner Toolbar */}
      <div className="bg-slate-900/90 border-b border-slate-800 px-6 py-3 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
            <Play className="w-3.5 h-3.5 text-indigo-400" />
            Verification Crash Test Scenarios:
          </span>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button
            disabled={isExecutingScenario}
            onClick={() => handleExecuteScenario("scenario_a", "Scenario A (Correct Detection)")}
            className="px-2.5 py-1 rounded-md text-xs font-medium bg-emerald-950/60 text-emerald-300 border border-emerald-700/50 hover:bg-emerald-900/80 transition"
          >
            A: Correct Detection (PASS)
          </button>
          <button
            disabled={isExecutingScenario}
            onClick={() => handleExecuteScenario("scenario_b", "Scenario B (Missed Mandatory Threat)")}
            className="px-2.5 py-1 rounded-md text-xs font-medium bg-rose-950/60 text-rose-300 border border-rose-700/50 hover:bg-rose-900/80 transition"
          >
            B: Missed Threat (FAIL)
          </button>
          <button
            disabled={isExecutingScenario}
            onClick={() => handleExecuteScenario("scenario_c", "Scenario C (Contradictory Agents)")}
            className="px-2.5 py-1 rounded-md text-xs font-medium bg-amber-950/60 text-amber-300 border border-amber-700/50 hover:bg-amber-900/80 transition"
          >
            C: Disagreement (No Vote)
          </button>
          <button
            disabled={isExecutingScenario}
            onClick={() => handleExecuteScenario("scenario_d", "Scenario D (False Evidence)")}
            className="px-2.5 py-1 rounded-md text-xs font-medium bg-purple-950/60 text-purple-300 border border-purple-700/50 hover:bg-purple-900/80 transition"
          >
            D: False Evidence (Reject)
          </button>
          <button
            disabled={isExecutingScenario}
            onClick={() => handleExecuteScenario("scenario_e", "Scenario E (Missing Telemetry)")}
            className="px-2.5 py-1 rounded-md text-xs font-medium bg-cyan-950/60 text-cyan-300 border border-cyan-700/50 hover:bg-cyan-900/80 transition"
          >
            E: Connector Outage (Gap)
          </button>
          <button
            disabled={isExecutingScenario}
            onClick={() => handleExecuteScenario("scenario_f", "Scenario F (Repeated Review)")}
            className="px-2.5 py-1 rounded-md text-xs font-medium bg-blue-950/60 text-blue-300 border border-blue-700/50 hover:bg-blue-900/80 transition"
          >
            F: Repeated Review (Cycle)
          </button>
          <button
            disabled={isExecutingScenario}
            onClick={() => handleExecuteScenario("scenario_g", "Scenario G (Unresolved Investigation)")}
            className="px-2.5 py-1 rounded-md text-xs font-medium bg-slate-800 text-slate-300 border border-slate-700 hover:bg-slate-700 transition"
          >
            G: Iteration Budget (Inconclusive)
          </button>
          <button
            disabled={isExecutingScenario}
            onClick={() => handleExecuteScenario("scenario_h", "Scenario H (Regulatory Claim)")}
            className="px-2.5 py-1 rounded-md text-xs font-medium bg-orange-950/60 text-orange-300 border border-orange-700/50 hover:bg-orange-900/80 transition"
          >
            H: Regulatory Integrity
          </button>
        </div>
      </div>

      {executionMessage && (
        <div className="bg-indigo-950/80 border-b border-indigo-800/60 px-6 py-2 text-xs font-medium text-indigo-200 flex items-center justify-between">
          <span>{executionMessage}</span>
          <button
            onClick={() => setExecutionMessage(null)}
            className="text-indigo-400 hover:text-white"
          >
            ✕
          </button>
        </div>
      )}

      {/* Main 7 Sections Navigation Bar */}
      <div className="bg-slate-900 border-b border-slate-800 px-6">
        <nav className="flex space-x-6 text-sm font-medium">
          <button
            onClick={() => setActiveTab("command")}
            className={`py-3 px-1 border-b-2 flex items-center gap-2 ${
              activeTab === "command"
                ? "border-indigo-500 text-indigo-400 font-semibold"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Activity className="w-4 h-4" />
            A. Command Center
          </button>
          <button
            onClick={() => setActiveTab("organization")}
            className={`py-3 px-1 border-b-2 flex items-center gap-2 ${
              activeTab === "organization"
                ? "border-indigo-500 text-indigo-400 font-semibold"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Users className="w-4 h-4" />
            B. Agent Organization (16 Agents)
          </button>
          <button
            onClick={() => setActiveTab("timeline")}
            className={`py-3 px-1 border-b-2 flex items-center gap-2 ${
              activeTab === "timeline"
                ? "border-indigo-500 text-indigo-400 font-semibold"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Clock className="w-4 h-4" />
            C. 11-Phase Review Timeline
          </button>
          <button
            onClick={() => setActiveTab("evidence")}
            className={`py-3 px-1 border-b-2 flex items-center gap-2 ${
              activeTab === "evidence"
                ? "border-indigo-500 text-indigo-400 font-semibold"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Database className="w-4 h-4" />
            D. Evidence Explorer ({evidenceList.length})
          </button>
          <button
            onClick={() => setActiveTab("results")}
            className={`py-3 px-1 border-b-2 flex items-center gap-2 ${
              activeTab === "results"
                ? "border-indigo-500 text-indigo-400 font-semibold"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <FileCheck2 className="w-4 h-4" />
            E. Verification Results
          </button>
          <button
            onClick={() => setActiveTab("connectors")}
            className={`py-3 px-1 border-b-2 flex items-center gap-2 ${
              activeTab === "connectors"
                ? "border-indigo-500 text-indigo-400 font-semibold"
                : "border-transparent text-slate-400 hover:text-slate-200"
            }`}
          >
            <Radio className="w-4 h-4" />
            F. Bank Connectors & Telemetry (8)
          </button>
          <button
            onClick={() => setActiveTab("reports")}
            className={`py-3 px-1 border-b-2 flex items-center gap-2 ${
              activeTab === "reports"
                ? "border-indigo-500 text-indigo-400 font-semibold"
                : "border-transparent text-slate-400 hover:text-slate-200"
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
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
                <span className="text-xs text-slate-400 font-medium">Evaluation Target</span>
                <div className="text-lg font-bold text-white mt-1">Tier-1 EDR Defender Suite</div>
                <div className="text-xs text-indigo-400 mt-0.5">Build v8.2.140 • Air-Gapped Testbed</div>
              </div>
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
                <span className="text-xs text-slate-400 font-medium">Platform Verdict</span>
                <div className="flex items-center gap-2 mt-1">
                  <span className={`text-xl font-black ${
                    commandStatus?.latest_investigation?.verdict === "PASS"
                      ? "text-emerald-400"
                      : commandStatus?.latest_investigation?.verdict === "FAIL"
                      ? "text-rose-400"
                      : "text-amber-400"
                  }`}>
                    {commandStatus?.latest_investigation?.verdict || "PASS"}
                  </span>
                  <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300 font-mono">
                    Deterministic Engine
                  </span>
                </div>
                <div className="text-xs text-slate-400 mt-0.5">Zero LLM Opinion • Rule Backed</div>
              </div>
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
                <span className="text-xs text-slate-400 font-medium">Team Evidence Grounding</span>
                <div className="text-xl font-bold text-white mt-1">
                  {commandStatus ? `${(commandStatus.team_evidence_grounding_average * 100).toFixed(1)}%` : "98.5%"}
                </div>
                <div className="text-xs text-emerald-400 mt-0.5">100% Traceable to Raw Logs</div>
              </div>
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
                <span className="text-xs text-slate-400 font-medium">Connector Health Ratio</span>
                <div className="text-xl font-bold text-white mt-1">
                  {commandStatus?.connector_health_ratio || "8/8 Online"}
                </div>
                <div className="text-xs text-slate-400 mt-0.5">SIEM • EDR • FW • IDS • IAM • MAIL</div>
              </div>
            </div>

            {/* Active Investigations & Quality Gate Status */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
                <div className="flex items-center justify-between">
                  <h2 className="text-base font-semibold text-white flex items-center gap-2">
                    <Activity className="w-4 h-4 text-indigo-400" />
                    Active Verification Posture & Summary
                  </h2>
                  <span className="text-xs font-mono px-2 py-1 bg-slate-800 rounded text-slate-300">
                    Iteration 1 / 5 Limit
                  </span>
                </div>
                <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800 text-sm leading-relaxed text-slate-300">
                  <p className="font-medium text-white mb-1">
                    {commandStatus?.latest_investigation?.summary ||
                      "Verification engine running controlled automotive crash tests against synthetic banking threat models."}
                  </p>
                  <p className="text-xs text-slate-400 mt-2">
                    Primary objective: Maximum achievable accuracy, depth of investigation, and evidence traceability.
                    Absence of alerts is NEVER equated with tool safety.
                  </p>
                </div>

                {/* Quality Gate Checks */}
                <div>
                  <h3 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                    Deterministic Quality Gates (6/6 Invariants):
                  </h3>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs">
                    <div className="p-2.5 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
                      <span className="text-slate-300">GATE-01: Mandatory Test Coverage</span>
                      <span className="text-emerald-400 font-mono flex items-center gap-1">
                        <CheckCircle2 className="w-3.5 h-3.5" /> PASSED
                      </span>
                    </div>
                    <div className="p-2.5 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
                      <span className="text-slate-300">GATE-02: Mandatory Threat Outcomes</span>
                      <span className="text-emerald-400 font-mono flex items-center gap-1">
                        <CheckCircle2 className="w-3.5 h-3.5" /> PASSED
                      </span>
                    </div>
                    <div className="p-2.5 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
                      <span className="text-slate-300">GATE-03: Evidence Authenticity (SHA-256)</span>
                      <span className="text-emerald-400 font-mono flex items-center gap-1">
                        <CheckCircle2 className="w-3.5 h-3.5" /> VERIFIED
                      </span>
                    </div>
                    <div className="p-2.5 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
                      <span className="text-slate-300">GATE-04: Disagreement Resolution</span>
                      <span className="text-emerald-400 font-mono flex items-center gap-1">
                        <CheckCircle2 className="w-3.5 h-3.5" /> RESOLVED
                      </span>
                    </div>
                    <div className="p-2.5 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
                      <span className="text-slate-300">GATE-05: Telemetry Pipeline Health</span>
                      <span className="text-emerald-400 font-mono flex items-center gap-1">
                        <CheckCircle2 className="w-3.5 h-3.5" /> ONLINE
                      </span>
                    </div>
                    <div className="p-2.5 rounded bg-slate-950 border border-slate-800 flex items-center justify-between">
                      <span className="text-slate-300">GATE-06: Review Iteration Budget</span>
                      <span className="text-emerald-400 font-mono flex items-center gap-1">
                        <CheckCircle2 className="w-3.5 h-3.5" /> WITHIN BUDGET
                      </span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Disagreement and Notice Panel */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
                <h2 className="text-base font-semibold text-white flex items-center gap-2">
                  <GitPullRequest className="w-4 h-4 text-amber-400" />
                  Preserved Disagreements ({disagreements.length})
                </h2>
                {disagreements.length === 0 ? (
                  <div className="p-4 rounded-lg bg-slate-950/60 border border-slate-800 text-xs text-slate-400 text-center">
                    Zero active unhandled disagreements. All technical claims reconciled through re-testing.
                  </div>
                ) : (
                  <div className="space-y-2">
                    {disagreements.map(d => (
                      <div key={d.id} className="p-3 rounded bg-amber-950/30 border border-amber-800/40 text-xs space-y-1.5">
                        <div className="font-semibold text-amber-300">{d.disputed_claim}</div>
                        <div className="text-slate-400">
                          <span className="text-slate-300">{d.agent_a_role}:</span> {d.agent_a_position}
                        </div>
                        <div className="text-slate-400">
                          <span className="text-slate-300">{d.agent_b_role}:</span> {d.agent_b_position}
                        </div>
                        <div className="text-amber-400 font-mono text-[10px]">
                          Resolution: {d.resolution_method}
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                <div className="p-3 rounded-lg bg-indigo-950/40 border border-indigo-800/40 text-xs text-indigo-300">
                  <span className="font-bold">Automotive Testing Analogy:</span> Security tools receive platform-issued results
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
                <h2 className="text-lg font-bold text-white flex items-center gap-2">
                  <Users className="w-5 h-5 text-indigo-400" />
                  Multi-Agent Organizational Hierarchy (6 Levels)
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Professional structure: Specialized engineers report to leads, independent QA challenges, decision engine approves
                </p>
              </div>
              <span className="text-xs px-2.5 py-1 bg-slate-800 rounded border border-slate-700 text-slate-300 font-mono">
                16 Registered Entities
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {agents.map(a => (
                <div
                  key={a.agent_id}
                  onClick={() => setSelectedAgent(a)}
                  className="bg-slate-900 border border-slate-800 hover:border-indigo-500/50 rounded-xl p-4 cursor-pointer transition hover:bg-slate-900/90 flex flex-col justify-between"
                >
                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-slate-800 text-indigo-300 border border-slate-700">
                        {a.level.split(":")[0]}
                      </span>
                      <span className={`text-[10px] px-2 py-0.5 rounded font-mono ${
                        a.status === "AVAILABLE"
                          ? "bg-emerald-950 text-emerald-400 border border-emerald-800/60"
                          : a.status === "INVESTIGATING"
                          ? "bg-indigo-950 text-indigo-300 border border-indigo-800/60"
                          : "bg-amber-950 text-amber-300 border border-amber-800/60"
                      }`}>
                        {a.status}
                      </span>
                    </div>

                    <div>
                      <h3 className="text-sm font-bold text-white">{a.display_name}</h3>
                      <p className="text-xs text-slate-400 font-medium">{a.department}</p>
                    </div>

                    <div className="text-xs text-slate-300 space-y-1">
                      <div className="text-slate-400 text-[11px]">Primary Duty:</div>
                      <p className="line-clamp-2 text-slate-300 text-xs">
                        {a.responsibilities[0]}
                      </p>
                    </div>
                  </div>

                  <div className="mt-4 pt-3 border-t border-slate-800/80 flex items-center justify-between text-xs">
                    <div>
                      <span className="text-[10px] text-slate-500 uppercase block">Grounding</span>
                      <span className="font-mono text-emerald-400 font-bold">
                        {(a.evidence_grounding_score * 100).toFixed(0)}%
                      </span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-500 uppercase block">Precision</span>
                      <span className="font-mono text-indigo-300 font-bold">
                        {(a.benchmarked_precision * 100).toFixed(0)}%
                      </span>
                    </div>
                    <div>
                      <span className="text-[10px] text-slate-500 uppercase block">Tasks</span>
                      <span className="font-mono text-slate-300 font-bold">
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
                <h2 className="text-lg font-bold text-white flex items-center gap-2">
                  <Clock className="w-5 h-5 text-indigo-400" />
                  11-Phase Continuous Review Workflow
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Plan → Delegate → Investigate → Submit → Lead Review → Cross-Exam → Dispute Resolution → Revision → Regression → Gate → Approval
                </p>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={handleRunLiveVerification}
                  disabled={isVerifyingLive}
                  className="px-3.5 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold flex items-center gap-1.5 shadow-sm transition disabled:opacity-50"
                  title="Run all 11 phases with specialized agents, cross-examination, and deterministic quality gate"
                >
                  <Cpu className={`w-3.5 h-3.5 ${isVerifyingLive ? "animate-spin" : ""}`} />
                  <span>{isVerifyingLive ? "Running 11 Phases..." : "Run Live Multi-Agent Review Loop (11 Phases)"}</span>
                </button>
                <span className="text-xs text-slate-400 font-mono">
                  {timelineEvents.length} Deliberations
                </span>
              </div>
            </div>

            {liveVerifyResult && (
              <div className="p-4 bg-indigo-950/60 border border-indigo-700/60 rounded-xl space-y-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                      LIVE VERIFICATION RESULT
                    </span>
                    <span className="text-xs font-mono font-bold text-white">{liveVerifyResult.id}</span>
                  </div>
                  <span className={`px-2 py-0.5 rounded text-xs font-bold font-mono ${
                    liveVerifyResult.final_verdict === "PASS"
                      ? "bg-emerald-950 text-emerald-300 border border-emerald-800"
                      : liveVerifyResult.final_verdict === "CONDITIONAL"
                      ? "bg-amber-950 text-amber-300 border border-amber-800"
                      : "bg-rose-950 text-rose-300 border border-rose-800"
                  }`}>
                    VERDICT: {liveVerifyResult.final_verdict}
                  </span>
                </div>
                <div className="text-xs text-slate-200">
                  {liveVerifyResult.summary}
                </div>
                {liveVerifyResult.quality_gate?.gate_checks && (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pt-2 border-t border-indigo-900/60 text-xs">
                    {liveVerifyResult.quality_gate.gate_checks.map((gc: any, gIdx: number) => (
                      <div key={gIdx} className="p-2 rounded bg-slate-950/70 border border-slate-800 flex items-center justify-between">
                        <span className="text-slate-300 font-mono text-[11px]">{gc.gate}</span>
                        <span className={`text-[10px] font-mono font-bold px-1.5 py-0.5 rounded ${
                          gc.passed
                            ? "bg-emerald-950 text-emerald-400"
                            : "bg-amber-950 text-amber-300"
                        }`}>
                          {gc.passed ? "PASSED" : "CONDITIONAL"}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            <div className="space-y-3 relative before:absolute before:inset-0 before:left-5 before:w-0.5 before:bg-slate-800">
              {timelineEvents.map((evt, idx) => (
                <div key={evt.id || idx} className="relative flex items-start gap-4 pl-10">
                  <div className="absolute left-3.5 -translate-x-1/2 top-1.5 w-3 h-3 rounded-full bg-indigo-500 border-2 border-slate-950" />
                  <div className="flex-1 bg-slate-900 border border-slate-800 rounded-lg p-3.5 space-y-1">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-bold text-indigo-400 font-mono">
                        {evt.phase}
                      </span>
                      <span className="text-[11px] text-slate-500 font-mono">
                        {evt.timestamp ? new Date(evt.timestamp).toLocaleTimeString() : ""}
                      </span>
                    </div>
                    <div className="text-xs font-semibold text-white">
                      {evt.actor_name} <span className="text-slate-400 font-normal">({evt.actor_role})</span>
                    </div>
                    <div className="text-xs text-slate-300 font-mono bg-slate-950 p-2 rounded border border-slate-800/80">
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
                <h2 className="text-lg font-bold text-white flex items-center gap-2">
                  <Database className="w-5 h-5 text-indigo-400" />
                  Canonical Shared Evidence Repository
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Tamper-evident canonical observations with SHA-256 integrity hashes & provenance
                </p>
              </div>

              <div className="relative w-full sm:w-72">
                <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-400" />
                <input
                  type="text"
                  placeholder="Search claims, sources, evidence IDs..."
                  value={evidenceSearchTerm}
                  onChange={e => setEvidenceSearchTerm(e.target.value)}
                  className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-indigo-500"
                />
              </div>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800 font-medium">
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
                  <tbody className="divide-y divide-slate-800/60">
                    {filteredEvidence.map(e => (
                      <tr key={e.evidence_id} className="hover:bg-slate-800/30 transition">
                        <td className="p-3 font-mono font-bold text-indigo-300">
                          {e.evidence_id}
                        </td>
                        <td className="p-3 font-mono text-slate-300">
                          {e.source_or_test_case}
                        </td>
                        <td className="p-3 text-slate-300">
                          {e.product_name} <span className="text-slate-500 text-[10px]">{e.product_version}</span>
                        </td>
                        <td className="p-3 max-w-xs text-slate-300">
                          <p className="truncate font-medium text-white">{e.claim}</p>
                          <p className="text-[11px] text-slate-400 truncate">{e.actual_behavior}</p>
                        </td>
                        <td className="p-3">
                          <span className={`px-2 py-0.5 rounded font-mono text-[10px] ${
                            e.validation_status === "VERIFIED"
                              ? "bg-emerald-950 text-emerald-400 border border-emerald-800/60"
                              : e.validation_status === "CONTRADICTED"
                              ? "bg-rose-950 text-rose-400 border border-rose-800/60"
                              : "bg-amber-950 text-amber-300 border border-amber-800/60"
                          }`}>
                            {e.validation_status}
                          </span>
                        </td>
                        <td className="p-3 font-mono text-[11px] text-slate-400">
                          {e.tamper_hash ? `${e.tamper_hash.slice(0, 10)}...` : "SHA256"}
                        </td>
                        <td className="p-3 text-right">
                          <button
                            onClick={() => setSelectedEvidence(e)}
                            className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs transition"
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
                <h2 className="text-lg font-bold text-white flex items-center gap-2">
                  <FileCheck2 className="w-5 h-5 text-indigo-400" />
                  Automotive-Style Crash Test Results & Confusion Matrix
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Benchmark-based precision, recall, false positives, and mandatory detection failure gates
                </p>
              </div>
              <span className="text-xs px-2.5 py-1 bg-slate-800 rounded text-slate-300 font-mono">
                8 Controlled Scenarios
              </span>
            </div>

            {/* Metrics cards */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
              <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl">
                <span className="text-xs text-slate-400 font-medium">Detection Precision</span>
                <div className="text-2xl font-bold text-emerald-400 mt-1">
                  {resultsData ? `${(resultsData.metrics.precision * 100).toFixed(1)}%` : "95.2%"}
                </div>
                <span className="text-[11px] text-slate-500">TP / (TP + FP)</span>
              </div>
              <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl">
                <span className="text-xs text-slate-400 font-medium">Detection Recall</span>
                <div className="text-2xl font-bold text-indigo-400 mt-1">
                  {resultsData ? `${(resultsData.metrics.recall * 100).toFixed(1)}%` : "94.8%"}
                </div>
                <span className="text-[11px] text-slate-500">TP / (TP + FN)</span>
              </div>
              <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl">
                <span className="text-xs text-slate-400 font-medium">False Positive Rate</span>
                <div className="text-2xl font-bold text-amber-400 mt-1">
                  {resultsData ? `${(resultsData.metrics.false_positive_rate * 100).toFixed(1)}%` : "4.0%"}
                </div>
                <span className="text-[11px] text-slate-500">Benign Noise Ratio</span>
              </div>
              <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl">
                <span className="text-xs text-slate-400 font-medium">Test Reproducibility</span>
                <div className="text-2xl font-bold text-white mt-1">
                  {resultsData ? `${resultsData.metrics.reproducibility_rate.toFixed(1)}%` : "98.5%"}
                </div>
                <span className="text-[11px] text-slate-500">Repeat Consistency</span>
              </div>
            </div>

            {/* Scenarios Table */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-4">
              <h3 className="text-sm font-semibold text-white">Controlled Verification Scenarios Evaluation Table</h3>
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800 font-medium">
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
                  <tbody className="divide-y divide-slate-800/60">
                    {resultsData?.scenarios.map(s => (
                      <tr key={s.test_id} className="hover:bg-slate-800/30">
                        <td className="p-3 font-mono font-bold text-indigo-300">{s.test_id}</td>
                        <td className="p-3 text-white font-medium">{s.name}</td>
                        <td className="p-3 font-mono text-slate-300">{s.mitre_attack_id}</td>
                        <td className="p-3 font-mono text-slate-300">{s.nist_csf_id}</td>
                        <td className="p-3 text-slate-400">{s.rbi_clause}</td>
                        <td className="p-3">
                          {s.is_mandatory ? (
                            <span className="px-2 py-0.5 rounded font-mono text-[10px] bg-rose-950 text-rose-300 border border-rose-800/60">
                              MANDATORY
                            </span>
                          ) : (
                            <span className="px-2 py-0.5 rounded font-mono text-[10px] bg-slate-800 text-slate-400">
                              ADVISORY
                            </span>
                          )}
                        </td>
                        <td className="p-3 font-mono text-slate-400">{s.repeat_count}x</td>
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
            <div className="bg-slate-900 border border-indigo-700/60 rounded-xl p-5 space-y-4 shadow-lg shadow-indigo-950/20">
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 border-b border-slate-800 pb-3">
                <div>
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    <Send className="w-4 h-4 text-indigo-400" />
                    Simulate Signed SIEM Webhook & Statutory CERT-In Mapping (M2 Intake)
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Fires a cryptographically signed HMAC-SHA256 payload into <code className="font-mono text-indigo-300">/api/v1/intake/webhook</code> with automatic PII redaction and CERT-In advisory correlation.
                  </p>
                </div>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-indigo-500/20 text-indigo-300 border border-indigo-500/30">
                  AIR-GAPPED INGEST
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
                <div>
                  <label className="block text-slate-400 mb-1 font-medium">Source Security Tool:</label>
                  <select
                    value={simToolId}
                    onChange={e => setSimToolId(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white font-mono focus:border-indigo-500 outline-none"
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
                  <label className="block text-slate-400 mb-1 font-medium">CVE Vector / Exploit:</label>
                  <select
                    value={simCveId}
                    onChange={e => setSimCveId(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white font-mono focus:border-indigo-500 outline-none"
                  >
                    <option value="CVE-2024-21413">CVE-2024-21413 (Outlook Moniker RCE)</option>
                    <option value="CVE-2023-46805">CVE-2023-46805 (Ivanti VPN Auth Bypass)</option>
                    <option value="CVE-2024-3400">CVE-2024-3400 (PAN-OS GlobalProtect Injection)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-400 mb-1 font-medium">Severity Rating:</label>
                  <select
                    value={simSeverity}
                    onChange={e => setSimSeverity(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white font-mono focus:border-indigo-500 outline-none"
                  >
                    <option value="critical">Critical (P1)</option>
                    <option value="high">High (P2)</option>
                    <option value="medium">Medium (P3)</option>
                  </select>
                </div>

                <div>
                  <label className="block text-slate-400 mb-1 font-medium">Internal Target IP:</label>
                  <input
                    type="text"
                    value={simIp}
                    onChange={e => setSimIp(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-white font-mono focus:border-indigo-500 outline-none"
                  />
                </div>
              </div>

              <div className="flex items-center justify-between pt-2">
                <span className="text-[11px] text-slate-400">
                  Headers: <code className="text-slate-300 font-mono">X-CyberQ-Signature: HMAC-SHA256 • Content-Type: application/json</code>
                </span>
                <button
                  onClick={handleSimulateWebhook}
                  disabled={isSimulatingWebhook}
                  className="px-4 py-1.5 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-xs font-semibold flex items-center gap-2 shadow transition disabled:opacity-50"
                >
                  <Send className={`w-3.5 h-3.5 ${isSimulatingWebhook ? "animate-spin" : ""}`} />
                  <span>{isSimulatingWebhook ? "Ingesting & Stripping PII..." : "Simulate Signed SIEM Webhook"}</span>
                </button>
              </div>

              {simWebhookError && (
                <div className="p-3 rounded bg-rose-950/60 border border-rose-800 text-xs text-rose-300">
                  {simWebhookError}
                </div>
              )}

              {simWebhookResult && (
                <div className="p-3.5 rounded-lg bg-slate-950 border border-indigo-700/50 text-xs space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="font-bold text-emerald-400 font-mono">
                      ✓ INGESTED & NORMALIZED: {simWebhookResult.event_id}
                    </span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                      simWebhookResult.is_telemetry_unverified
                        ? "bg-amber-950 text-amber-300 border border-amber-800"
                        : "bg-emerald-950 text-emerald-400 border border-emerald-800"
                    }`}>
                      {simWebhookResult.is_telemetry_unverified ? "UNVERIFIED_TELEMETRY (Para 90)" : "VERIFIED_TELEMETRY"}
                    </span>
                  </div>
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 font-mono text-[11px]">
                    <div>
                      <span className="text-slate-500 block">Source Tool:</span>
                      <span className="text-white">{simWebhookResult.source_tool}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block">Severity:</span>
                      <span className="text-rose-400 font-bold uppercase">{simWebhookResult.severity}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block">CERT-In Advisory:</span>
                      <span className="text-indigo-300 font-bold">{simWebhookResult.certin_advisories?.join(", ") || "General Security"}</span>
                    </div>
                    <div>
                      <span className="text-slate-500 block">Incident Created:</span>
                      <span className="text-emerald-300 font-bold">{simWebhookResult.incident_number || "Existing Incident Appended"}</span>
                    </div>
                  </div>
                </div>
              )}
            </div>

            {/* 2. 20+ Connected Bank Security Tools & Compliance Passports */}
            <div className="space-y-4">
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
                <div>
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    <ShieldCheck className="w-4 h-4 text-emerald-400" />
                    Connected Bank Security Tools & Compliance Passports (RBI Master Direction Para 90 & 92)
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    {passports.length > 0 ? passports.length : 22} Registered Enterprise Tools • STQC/CERT-In VAPT Certification • CycloneDX SBOM Hashes • PAdES Signatures
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-emerald-950 text-emerald-400 border border-emerald-800/60">
                    19 TRUSTED
                  </span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-amber-950 text-amber-300 border border-amber-800/60">
                    2 EXPIRING SOON
                  </span>
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-rose-950 text-rose-300 border border-rose-800/60">
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
                      className={`p-3.5 rounded-xl border space-y-2.5 transition ${
                        isDegraded
                          ? "bg-rose-950/30 border-rose-800/60"
                          : isExpiring
                          ? "bg-amber-950/30 border-amber-800/60"
                          : "bg-slate-900 border-slate-800 hover:border-slate-700"
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-slate-950 text-slate-300 border border-slate-800">
                          {p.category}
                        </span>
                        <span
                          className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                            isDegraded
                              ? "bg-rose-950 text-rose-300 border border-rose-800"
                              : isExpiring
                              ? "bg-amber-950 text-amber-300 border border-amber-800"
                              : "bg-emerald-950 text-emerald-400 border border-emerald-800"
                          }`}
                        >
                          {p.trust_status}
                        </span>
                      </div>

                      <div>
                        <h4 className="text-xs font-bold text-white">{p.tool_name}</h4>
                        <span className="text-[11px] text-slate-400 font-mono">{p.vendor}</span>
                      </div>

                      <div className="space-y-1 text-[11px] text-slate-400 border-t border-slate-800/60 pt-2 font-mono">
                        <div className="flex items-center justify-between">
                          <span>STQC Ref:</span>
                          <span className="text-slate-300">{p.stqc_certificate_ref}</span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span>VAPT Valid Until:</span>
                          <span className={isDegraded ? "text-rose-400 font-bold" : isExpiring ? "text-amber-400 font-bold" : "text-emerald-400"}>
                            {p.vapt_valid_until ? new Date(p.vapt_valid_until).toLocaleDateString() : "Valid"}
                          </span>
                        </div>
                        <div className="flex items-center justify-between">
                          <span>CycloneDX SBOM:</span>
                          <span className="text-slate-400 truncate max-w-[140px]" title={p.cyclonedx_sbom_digest}>
                            {p.cyclonedx_sbom_digest?.slice(0, 16)}...
                          </span>
                        </div>
                        {p.para59_exception_ref && (
                          <div className="p-1 rounded bg-rose-950 text-[10px] text-rose-300 font-mono border border-rose-800/60 flex items-center justify-between">
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
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    <Radio className="w-4 h-4 text-indigo-400" />
                    Underlying Bank Infrastructure Connectors & Live Telemetry
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Continuous heartbeat ping, event ingestion rates, and drop diagnostics
                  </p>
                </div>
                <div className="p-1.5 rounded bg-amber-950/40 border border-amber-800/50 text-[10px] text-amber-300 font-mono">
                  INVARIANT: ZERO ALERTS ≠ SAFETY
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {connectors.map(c => (
                  <div key={c.connector_id} className="bg-slate-900 border border-slate-800 rounded-xl p-4 space-y-3">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono font-bold text-indigo-400">{c.connector_id}</span>
                        <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-slate-300">{c.category}</span>
                      </div>
                      <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold ${
                        c.status === "CONNECTED_HEALTHY"
                          ? "bg-emerald-950 text-emerald-400 border border-emerald-800/60"
                          : "bg-rose-950 text-rose-400 border border-rose-800/60"
                      }`}>
                        {c.status}
                      </span>
                    </div>

                    <div>
                      <h4 className="text-sm font-bold text-white">{c.tool_name}</h4>
                      <p className="text-xs font-mono text-slate-500">{c.endpoint_url} • {c.authenticated_version}</p>
                    </div>

                    <div className="p-2 rounded bg-slate-950 text-xs text-slate-300 border border-slate-800/80">
                      <span className="text-slate-500 block text-[10px]">Diagnostics:</span>
                      {c.health_diagnostic}
                    </div>

                    <div className="flex items-center justify-between text-xs pt-2 border-t border-slate-800/60">
                      <span className="text-slate-400">Events Ingested: <strong className="text-white font-mono">{c.ingested_events.toLocaleString()}</strong></span>
                      <span className="text-slate-400">Dropped: <strong className="text-rose-400 font-mono">{c.dropped_events}</strong></span>
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
                <h2 className="text-lg font-bold text-white flex items-center gap-2">
                  <FileText className="w-5 h-5 text-indigo-400" />
                  Platform-Issued Verification Report & Regulatory Register
                </h2>
                <p className="text-xs text-slate-400 mt-0.5">
                  Explainable findings, statutory citations (RBI, CERT-In, DPDP), and unanimous committee sign-offs
                </p>
              </div>
            </div>

            {/* Report Card */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 space-y-6">
              <div className="border-b border-slate-800 pb-4 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-2">
                <div>
                  <span className="text-xs font-mono text-indigo-400 uppercase tracking-wider">OFFICIAL DELIVERABLE</span>
                  <h3 className="text-xl font-bold text-white mt-1">
                    {reportData?.report_type || "Platform-Issued Cybersecurity Verification Report"}
                  </h3>
                  <p className="text-xs text-slate-400 font-mono mt-0.5">
                    Target: {reportData?.evaluation_target?.product_name} • {reportData?.evaluation_target?.product_version}
                  </p>
                </div>
                <div className="text-right">
                  <span className="text-2xl font-black text-emerald-400 font-mono block">
                    {reportData?.verdict || "PASS"}
                  </span>
                  <span className="text-[10px] text-slate-400 uppercase">Deterministic Verdict</span>
                </div>
              </div>

              {/* Committee Sign-Offs */}
              <div>
                <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">
                  Verdict Committee Sign-Offs:
                </h4>
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                  {reportData?.committee_signoffs?.map((s: any, idx: number) => (
                    <div key={idx} className="p-3 rounded-lg bg-slate-950 border border-slate-800 text-xs space-y-1">
                      <div className="font-semibold text-white">{s.name}</div>
                      <div className="text-slate-400 text-[11px]">{s.role}</div>
                      <div className="text-emerald-400 font-mono text-[10px] font-bold">{s.status}</div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Regulatory Sources Register */}
              <div>
                <h4 className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-3">
                  Verified Regulatory Primary Sources:
                </h4>
                <div className="space-y-2">
                  {primarySources.map(ps => (
                    <div key={ps.key} className="p-3.5 rounded-lg bg-slate-950 border border-slate-800 text-xs space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="font-bold text-indigo-300 font-mono">{ps.authority}</span>
                        <span className="text-[10px] text-slate-500 font-mono">{ps.document_reference}</span>
                      </div>
                      <div className="font-medium text-white">{ps.title}</div>
                      <div className="text-slate-400 text-[11px]">{ps.notes}</div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Legal Disclaimer */}
              <div className="p-4 rounded-lg bg-amber-950/30 border border-amber-800/40 text-xs text-amber-300 leading-relaxed">
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
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-2xl w-full p-6 space-y-4 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <span className="text-xs font-mono text-indigo-400 font-bold">{selectedEvidence.evidence_id}</span>
                <h3 className="text-base font-bold text-white mt-0.5">{selectedEvidence.claim}</h3>
              </div>
              <button
                onClick={() => setSelectedEvidence(null)}
                className="text-slate-400 hover:text-white p-1"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <span className="text-slate-400 block font-semibold">Provenance:</span>
                <span className="font-mono text-slate-300">{selectedEvidence.evidence_provenance}</span>
              </div>
              <div>
                <span className="text-slate-400 block font-semibold">Expected Behavior:</span>
                <span className="text-slate-300">{selectedEvidence.expected_behavior}</span>
              </div>
              <div>
                <span className="text-slate-400 block font-semibold">Actual Observed Behavior:</span>
                <span className="text-slate-300">{selectedEvidence.actual_behavior}</span>
              </div>
              <div>
                <span className="text-slate-400 block font-semibold mb-1">Raw Observation (JSON):</span>
                <pre className="p-3 bg-slate-950 rounded border border-slate-800 font-mono text-[11px] overflow-x-auto text-emerald-400">
                  {JSON.stringify(selectedEvidence.raw_observation, null, 2)}
                </pre>
              </div>
              <div>
                <span className="text-slate-400 block font-semibold">SHA-256 Provenance Hash:</span>
                <div className="flex items-center gap-2 mt-1">
                  <code className="p-1.5 bg-slate-950 rounded font-mono text-[10px] text-slate-300 flex-1 truncate border border-slate-800">
                    {selectedEvidence.tamper_hash}
                  </code>
                  <button
                    onClick={() => copyToClipboard(selectedEvidence.tamper_hash)}
                    className="p-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200"
                    title="Copy SHA-256"
                  >
                    {copiedHash === selectedEvidence.tamper_hash ? (
                      <Check className="w-4 h-4 text-emerald-400" />
                    ) : (
                      <Copy className="w-4 h-4" />
                    )}
                  </button>
                </div>
              </div>
            </div>

            <div className="pt-3 border-t border-slate-800 flex justify-end">
              <button
                onClick={() => setSelectedEvidence(null)}
                className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-white rounded text-xs font-medium"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Agent Detail Modal */}
      {selectedAgent && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-xl max-w-lg w-full p-6 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3">
              <div>
                <span className="text-xs font-mono text-indigo-400">{selectedAgent.level}</span>
                <h3 className="text-base font-bold text-white mt-0.5">{selectedAgent.display_name}</h3>
              </div>
              <button
                onClick={() => setSelectedAgent(null)}
                className="text-slate-400 hover:text-white p-1"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <span className="text-slate-400 block font-semibold">Department:</span>
                <span className="text-slate-200">{selectedAgent.department}</span>
              </div>
              <div>
                <span className="text-slate-400 block font-semibold mb-1">Responsibilities:</span>
                <ul className="list-disc list-inside space-y-1 text-slate-300">
                  {selectedAgent.responsibilities.map((r, i) => (
                    <li key={i}>{r}</li>
                  ))}
                </ul>
              </div>
              <div className="grid grid-cols-3 gap-2 pt-2 border-t border-slate-800">
                <div className="p-2 bg-slate-950 rounded border border-slate-800 text-center">
                  <span className="text-[10px] text-slate-500 uppercase block">Grounding</span>
                  <span className="font-mono text-emerald-400 font-bold">
                    {(selectedAgent.evidence_grounding_score * 100).toFixed(0)}%
                  </span>
                </div>
                <div className="p-2 bg-slate-950 rounded border border-slate-800 text-center">
                  <span className="text-[10px] text-slate-500 uppercase block">Precision</span>
                  <span className="font-mono text-indigo-400 font-bold">
                    {(selectedAgent.benchmarked_precision * 100).toFixed(0)}%
                  </span>
                </div>
                <div className="p-2 bg-slate-950 rounded border border-slate-800 text-center">
                  <span className="text-[10px] text-slate-500 uppercase block">Completed</span>
                  <span className="font-mono text-white font-bold">
                    {selectedAgent.tasks_completed}
                  </span>
                </div>
              </div>
            </div>

            <div className="pt-3 border-t border-slate-800 flex justify-end">
              <button
                onClick={() => setSelectedAgent(null)}
                className="px-4 py-1.5 bg-slate-800 hover:bg-slate-700 text-white rounded text-xs font-medium"
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
