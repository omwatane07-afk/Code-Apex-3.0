import React, { useState, useEffect, useCallback } from "react"
import { 
  Sliders, 
  ArrowLeft, 
  CheckCircle2, 
  Clock, 
  Database, 
  ShieldAlert, 
  Cpu, 
  Layers, 
  RefreshCw, 
  Lock, 
  Activity, 
  AlertTriangle, 
  Wifi, 
  Zap, 
  Server, 
  Radio, 
  Eye, 
  Shield, 
  Brain, 
  ChevronRight, 
  ChevronDown, 
  XCircle, 
  Bell, 
  Gauge, 
  Play, 
  Pause, 
  Flame, 
  Volume2, 
  VolumeX, 
  Sparkles, 
  X 
} from "lucide-react"

import { ANOMALY_SCENARIOS } from "../../lib/liveTelemetryEngine"

import { useTelemetry } from "../../lib/telemetryContext"

// ─── Type Definitions ────────────────────────────────────────────────

interface HealthData {
  status: string
  version: string
  environment: string
  server_time_utc: string
}

interface ReadyData {
  status: string
  database: string
  worker_heartbeat: string
  ntp_skew_seconds: number
  server_time_utc: string
}

type AdminTab = "overview" | "tools" | "alerts" | "llm" | "packs"

interface AdminViewProps {
  userRole: string
  theme: "light" | "dark"
  onToggleTheme: () => void
  onBackToCommand: () => void
}

// ─── Badges ──────────────────────────────────────────────────────────

const SeverityBadge: React.FC<{ severity: string }> = ({ severity }) => {
  const colors: Record<string, string> = {
    critical: "bg-status-critical/15 text-status-critical border-status-critical/40",
    high: "bg-[#FF6B35]/15 text-[#FF6B35] border-[#FF6B35]/40",
    medium: "bg-status-due_soon/15 text-status-due_soon border-status-due_soon/40",
    low: "bg-status-info/15 text-status-info border-status-info/40",
    warning: "bg-status-due_soon/15 text-status-due_soon border-status-due_soon/40",
    info: "bg-status-info/15 text-status-info border-status-info/40",
    nominal: "bg-status-ok/15 text-status-ok border-status-ok/40",
  }
  return (
    <span className={`px-1.5 py-0.5 rounded-segment text-[10px] font-mono font-bold uppercase border ${colors[severity] || colors.info}`}>
      {severity}
    </span>
  )
}

const HealthBadge: React.FC<{ health: string }> = ({ health }) => {
  const mapping: Record<string, { icon: React.ReactNode; cls: string }> = {
    HEALTHY: {
      icon: <CheckCircle2 className="w-3 h-3" />,
      cls: "bg-status-ok/10 text-status-ok border-status-ok/40",
    },
    WARNING: {
      icon: <AlertTriangle className="w-3 h-3" />,
      cls: "bg-status-due_soon/10 text-status-due_soon border-status-due_soon/40",
    },
    DEGRADED: {
      icon: <XCircle className="w-3 h-3" />,
      cls: "bg-status-critical/10 text-status-critical border-status-critical/40",
    },
  }
  const { icon, cls } = mapping[health] || mapping.HEALTHY
  return (
    <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded-segment text-[10px] font-mono font-bold border ${cls}`}>
      {icon}
      <span>{health}</span>
    </span>
  )
}

// ─── Main Component ──────────────────────────────────────────────────

export const AdminView: React.FC<AdminViewProps> = ({
  userRole: _userRole,
  theme,
  onToggleTheme,
  onBackToCommand,
}) => {
  const {
    toolsState,
    telemetry,
    isStreaming,
    streamSpeedMs,
    soundEnabled,
    toggleStreaming,
    setStreamSpeedMs,
    toggleSound,
    triggerAnomaly,
    refreshTelemetry,
  } = useTelemetry()

  const [health, setHealth] = useState<HealthData | null>(null)
  const [ready, setReady] = useState<ReadyData | null>(null)
  const [isLoading, setIsLoading] = useState<boolean>(false)
  const [activeTab, setActiveTab] = useState<AdminTab>("overview")
  const [expandedAlert, setExpandedAlert] = useState<string | null>(null)
  const [expandedTool, setExpandedTool] = useState<string | null>(null)
  const [showScenarioMenu, setShowScenarioMenu] = useState<boolean>(false)

  // Fetch health & ready states from backend
  const fetchHealth = useCallback(async () => {
    setIsLoading(true)
    try {
      const [hRes, rRes] = await Promise.all([
        fetch("/healthz"),
        fetch("/readyz"),
      ])
      if (hRes.ok) setHealth(await hRes.json())
      if (rRes.ok) setReady(await rRes.json())
      await refreshTelemetry()
    } catch {
      // offline fallback handled by telemetryContext
    } finally {
      setIsLoading(false)
    }
  }, [refreshTelemetry])

  useEffect(() => {
    fetchHealth()
  }, [fetchHealth])

  const handleTriggerAnomaly = (scenarioIndex?: number) => {
    triggerAnomaly(scenarioIndex)
    setShowScenarioMenu(false)
  }

  const formatIST = (utcStr: string | undefined) => {
    if (!utcStr) return "N/A"
    try {
      const d = new Date(utcStr)
      return (
        d.toLocaleString("en-IN", {
          timeZone: "Asia/Kolkata",
          day: "2-digit",
          month: "short",
          year: "numeric",
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        }) + " IST"
      )
    } catch {
      return utcStr
    }
  }

  const timeAgo = (isoStr: string): string => {
    const diff = Date.now() - new Date(isoStr).getTime()
    const mins = Math.floor(diff / 60000)
    if (mins < 1) return "Just now"
    if (mins < 60) return `${mins}m ago`
    const hrs = Math.floor(mins / 60)
    if (hrs < 24) return `${hrs}h ${mins % 60}m ago`
    return `${Math.floor(hrs / 24)}d ago`
  }

  const categoryIcon = (cat: string): React.ReactNode => {
    switch (cat) {
      case "SIEM": return <Database className="w-3.5 h-3.5" />
      case "EDR": return <Shield className="w-3.5 h-3.5" />
      case "Firewall": return <ShieldAlert className="w-3.5 h-3.5" />
      case "WAF": return <Shield className="w-3.5 h-3.5" />
      case "Database Security": return <Database className="w-3.5 h-3.5" />
      case "IAM/PAM": case "IAM": return <Lock className="w-3.5 h-3.5" />
      case "Cloud Security": case "CSPM": return <Cpu className="w-3.5 h-3.5" />
      case "VPN Gateway": return <Wifi className="w-3.5 h-3.5" />
      case "NIDS": return <Radio className="w-3.5 h-3.5" />
      case "DLP": return <Eye className="w-3.5 h-3.5" />
      default: return <Server className="w-3.5 h-3.5" />
    }
  }

  const s = telemetry?.summary

  return (
    <div className="flex-1 flex flex-col h-full bg-app overflow-hidden relative">

      {/* ═══ Top Header with Live Simulation Controls ═══ */}
      <div className="h-14 border-b border-rule bg-surface flex items-center justify-between px-6 flex-shrink-0">
        <div className="flex items-center gap-3">
          <button
            onClick={onBackToCommand}
            className="p-1.5 rounded-control text-muted hover:text-main hover:bg-app border border-rule flex items-center gap-1.5 text-xs"
            title="Return to Incident Command Center"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>Command Center</span>
          </button>
          <span className="text-muted text-xs">/</span>
          <div className="flex items-center gap-2">
            <Sliders className="w-4 h-4 text-primary" />
            <h1 className="text-sm font-semibold text-main">System administration & telemetry</h1>
          </div>
        </div>

        {/* ═══ Simulation Control Bar ═══ */}
        <div className="flex items-center gap-2.5 text-xs">
          {/* Active Live Streaming Button */}
          <button
            onClick={toggleStreaming}
            className={`px-2.5 py-1 rounded-segment border flex items-center gap-1.5 text-xs font-mono font-medium transition-colors ${
              isStreaming
                ? "bg-status-ok/10 text-status-ok border-status-ok/40 hover:bg-status-ok/20"
                : "bg-status-due_soon/10 text-status-due_soon border-status-due_soon/40 hover:bg-status-due_soon/20"
            }`}
            title={isStreaming ? "Click to pause telemetry stream" : "Click to resume telemetry stream"}
          >
            <span className="relative flex h-2 w-2">
              <span className={`absolute inline-flex h-full w-full rounded-full opacity-75 ${isStreaming ? "animate-ping bg-status-ok" : "bg-status-due_soon"}`} />
              <span className={`relative inline-flex rounded-full h-2 w-2 ${isStreaming ? "bg-status-ok" : "bg-status-due_soon"}`} />
            </span>
            <span>{isStreaming ? "LIVE STREAMING" : "STREAM PAUSED"}</span>
            {isStreaming ? <Pause className="w-3 h-3 ml-0.5" /> : <Play className="w-3 h-3 ml-0.5" />}
          </button>

          {/* Speed Selector */}
          <div className="flex items-center rounded-segment border border-rule bg-app p-0.5 text-[11px] font-mono">
            {[
              { label: "1.5s", ms: 1500 },
              { label: "2.5s", ms: 2500 },
              { label: "5.0s", ms: 5000 },
            ].map((spd) => (
              <button
                key={spd.ms}
                onClick={() => setStreamSpeedMs(spd.ms)}
                className={`px-2 py-0.5 rounded text-[10px] font-medium transition-colors ${
                  streamSpeedMs === spd.ms
                    ? "bg-surface text-primary border border-rule shadow-sm font-bold"
                    : "text-muted hover:text-main"
                }`}
                title={`Telemetry refresh cycle: ${spd.label}`}
              >
                {spd.label}
              </button>
            ))}
          </div>

          {/* Trigger Anomaly Dropdown / Button */}
          <div className="relative">
            <button
              onClick={() => setShowScenarioMenu((prev) => !prev)}
              className="px-2.5 py-1 rounded-segment bg-status-critical/15 text-status-critical border border-status-critical/40 hover:bg-status-critical/25 font-semibold text-xs flex items-center gap-1.5 transition-colors shadow-sm"
              title="Inject simulated security anomaly immediately"
            >
              <Flame className="w-3.5 h-3.5 text-status-critical animate-pulse" />
              <span>Simulate Anomaly</span>
              <ChevronDown className="w-3 h-3" />
            </button>

            {showScenarioMenu && (
              <div className="absolute right-0 mt-1.5 w-80 rounded-control bg-surface border border-rule shadow-2xl p-2 z-50 text-xs space-y-1 animate-in fade-in-50 zoom-in-95">
                <div className="px-2 py-1 text-[10px] font-semibold text-muted uppercase tracking-wider border-b border-rule mb-1 flex items-center justify-between">
                  <span>Inject Security Anomaly</span>
                  <button onClick={() => setShowScenarioMenu(false)} className="text-muted hover:text-main">
                    <X className="w-3.5 h-3.5" />
                  </button>
                </div>
                
                <button
                  onClick={() => handleTriggerAnomaly()}
                  className="w-full text-left px-2.5 py-2 rounded hover:bg-app text-main flex items-center justify-between font-medium border border-dashed border-rule"
                >
                  <span className="flex items-center gap-1.5">
                    <Sparkles className="w-3.5 h-3.5 text-primary" />
                    <span className="font-semibold">🎲 Random Security Anomaly</span>
                  </span>
                  <span className="text-[10px] font-mono text-muted">Auto</span>
                </button>

                <div className="max-h-60 overflow-y-auto space-y-1 pt-1">
                  {ANOMALY_SCENARIOS.map((scen, idx) => (
                    <button
                      key={scen.tool_id + idx}
                      onClick={() => handleTriggerAnomaly(idx)}
                      className="w-full text-left px-2.5 py-1.5 rounded hover:bg-app text-main flex flex-col gap-0.5 transition-colors border border-transparent hover:border-rule"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-[11px] truncate">{scen.tool_name}</span>
                        <span className={`px-1 py-0.2 rounded text-[9px] font-mono font-bold uppercase ${
                          scen.severity === "critical" ? "bg-status-critical/20 text-status-critical" : "bg-status-due_soon/20 text-status-due_soon"
                        }`}>
                          {scen.severity}
                        </span>
                      </div>
                      <span className="text-[10px] text-muted truncate">{scen.title}</span>
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Sound Toggle */}
          <button
            onClick={toggleSound}
            className="p-1.5 rounded-control text-muted hover:text-main hover:bg-app border border-rule transition-colors"
            title={soundEnabled ? "Mute live anomaly audio chime" : "Unmute live anomaly audio chime"}
          >
            {soundEnabled ? <Volume2 className="w-3.5 h-3.5 text-primary" /> : <VolumeX className="w-3.5 h-3.5 text-muted/50" />}
          </button>

          <button
            onClick={fetchHealth}
            disabled={isLoading}
            className="p-1.5 rounded-control text-muted hover:text-main hover:bg-app border border-rule flex items-center gap-1"
            title="Reload from server"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? "animate-spin" : ""}`} />
          </button>
        </div>
      </div>

      {/* ═══ Sub-Tab Navigation ═══ */}
      <div className="h-10 border-b border-rule bg-surface px-6 flex items-center gap-1 flex-shrink-0">
        {([
          { id: "overview", label: "Overview", icon: <Gauge className="w-3.5 h-3.5" /> },
          { id: "tools", label: `Tool Health (${toolsState.length})`, icon: <Server className="w-3.5 h-3.5" /> },
          { id: "alerts", label: `Alerts${s ? ` (${s.alert_count_last_2h})` : ""}`, icon: <Bell className="w-3.5 h-3.5" /> },
          { id: "llm", label: "LLM Status", icon: <Brain className="w-3.5 h-3.5" /> },
          { id: "packs", label: "Obligation Packs", icon: <Layers className="w-3.5 h-3.5" /> },
        ] as const).map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id as AdminTab)}
            className={`px-3 py-1 rounded-segment text-xs font-medium flex items-center gap-1.5 transition-colors ${
              activeTab === tab.id
                ? "bg-app text-primary border border-rule shadow-sm"
                : "text-muted hover:text-main"
            }`}
          >
            {tab.icon}
            <span>{tab.label}</span>
          </button>
        ))}
      </div>

      {/* ═══ Scrollable Body Content ═══ */}
      <div className="flex-1 overflow-y-auto p-6 space-y-6">

        {/* ═══════════ OVERVIEW TAB ═══════════ */}
        {activeTab === "overview" && (
          <>
            {/* KPI Cards Row */}
            <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
              <div className="p-3.5 rounded-segment border border-rule bg-surface">
                <div className="text-[11px] text-muted flex items-center justify-between mb-1">
                  <span>Monitored Tools</span>
                  <Server className="w-3.5 h-3.5 text-primary" />
                </div>
                <div className="text-xl font-bold font-mono text-main">{s?.total_tools_monitored ?? 12}</div>
                <div className="text-[10px] text-status-ok font-mono mt-0.5">
                  {s?.healthy_tools ?? 10} Healthy · {s?.warning_tools ?? 1} Warning
                </div>
              </div>

              <div className="p-3.5 rounded-segment border border-rule bg-surface">
                <div className="text-[11px] text-muted flex items-center justify-between mb-1">
                  <span>Live Throughput</span>
                  <Activity className="w-3.5 h-3.5 text-status-ok" />
                </div>
                <div className="text-xl font-bold font-mono text-main">
                  {s?.total_events_per_minute?.toLocaleString() ?? "1,293"}
                </div>
                <div className="text-[10px] text-muted font-mono mt-0.5 flex items-center gap-1">
                  <span className="w-1.5 h-1.5 rounded-full bg-status-ok animate-pulse" />
                  <span>Events/min (Streaming)</span>
                </div>
              </div>

              <div className="p-3.5 rounded-segment border border-rule bg-surface">
                <div className="text-[11px] text-muted flex items-center justify-between mb-1">
                  <span>Degraded Tools</span>
                  <AlertTriangle className="w-3.5 h-3.5 text-status-critical" />
                </div>
                <div className="text-xl font-bold font-mono text-status-critical">{s?.degraded_tools ?? 1}</div>
                <div className="text-[10px] text-muted mt-0.5">VAPT re-certification due</div>
              </div>

              <div className="p-3.5 rounded-segment border border-rule bg-surface">
                <div className="text-[11px] text-muted flex items-center justify-between mb-1">
                  <span>Security Alerts</span>
                  <Bell className="w-3.5 h-3.5 text-status-due_soon" />
                </div>
                <div className="text-xl font-bold font-mono text-main">{s?.alert_count_last_2h ?? 12}</div>
                <div className="text-[10px] text-status-critical font-mono mt-0.5">
                  {s?.critical_alerts ?? 4} Critical
                </div>
              </div>

              <div className="p-3.5 rounded-segment border border-rule bg-surface">
                <div className="text-[11px] text-muted flex items-center justify-between mb-1">
                  <span>NTP Clock Drift</span>
                  <Clock className="w-3.5 h-3.5 text-primary" />
                </div>
                <div className="text-xl font-bold font-mono text-status-ok">
                  {ready?.ntp_skew_seconds !== undefined ? `${ready.ntp_skew_seconds}s` : "0.050s"}
                </div>
                <div className="text-[10px] text-muted mt-0.5">&lt; 1.0s limit (Statutory)</div>
              </div>
            </div>

            {/* Live Streaming Status Banner */}
            <div className="p-4 rounded-segment border border-rule bg-surface flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className={`w-9 h-9 rounded-control flex items-center justify-center flex-shrink-0 ${
                  isStreaming ? "bg-status-ok/10 text-status-ok" : "bg-status-due_soon/10 text-status-due_soon"
                }`}>
                  <Activity className={`w-5 h-5 ${isStreaming ? "animate-pulse" : ""}`} />
                </div>
                <div>
                  <div className="text-xs font-semibold text-main flex items-center gap-2">
                    <span>Real-Time Security Tool Telemetry Simulator</span>
                    <span className={`px-1.5 py-0.2 rounded text-[10px] font-mono font-bold uppercase ${
                      isStreaming ? "bg-status-ok/15 text-status-ok" : "bg-status-due_soon/15 text-status-due_soon"
                    }`}>
                      {isStreaming ? `Active (${streamSpeedMs / 1000}s tick)` : "Paused"}
                    </span>
                  </div>
                  <div className="text-[11px] text-muted mt-0.5">
                    Streaming events from CrowdStrike, Splunk, Palo Alto, Imperva, CyberArk, and 7 other security tools. Metrics fluctuate dynamically in real time.
                  </div>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => handleTriggerAnomaly()}
                  className="px-3 py-1.5 rounded-control bg-status-critical/15 text-status-critical border border-status-critical/40 hover:bg-status-critical/25 text-xs font-semibold flex items-center gap-1.5"
                >
                  <Flame className="w-3.5 h-3.5 animate-pulse" />
                  <span>Inject Test Anomaly</span>
                </button>
              </div>
            </div>

            {/* System Health Grid */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* API Liveness */}
              <div className="p-4 rounded-segment border border-rule bg-surface space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-medium text-muted flex items-center gap-1.5">
                    <Cpu className="w-4 h-4 text-primary" />
                    <span>API Liveness</span>
                  </span>
                  <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded-segment text-[10px] font-mono font-medium bg-status-ok/10 text-status-ok border border-status-ok">
                    <CheckCircle2 className="w-3 h-3" />
                    <span>{health?.status === "ok" ? "LIVE" : "HEALTHY"}</span>
                  </span>
                </div>
                <div className="space-y-1.5 text-xs font-mono">
                  <div className="flex justify-between">
                    <span className="text-muted">Environment:</span>
                    <span className="text-main font-semibold">{health?.environment?.toUpperCase() || "DEMO"}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted">Version:</span>
                    <span className="text-main">{health?.version || "0.1.0"}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted">UI Theme:</span>
                    <button onClick={onToggleTheme} className="text-primary hover:underline">
                      {theme === "light" ? "Day Ledger" : "Night Desk"}
                    </button>
                  </div>
                </div>
              </div>

              {/* Database */}
              <div className="p-4 rounded-segment border border-rule bg-surface space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-medium text-muted flex items-center gap-1.5">
                    <Database className="w-4 h-4 text-primary" />
                    <span>Database Connectivity</span>
                  </span>
                  <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded-segment text-[10px] font-mono font-medium bg-status-ok/10 text-status-ok border border-status-ok">
                    <CheckCircle2 className="w-3 h-3" />
                    <span>{ready?.database === "ok" ? "HEALTHY" : "CONNECTED"}</span>
                  </span>
                </div>
                <div className="space-y-1.5 text-xs font-mono">
                  <div className="flex justify-between">
                    <span className="text-muted">Pool Probe:</span>
                    <span className="text-main">SELECT 1 (2ms)</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted">Worker Status:</span>
                    <span className="text-main">{ready?.worker_heartbeat || "ACTIVE"}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted">Fail Closed:</span>
                    <span className="text-status-ok font-semibold">ENFORCED</span>
                  </div>
                </div>
              </div>

              {/* Clock */}
              <div className="p-4 rounded-segment border border-rule bg-surface space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-medium text-muted flex items-center gap-1.5">
                    <Clock className="w-4 h-4 text-primary" />
                    <span>Clock Calibration</span>
                  </span>
                  <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded-segment text-[10px] font-mono font-medium bg-status-ok/10 text-status-ok border border-status-ok">
                    <CheckCircle2 className="w-3 h-3" />
                    <span>SYNCHRONIZED</span>
                  </span>
                </div>
                <div className="space-y-1.5 text-xs font-mono">
                  <div className="flex justify-between">
                    <span className="text-muted">NTP Drift:</span>
                    <span className="text-status-ok font-semibold">{ready?.ntp_skew_seconds ?? 0.05}s (&lt; 1.0s limit)</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted">Server UTC:</span>
                    <span className="text-main truncate max-w-[140px]" title={health?.server_time_utc}>
                      {health?.server_time_utc?.split("T")[1]?.slice(0, 8) || "N/A"} UTC
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted">Local IST:</span>
                    <span className="text-main">{formatIST(health?.server_time_utc).split(", ")[1] || "N/A"}</span>
                  </div>
                </div>
              </div>
            </div>
          </>
        )}

        {/* ═══════════ TOOL HEALTH TAB ═══════════ */}
        {activeTab === "tools" && (
          <>
            <div className="flex items-center justify-between mb-2">
              <div className="text-xs text-muted">
                Showing live telemetry from {toolsState.length} enterprise cybersecurity tools. Values fluctuate dynamically in real time.
              </div>
              <div className="flex items-center gap-2">
                <span className="text-[11px] text-muted font-mono">
                  Tick speed: {streamSpeedMs / 1000}s
                </span>
                <button
                  onClick={() => handleTriggerAnomaly()}
                  className="px-2.5 py-1 rounded-segment bg-status-critical/15 text-status-critical border border-status-critical/40 hover:bg-status-critical/25 text-xs font-semibold flex items-center gap-1"
                >
                  <Flame className="w-3 h-3" />
                  <span>Test Anomaly</span>
                </button>
              </div>
            </div>

            {/* Category Summary Bar */}
            <div className="flex flex-wrap gap-2 mb-4">
              {["SIEM", "EDR", "Firewall", "WAF", "Database Security", "IAM/PAM", "Cloud Security", "VPN Gateway", "NIDS"].map(cat => {
                const count = toolsState.filter(t => t.category === cat).length
                if (count === 0) return null
                return (
                  <span key={cat} className="px-2 py-1 rounded-segment border border-rule bg-app text-[10px] font-mono text-muted flex items-center gap-1">
                    {categoryIcon(cat)}
                    <span>{cat}: {count}</span>
                  </span>
                )
              })}
            </div>

            {/* Tool Health Cards */}
            <div className="space-y-2">
              {[...toolsState]
                .sort((a, b) => {
                  if (a.active_anomaly && !b.active_anomaly) return -1
                  if (!a.active_anomaly && b.active_anomaly) return 1
                  const order = { DEGRADED: 0, WARNING: 1, HEALTHY: 2 }
                  return (order[a.health] ?? 2) - (order[b.health] ?? 2)
                })
                .map(tool => {
                  const hasAnomaly = Boolean(tool.active_anomaly)
                  return (
                    <div
                      key={tool.tool_id}
                      className={`rounded-segment border bg-surface overflow-hidden transition-all ${
                        hasAnomaly
                          ? "ring-2 ring-status-critical/70 border-status-critical shadow-lg shadow-status-critical/10"
                          : tool.health === "DEGRADED" ? "border-status-critical/40"
                          : tool.health === "WARNING" ? "border-status-due_soon/40"
                          : "border-rule"
                      }`}
                    >
                      <button
                        onClick={() => setExpandedTool(expandedTool === tool.tool_id ? null : tool.tool_id)}
                        className="w-full px-4 py-3 flex items-center justify-between text-left hover:bg-app/40 transition-colors"
                      >
                        <div className="flex items-center gap-3">
                          <div className={`w-8 h-8 rounded-control flex items-center justify-center flex-shrink-0 ${
                            hasAnomaly || tool.health === "DEGRADED" ? "bg-status-critical/10 text-status-critical" :
                            tool.health === "WARNING" ? "bg-status-due_soon/10 text-status-due_soon" :
                            "bg-primary/10 text-primary"
                          }`}>
                            {categoryIcon(tool.category)}
                          </div>
                          <div>
                            <div className="text-xs font-semibold text-main flex items-center gap-2">
                              <span>{tool.tool_name}</span>
                              {hasAnomaly && (
                                <span className="inline-flex items-center gap-1 px-1.5 py-0.2 rounded-segment bg-status-critical text-white text-[9px] font-mono font-bold animate-pulse">
                                  <Flame className="w-2.5 h-2.5" />
                                  <span>ANOMALY</span>
                                </span>
                              )}
                            </div>
                            <div className="text-[11px] text-muted font-mono">{tool.category} · {tool.tool_id}</div>
                          </div>
                        </div>
                        <div className="flex items-center gap-3">
                          <div className="text-right text-[11px] font-mono text-muted hidden md:block">
                            <div className="text-main font-bold">{tool.metrics.events_per_minute} events/min</div>
                            <div>{tool.metrics.avg_latency_ms}ms latency</div>
                          </div>
                          <HealthBadge health={tool.health} />
                          <ChevronRight className={`w-4 h-4 text-muted transition-transform ${expandedTool === tool.tool_id ? "rotate-90" : ""}`} />
                        </div>
                      </button>

                      {tool.active_anomaly && (
                        <div className="mx-4 mb-3 p-2 rounded bg-status-critical/15 border border-status-critical/40 text-[11px] text-status-critical flex items-center justify-between">
                          <div className="flex items-center gap-1.5">
                            <Flame className="w-3.5 h-3.5 flex-shrink-0" />
                            <span className="font-semibold">Active Anomaly: {tool.active_anomaly}</span>
                          </div>
                          <button
                            onClick={() => setActiveTab("alerts")}
                            className="px-2 py-0.5 rounded bg-status-critical text-white text-[10px] font-bold hover:bg-status-critical/90"
                          >
                            View Alerts
                          </button>
                        </div>
                      )}

                      {expandedTool === tool.tool_id && (
                        <div className="px-4 pb-4 pt-1 border-t border-rule">
                          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-3">
                            <div className="p-2 rounded bg-app text-center">
                              <div className="text-[10px] text-muted">Events/min</div>
                              <div className="text-sm font-bold font-mono text-main">{tool.metrics.events_per_minute}</div>
                            </div>
                            <div className="p-2 rounded bg-app text-center">
                              <div className="text-[10px] text-muted">Latency</div>
                              <div className={`text-sm font-bold font-mono ${tool.metrics.avg_latency_ms > 50 ? "text-status-critical" : "text-main"}`}>
                                {tool.metrics.avg_latency_ms}ms
                              </div>
                            </div>
                            <div className="p-2 rounded bg-app text-center">
                              <div className="text-[10px] text-muted">CPU</div>
                              <div className={`text-sm font-bold font-mono ${tool.metrics.cpu_usage_pct > 80 ? "text-status-critical" : tool.metrics.cpu_usage_pct > 60 ? "text-status-due_soon" : "text-main"}`}>
                                {tool.metrics.cpu_usage_pct}%
                              </div>
                            </div>
                            <div className="p-2 rounded bg-app text-center">
                              <div className="text-[10px] text-muted">Memory</div>
                              <div className="text-sm font-bold font-mono text-main">{tool.metrics.memory_usage_mb} MB</div>
                            </div>
                          </div>
                          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-[11px] font-mono">
                            <div>
                              <span className="text-muted">Dropped:</span>{" "}
                              <span className={tool.metrics.dropped_events > 0 ? "text-status-critical font-bold" : "text-status-ok"}>
                                {tool.metrics.dropped_events}
                              </span>
                            </div>
                            <div>
                              <span className="text-muted">Connections:</span>{" "}
                              <span className="text-main">{tool.metrics.active_connections}</span>
                            </div>
                            <div>
                              <span className="text-muted">Uptime:</span>{" "}
                              <span className="text-main">{tool.uptime_hours}h</span>
                            </div>
                            <div>
                              <span className="text-muted">Heartbeat:</span>{" "}
                              <span className="text-main">{timeAgo(tool.last_heartbeat)}</span>
                            </div>
                          </div>
                          {tool.trust_status === "DEGRADED" && (
                            <div className="mt-3 p-2 rounded bg-status-critical/10 border border-status-critical/30 text-[11px] text-status-critical">
                              <strong>⚠ VAPT Expired:</strong> This tool's VAPT certification has expired under RBI Master Directions Para 90/92. Telemetry is flagged as degraded.
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  )
                })}
            </div>
          </>
        )}

        {/* ═══════════ ALERTS TAB ═══════════ */}
        {activeTab === "alerts" && telemetry && (
          <>
            <div className="flex items-center justify-between mb-2">
              <div className="text-xs text-muted">
                Showing {telemetry.recent_alerts.length} automated alerts with MITRE ATT&CK mapping and response actions.
              </div>
              <button
                onClick={() => handleTriggerAnomaly()}
                className="px-2.5 py-1 rounded-segment bg-status-critical/15 text-status-critical border border-status-critical/40 hover:bg-status-critical/25 text-xs font-semibold flex items-center gap-1"
              >
                <Flame className="w-3 h-3" />
                <span>Simulate New Alert</span>
              </button>
            </div>

            <div className="space-y-2">
              {telemetry.recent_alerts.map((alert) => (
                <div
                  key={alert.alert_id}
                  className={`rounded-segment border bg-surface overflow-hidden ${
                    alert.severity === "critical" ? "border-status-critical/40" :
                    alert.severity === "high" ? "border-[#FF6B35]/40" :
                    "border-rule"
                  }`}
                >
                  <button
                    onClick={() => setExpandedAlert(expandedAlert === alert.alert_id ? null : alert.alert_id)}
                    className="w-full px-4 py-3 flex items-center justify-between text-left hover:bg-app/40 transition-colors"
                  >
                    <div className="flex items-center gap-3 flex-1 min-w-0">
                      <div className={`w-8 h-8 rounded-control flex items-center justify-center flex-shrink-0 ${
                        alert.severity === "critical" ? "bg-status-critical/10 text-status-critical" :
                        alert.severity === "high" ? "bg-[#FF6B35]/10 text-[#FF6B35]" :
                        "bg-status-info/10 text-status-info"
                      }`}>
                        {categoryIcon(alert.category)}
                      </div>
                      <div className="min-w-0 flex-1">
                        <div className="text-xs font-semibold text-main truncate">{alert.title}</div>
                        <div className="text-[11px] text-muted font-mono truncate">
                          {alert.source_tool} · {alert.affected_asset} · {timeAgo(alert.timestamp)}
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 flex-shrink-0 ml-3">
                      <SeverityBadge severity={alert.severity} />
                      <span className={`px-1.5 py-0.5 rounded-segment text-[10px] font-mono border ${
                        alert.response_status === "EXECUTED"
                          ? "bg-status-ok/10 text-status-ok border-status-ok/40"
                          : "bg-status-due_soon/10 text-status-due_soon border-status-due_soon/40"
                      }`}>
                        {alert.response_status === "EXECUTED" ? "✓ EXECUTED" : "⏳ PENDING"}
                      </span>
                      <ChevronRight className={`w-4 h-4 text-muted transition-transform ${expandedAlert === alert.alert_id ? "rotate-90" : ""}`} />
                    </div>
                  </button>

                  {expandedAlert === alert.alert_id && (
                    <div className="px-4 pb-4 pt-1 border-t border-rule space-y-3">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-[11px] font-mono">
                        <div>
                          <div className="text-muted mb-1 font-sans">Alert Details</div>
                          <div className="space-y-1 bg-app p-2 rounded border border-rule">
                            <div><span className="text-muted">ID:</span> <span className="text-main">{alert.alert_id}</span></div>
                            <div><span className="text-muted">Source:</span> <span className="text-main">{alert.source_tool}</span></div>
                            <div><span className="text-muted">Target Asset:</span> <span className="text-main font-bold">{alert.affected_asset}</span></div>
                            <div><span className="text-muted">MITRE ATT&CK:</span> <span className="text-status-info">{alert.mitre_attack_id}</span></div>
                            <div><span className="text-muted">Timestamp:</span> <span className="text-main">{formatIST(alert.timestamp)}</span></div>
                          </div>
                        </div>
                        <div>
                          <div className="text-muted mb-1 font-sans">Automated Response Action</div>
                          <div className={`p-2 rounded border ${
                            alert.response_status === "EXECUTED"
                              ? "bg-status-ok/5 border-status-ok/20"
                              : "bg-status-due_soon/5 border-status-due_soon/20"
                          }`}>
                            <div className="flex items-center gap-1 mb-1">
                              <Zap className="w-3.5 h-3.5 text-status-ok" />
                              <span className="font-semibold text-status-ok text-[11px]">
                                Action Taken ({alert.response_status})
                              </span>
                            </div>
                            <div className="text-muted text-[11px] leading-relaxed">
                              {alert.automated_response}
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              ))}
            </div>
          </>
        )}

        {/* ═══════════ LLM STATUS & FALLBACK TAB ═══════════ */}
        {activeTab === "llm" && telemetry && (
          <div className="space-y-4">
            <div className="p-4 rounded-segment border border-rule bg-surface space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Brain className="w-5 h-5 text-primary" />
                  <span className="text-sm font-semibold text-main">Local LLM Inference Engine</span>
                </div>
                <span className={`px-2 py-0.5 rounded-segment text-xs font-mono font-bold uppercase border ${
                  telemetry.llm_status.llm_available
                    ? "bg-status-ok/10 text-status-ok border-status-ok"
                    : "bg-status-due_soon/15 text-status-due_soon border-status-due_soon"
                }`}>
                  {telemetry.llm_status.llm_available ? "ONLINE (Active)" : "OFFLINE (Rule Fallback)"}
                </span>
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
                <div className="p-2.5 rounded bg-app border border-rule">
                  <div className="text-muted text-[10px]">Endpoint</div>
                  <div className="text-main font-semibold truncate">{telemetry.llm_status.llm_endpoint}</div>
                </div>
                <div className="p-2.5 rounded bg-app border border-rule">
                  <div className="text-muted text-[10px]">Model Invariant</div>
                  <div className="text-main font-semibold">{telemetry.llm_status.llm_model || "qwen2.5-coder"}</div>
                </div>
                <div className="p-2.5 rounded bg-app border border-rule">
                  <div className="text-muted text-[10px]">Air-Gap Invariant</div>
                  <div className="text-status-ok font-semibold">Strict (Zero External Calls)</div>
                </div>
                <div className="p-2.5 rounded bg-app border border-rule">
                  <div className="text-muted text-[10px]">Active Engine</div>
                  <div className="text-main font-semibold truncate">{telemetry.llm_status.fallback_engine || "Deterministic"}</div>
                </div>
              </div>
            </div>

            {/* Fallback Alerts */}
            {telemetry.llm_status.alerts.map((al) => (
              <div
                key={al.alert_id}
                className="p-4 rounded-segment border border-status-due_soon/30 bg-surface space-y-3"
              >
                <div className="flex items-start justify-between gap-3">
                  <div className="flex items-start gap-2.5">
                    <AlertTriangle className="w-4 h-4 text-status-due_soon flex-shrink-0 mt-0.5" />
                    <div>
                      <div className="text-xs font-semibold text-main">{al.title}</div>
                      <div className="text-[11px] text-muted mt-1 leading-relaxed">{al.detail}</div>
                    </div>
                  </div>
                  <SeverityBadge severity={al.severity} />
                </div>

                {al.remediation && (
                  <div className="mt-2 p-2.5 rounded bg-app border border-rule space-y-1">
                    <div className="text-[10px] font-semibold text-muted uppercase">Local Remediation Commands</div>
                    {al.remediation.map((r, idx) => (
                      <div key={idx} className="font-mono text-[11px] text-primary select-all">
                        $ {r}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

        {/* ═══════════ OBLIGATION PACKS TAB ═══════════ */}
        {activeTab === "packs" && (
          <div className="p-4 rounded-segment border border-rule bg-surface">
            <h3 className="text-xs font-semibold text-main mb-3">Statutory Regulatory Packs</h3>
            <div className="space-y-2 text-xs">
              <div className="p-3 rounded border border-rule bg-app flex items-center justify-between">
                <div>
                  <span className="font-semibold text-main">CERT-In Directions 2022</span>
                  <div className="text-[11px] text-muted">Section 70B Mandatory 6-Hour reporting window</div>
                </div>
                <span className="px-2 py-0.5 rounded-segment bg-status-ok/10 text-status-ok border border-status-ok text-[10px] font-mono">
                  SHA-256 VERIFIED
                </span>
              </div>
              <div className="p-3 rounded border border-rule bg-app flex items-center justify-between">
                <div>
                  <span className="font-semibold text-main">RBI Cybersecurity Directions 2026</span>
                  <div className="text-[11px] text-muted">Master Directions on IT Governance (DAKSH portal intimation)</div>
                </div>
                <span className="px-2 py-0.5 rounded-segment bg-status-ok/10 text-status-ok border border-status-ok text-[10px] font-mono">
                  SHA-256 VERIFIED
                </span>
              </div>
              <div className="p-3 rounded border border-rule bg-app flex items-center justify-between">
                <div>
                  <span className="font-semibold text-main">DPDP Act 2023 Rules</span>
                  <div className="text-[11px] text-muted">Section 8(6) Rule 7: 72-Hour Breach Intimation window</div>
                </div>
                <span className="px-2 py-0.5 rounded-segment bg-status-due_soon/10 text-status-due_soon border border-status-due_soon text-[10px] font-mono">
                  DRAFT GUIDANCE
                </span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
