import React, { useState } from "react"
import {
  X,
  Play,
  Pause,
  Volume2,
  VolumeX,
  Flame,
  AlertTriangle,
  ArrowRight,
  ShieldAlert,
  ChevronDown,
  Plus,
} from "lucide-react"
import { useTelemetry } from "../../lib/telemetryContext"
import { ANOMALY_SCENARIOS, type LiveAnomalyAlert } from "../../lib/liveTelemetryEngine"

interface LiveTelemetryDrawerProps {
  onNavigateToAdmin?: () => void
  onCreateIncident?: (alert: LiveAnomalyAlert) => void
}

export const LiveTelemetryDrawer: React.FC<LiveTelemetryDrawerProps> = ({ onNavigateToAdmin, onCreateIncident }) => {
  const {
    toolsState,
    activeAnomalies,
    isStreaming,
    streamSpeedMs,
    soundEnabled,
    isDrawerOpen,
    closeDrawer,
    toggleStreaming,
    setStreamSpeedMs,
    toggleSound,
    triggerAnomaly,
    acknowledgeAnomaly,
  } = useTelemetry()

  const [showScenarioMenu, setShowScenarioMenu] = useState(false)

  if (!isDrawerOpen) return null

  const totalEps = toolsState.reduce((acc, t) => acc + t.metrics.events_per_minute, 0)
  const criticalCount = activeAnomalies.filter((a) => a.severity === "critical").length

  return (
    <div className="fixed inset-0 z-50 overflow-hidden flex justify-end">
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/60 backdrop-blur-sm transition-opacity"
        onClick={closeDrawer}
        aria-hidden="true"
      />

      {/* Slide-over panel */}
      <div className="relative z-50 w-full max-w-2xl bg-surface border-l border-rule shadow-2xl flex flex-col h-full animate-in slide-in-from-right duration-300">
        {/* Header */}
        <div className="px-5 py-3.5 border-b border-rule bg-app flex items-center justify-between flex-shrink-0">
          <div className="flex items-center gap-2.5">
            <span className="relative flex h-3 w-3">
              <span
                className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${
                  criticalCount > 0 ? "bg-status-critical" : "bg-status-ok"
                }`}
              />
              <span
                className={`relative inline-flex rounded-full h-3 w-3 ${
                  criticalCount > 0 ? "bg-status-critical" : "bg-status-ok"
                }`}
              />
            </span>
            <div>
              <div className="flex items-center gap-2">
                <h2 className="text-sm font-bold text-main">Live Telemetry Simulator</h2>
                <span className="text-[10px] font-mono px-1.5 py-0.2 rounded-segment bg-primary/10 text-primary border border-primary/20">
                  12 Connected Tools
                </span>
              </div>
              <p className="text-[11px] text-muted font-mono mt-0.5">
                Dynamic Network Jitter: <span className="text-main font-semibold">{totalEps.toLocaleString()} EPS</span> | Status:{" "}
                <span className={isStreaming ? "text-status-ok font-medium" : "text-status-due_soon"}>
                  {isStreaming ? `LIVE (${streamSpeedMs / 1000}s tick)` : "PAUSED"}
                </span>
              </p>
            </div>
          </div>

          <div className="flex items-center gap-1.5">
            {/* Stream Play/Pause */}
            <button
              onClick={toggleStreaming}
              className={`p-1.5 rounded-segment border text-xs flex items-center gap-1 transition-colors ${
                isStreaming
                  ? "bg-status-ok/10 text-status-ok border-status-ok/30 hover:bg-status-ok/20"
                  : "bg-status-due_soon/10 text-status-due_soon border-status-due_soon/30 hover:bg-status-due_soon/20"
              }`}
              title={isStreaming ? "Pause Telemetry Stream" : "Resume Telemetry Stream"}
            >
              {isStreaming ? <Pause className="w-3.5 h-3.5" /> : <Play className="w-3.5 h-3.5" />}
              <span className="text-[11px] font-medium hidden sm:inline">{isStreaming ? "Live" : "Paused"}</span>
            </button>

            {/* Sound Toggle */}
            <button
              onClick={toggleSound}
              className="p-1.5 rounded-segment border border-rule text-muted hover:text-main hover:bg-surface text-xs transition-colors"
              title={soundEnabled ? "Mute alert audio chime" : "Enable alert audio chime"}
            >
              {soundEnabled ? <Volume2 className="w-3.5 h-3.5 text-primary" /> : <VolumeX className="w-3.5 h-3.5" />}
            </button>

            {/* Close Button */}
            <button
              onClick={closeDrawer}
              className="p-1.5 rounded-segment border border-rule text-muted hover:text-main hover:bg-surface transition-colors"
              aria-label="Close telemetry drawer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Simulator Controls & Anomaly Injection Bar */}
        <div className="p-4 border-b border-rule bg-surface/50 space-y-3 flex-shrink-0">
          <div className="flex flex-wrap items-center justify-between gap-2">
            {/* Speed Selector */}
            <div className="flex items-center gap-1.5 text-xs text-muted">
              <span>Tick Speed:</span>
              <div className="inline-flex rounded-segment border border-rule p-0.5 bg-app">
                {[
                  { label: "1.0s Fast", ms: 1000 },
                  { label: "2.5s Normal", ms: 2500 },
                  { label: "5.0s Slow", ms: 5000 },
                ].map((s) => (
                  <button
                    key={s.ms}
                    onClick={() => setStreamSpeedMs(s.ms)}
                    className={`px-2 py-0.5 text-[11px] font-mono rounded transition-colors ${
                      streamSpeedMs === s.ms
                        ? "bg-primary text-black font-semibold shadow-sm"
                        : "text-muted hover:text-main"
                    }`}
                  >
                    {s.label}
                  </button>
                ))}
              </div>
            </div>

            {/* Quick Trigger Buttons */}
            <div className="flex items-center gap-2">
              <button
                onClick={() => triggerAnomaly()}
                className="px-3 py-1.5 rounded-segment bg-status-critical/15 hover:bg-status-critical/25 text-status-critical border border-status-critical/40 text-xs font-semibold flex items-center gap-1.5 shadow-sm transition-all active:scale-95"
                title="Randomly inject an enterprise security anomaly"
              >
                <Flame className="w-3.5 h-3.5 text-status-critical animate-pulse" />
                <span>Simulate Anomaly</span>
              </button>

              <div className="relative">
                <button
                  onClick={() => setShowScenarioMenu((prev) => !prev)}
                  className="px-2 py-1.5 rounded-segment border border-rule text-muted hover:text-main hover:bg-app text-xs flex items-center gap-1"
                  title="Choose specific security attack vector scenario"
                >
                  <span className="text-[11px]">Choose Threat</span>
                  <ChevronDown className="w-3 h-3" />
                </button>

                {showScenarioMenu && (
                  <div className="absolute right-0 mt-1 w-80 bg-surface border border-rule rounded-control shadow-2xl p-1 z-50 text-xs">
                    <div className="px-2 py-1 text-[10px] font-mono uppercase text-muted tracking-wider border-b border-rule">
                      Inject Specific Threat Scenario
                    </div>
                    <div className="max-h-60 overflow-y-auto py-1">
                      {ANOMALY_SCENARIOS.map((sc, idx) => (
                        <button
                          key={sc.tool_id + idx}
                          onClick={() => {
                            triggerAnomaly(idx)
                            setShowScenarioMenu(false)
                          }}
                          className="w-full text-left px-2.5 py-1.5 rounded hover:bg-app text-[11px] text-main flex flex-col gap-0.5 transition-colors"
                        >
                          <div className="flex items-center justify-between">
                            <span className="font-semibold text-primary">{sc.tool_name}</span>
                            <span
                              className={`text-[9px] uppercase font-mono px-1 rounded ${
                                sc.severity === "critical"
                                  ? "bg-status-critical/20 text-status-critical"
                                  : "bg-status-due_soon/20 text-status-due_soon"
                              }`}
                            >
                              {sc.severity}
                            </span>
                          </div>
                          <span className="text-muted text-[10px] line-clamp-1">{sc.title}</span>
                        </button>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Active Anomalies Alert Strip if any */}
          {activeAnomalies.length > 0 && (
            <div className="p-2.5 rounded-control bg-status-critical/10 border border-status-critical/30 space-y-1.5 animate-in fade-in duration-200">
              <div className="flex items-center justify-between">
                <span className="text-xs font-bold text-status-critical flex items-center gap-1.5">
                  <ShieldAlert className="w-4 h-4 text-status-critical" />
                  Active Security Anomalies Detected ({activeAnomalies.length})
                </span>
                <span className="text-[10px] font-mono text-status-critical">Automated Containment Active</span>
              </div>
              {activeAnomalies.map((anom) => (
                <div
                  key={anom.id}
                  className="bg-black/30 p-2 rounded border border-status-critical/20 flex items-center justify-between text-xs"
                >
                  <div className="pr-2">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-main text-[11px]">{anom.tool_name}</span>
                      <span className="text-[10px] font-mono text-muted">{anom.affected_asset}</span>
                    </div>
                    <p className="text-[11px] text-muted line-clamp-1 mt-0.5">{anom.title}</p>
                  </div>
                  <div className="flex items-center gap-1.5 flex-shrink-0">
                    {onCreateIncident && (
                      <button
                        onClick={() => {
                          closeDrawer()
                          onCreateIncident(anom)
                        }}
                        className="px-2.5 py-1 rounded-segment bg-primary text-black text-[10px] font-semibold hover:bg-primary/90 transition-all flex items-center gap-1 shadow-sm active:scale-95 cursor-pointer"
                        title="Directly create an incident from this anomaly"
                      >
                        <Plus className="w-3 h-3 stroke-[2.5]" />
                        <span>Create Incident</span>
                      </button>
                    )}
                    <button
                      onClick={() => acknowledgeAnomaly(anom.id)}
                      className="px-2.5 py-1 rounded-segment bg-status-critical text-white text-[10px] font-semibold hover:bg-status-critical/80 transition-colors cursor-pointer"
                    >
                      Acknowledge
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Tool Cards List with Live Dynamic Fluctuations */}
        <div className="flex-1 overflow-y-auto p-4 space-y-2.5">
          <div className="flex items-center justify-between text-xs text-muted pb-1">
            <span className="font-medium text-main">Cybersecurity Ecosystem ({toolsState.length} Tools)</span>
            <span className="text-[11px]">
              {toolsState.filter((t) => t.health === "HEALTHY").length} Healthy |{" "}
              {toolsState.filter((t) => t.health === "WARNING").length} Warning |{" "}
              {toolsState.filter((t) => t.health === "DEGRADED").length} Degraded
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
            {toolsState.map((tool) => {
              const isAnomalous = !!tool.active_anomaly
              const isDegraded = tool.health === "DEGRADED"
              const isWarning = tool.health === "WARNING"

              return (
                <div
                  key={tool.tool_id}
                  className={`p-3 rounded-control border transition-all ${
                    isAnomalous
                      ? "bg-status-critical/10 border-status-critical/50 shadow-md ring-1 ring-status-critical/30"
                      : isDegraded
                      ? "bg-app border-status-critical/30"
                      : isWarning
                      ? "bg-app border-status-due_soon/30"
                      : "bg-app border-rule hover:border-rule-subtle"
                  }`}
                >
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="flex items-center gap-1.5">
                        <span
                          className={`w-2 h-2 rounded-full ${
                            isAnomalous || isDegraded
                              ? "bg-status-critical animate-pulse"
                              : isWarning
                              ? "bg-status-due_soon"
                              : "bg-status-ok"
                          }`}
                        />
                        <h4 className="text-xs font-bold text-main leading-none">{tool.tool_name}</h4>
                      </div>
                      <span className="text-[10px] font-mono text-muted mt-1 block">
                        Category: {tool.category} | Uptime: {tool.uptime_hours.toFixed(0)}h
                      </span>
                    </div>

                    <span
                      className={`text-[9px] font-mono uppercase px-1.5 py-0.5 rounded-segment font-bold ${
                        isAnomalous || isDegraded
                          ? "bg-status-critical/20 text-status-critical border border-status-critical/40"
                          : isWarning
                          ? "bg-status-due_soon/20 text-status-due_soon border border-status-due_soon/40"
                          : "bg-status-ok/10 text-status-ok border border-status-ok/30"
                      }`}
                    >
                      {tool.health}
                    </span>
                  </div>

                  {/* Active Anomaly Banner */}
                  {tool.active_anomaly && (
                    <div className="mt-2 p-1.5 rounded bg-status-critical/20 border border-status-critical/40 text-[10px] text-status-critical font-medium flex items-center gap-1 animate-pulse">
                      <AlertTriangle className="w-3 h-3 flex-shrink-0" />
                      <span className="truncate">{tool.active_anomaly}</span>
                    </div>
                  )}

                  {/* Fluctuating Dynamic Metrics */}
                  <div className="grid grid-cols-3 gap-1.5 mt-2.5 pt-2 border-t border-rule text-[10px]">
                    <div className="bg-surface p-1 rounded border border-rule/50">
                      <span className="text-muted block text-[9px]">Throughput</span>
                      <span className="font-mono font-bold text-main text-[11px]">
                        {tool.metrics.events_per_minute} <span className="text-[9px] text-muted">EPS</span>
                      </span>
                    </div>

                    <div className="bg-surface p-1 rounded border border-rule/50">
                      <span className="text-muted block text-[9px]">Latency</span>
                      <span
                        className={`font-mono font-bold text-[11px] ${
                          tool.metrics.avg_latency_ms > 50 ? "text-status-critical" : "text-main"
                        }`}
                      >
                        {tool.metrics.avg_latency_ms} <span className="text-[9px] text-muted">ms</span>
                      </span>
                    </div>

                    <div className="bg-surface p-1 rounded border border-rule/50">
                      <span className="text-muted block text-[9px]">CPU Usage</span>
                      <span
                        className={`font-mono font-bold text-[11px] ${
                          tool.metrics.cpu_usage_pct > 80 ? "text-status-critical" : "text-main"
                        }`}
                      >
                        {tool.metrics.cpu_usage_pct}%
                      </span>
                    </div>
                  </div>

                  {/* Secondary Metrics Bar */}
                  <div className="flex items-center justify-between text-[9px] text-muted font-mono mt-1.5 px-0.5">
                    <span>Connections: {tool.metrics.active_connections}</span>
                    <span className={tool.metrics.dropped_events > 0 ? "text-status-critical font-bold" : ""}>
                      Dropped: {tool.metrics.dropped_events}
                    </span>
                    <span>Memory: {tool.metrics.memory_usage_mb}MB</span>
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* Footer Link to Full Admin Console */}
        <div className="px-5 py-3 border-t border-rule bg-app flex items-center justify-between flex-shrink-0 text-xs">
          <span className="text-muted text-[11px]">
            Statutory Air-Gapped Telemetry Engine (Zero external SaaS calls)
          </span>
          {onNavigateToAdmin && (
            <button
              onClick={() => {
                closeDrawer()
                onNavigateToAdmin()
              }}
              className="px-3 py-1.5 rounded-segment bg-primary/10 hover:bg-primary/20 text-primary border border-primary/30 font-medium flex items-center gap-1.5 transition-colors"
            >
              <span>Full Admin Console</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
