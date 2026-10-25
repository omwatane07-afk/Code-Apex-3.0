import { useState, useEffect, type FC } from "react"
import { 
  X, 
  CheckCircle2, 
  Volume2, 
  VolumeX, 
  ChevronRight, 
  Activity, 
  Zap,
  Plus,
} from "lucide-react"
import type { LiveAnomalyAlert } from "../../lib/liveTelemetryEngine"

interface LiveAnomalyNotificationModalProps {
  alerts: LiveAnomalyAlert[]
  onDismiss: (id: string) => void
  onDismissAll: () => void
  onAcknowledge: (id: string) => void
  onInspectTool?: (toolId: string) => void
  onCreateIncident?: (alert: LiveAnomalyAlert) => void
  soundEnabled: boolean
  onToggleSound: () => void
}

export const LiveAnomalyNotificationModal: FC<LiveAnomalyNotificationModalProps> = ({
  alerts,
  onDismiss,
  onDismissAll,
  onAcknowledge,
  onInspectTool,
  onCreateIncident,
  soundEnabled,
  onToggleSound,
}) => {
  const [currentIndex, setCurrentIndex] = useState(0)

  const unacknowledgedAlerts = alerts.filter((a) => !a.acknowledged)

  // Clamp index if unacknowledged alerts array changes
  useEffect(() => {
    if (currentIndex >= unacknowledgedAlerts.length && unacknowledgedAlerts.length > 0) {
      setCurrentIndex(unacknowledgedAlerts.length - 1)
    }
  }, [unacknowledgedAlerts.length, currentIndex])

  if (unacknowledgedAlerts.length === 0) return null

  const currentAlert = unacknowledgedAlerts[currentIndex] || unacknowledgedAlerts[0]
  const isCritical = currentAlert.severity === "critical"

  const handleAcknowledge = () => {
    onAcknowledge(currentAlert.id)
    onDismiss(currentAlert.id)
    if (currentIndex >= unacknowledgedAlerts.length - 1 && currentIndex > 0) {
      setCurrentIndex((prev) => prev - 1)
    }
  }

  const formatIST = (isoStr: string) => {
    try {
      return (
        new Date(isoStr).toLocaleTimeString("en-IN", {
          timeZone: "Asia/Kolkata",
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
          hour12: false,
        }) + " IST"
      )
    } catch {
      return isoStr
    }
  }

  return (
    <div className="fixed bottom-5 right-5 z-50 w-full max-w-lg animate-in slide-in-from-bottom-5 duration-300">
      <div 
        className={`rounded-control border shadow-2xl overflow-hidden backdrop-blur-md transition-all ${
          isCritical
            ? "bg-[#180A0A]/95 border-status-critical/60 shadow-status-critical/20"
            : "bg-[#1A1208]/95 border-status-due_soon/60 shadow-status-due_soon/20"
        }`}
      >
        {/* Top Accent Strip */}
        <div 
          className={`h-1.5 w-full animate-pulse ${
            isCritical ? "bg-status-critical" : "bg-status-due_soon"
          }`} 
        />

        {/* Header */}
        <div className="p-3.5 border-b border-white/10 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="relative flex h-3 w-3">
              <span 
                className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${
                  isCritical ? "bg-status-critical" : "bg-status-due_soon"
                }`}
              />
              <span 
                className={`relative inline-flex rounded-full h-3 w-3 ${
                  isCritical ? "bg-status-critical" : "bg-status-due_soon"
                }`}
              />
            </span>
            <span 
              className={`text-xs font-mono font-bold tracking-wider uppercase px-2 py-0.5 rounded-segment ${
                isCritical 
                  ? "bg-status-critical/20 text-status-critical border border-status-critical/40"
                  : "bg-status-due_soon/20 text-status-due_soon border border-status-due_soon/40"
              }`}
            >
              {currentAlert.severity} ANOMALY DETECTED
            </span>
            {unacknowledgedAlerts.length > 1 && (
              <span className="text-[11px] text-muted font-mono">
                ({currentIndex + 1} of {unacknowledgedAlerts.length})
              </span>
            )}
          </div>

          <div className="flex items-center gap-1.5">
            <button
              onClick={onToggleSound}
              className="p-1 rounded text-muted hover:text-main hover:bg-white/5 transition-colors"
              title={soundEnabled ? "Mute alert chime" : "Unmute alert chime"}
              aria-label="Toggle alert sound"
            >
              {soundEnabled ? <Volume2 className="w-3.5 h-3.5" /> : <VolumeX className="w-3.5 h-3.5 text-muted/50" />}
            </button>
            {unacknowledgedAlerts.length > 1 && (
              <button
                onClick={onDismissAll}
                className="px-1.5 py-0.5 rounded text-[10px] text-muted hover:text-main hover:bg-white/10 transition-colors"
                title="Dismiss all active alerts"
              >
                Dismiss All
              </button>
            )}
            <button
              onClick={() => onDismiss(currentAlert.id)}
              className="p-1 rounded text-muted hover:text-main hover:bg-white/5 transition-colors"
              aria-label="Dismiss alert"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Content Body */}
        <div className="p-4 space-y-3 text-xs text-main">
          {/* Tool & Timestamp */}
          <div className="flex items-center justify-between text-[11px] text-muted">
            <span className="font-semibold text-main flex items-center gap-1.5">
              <Activity className="w-3.5 h-3.5 text-primary" />
              <span>{currentAlert.tool_name}</span>
              <span className="px-1.5 py-0.2 rounded-segment bg-white/5 border border-white/10 text-[10px] font-mono">
                {currentAlert.category}
              </span>
            </span>
            <span className="font-mono">{formatIST(currentAlert.timestamp)}</span>
          </div>

          {/* Anomaly Title */}
          <div>
            <h3 className="text-sm font-bold text-main leading-snug">
              {currentAlert.title}
            </h3>
            <p className="text-muted text-[11px] mt-1 leading-relaxed">
              {currentAlert.description}
            </p>
          </div>

          {/* Metric Spike & MITRE ATT&CK */}
          <div className="grid grid-cols-2 gap-2 text-[11px]">
            <div className="p-2 rounded bg-black/40 border border-white/10">
              <span className="text-muted text-[10px] block font-medium">Telemetry Anomaly Spike</span>
              <span className="font-mono text-status-critical font-bold mt-0.5 block truncate">
                {currentAlert.anomalous_metric}
              </span>
            </div>
            <div className="p-2 rounded bg-black/40 border border-white/10">
              <span className="text-muted text-[10px] block font-medium">MITRE ATT&CK Technique</span>
              <span className="font-mono text-primary font-bold mt-0.5 block truncate">
                {currentAlert.mitre_attack_id}
              </span>
            </div>
          </div>

          {/* Affected Asset & Automated Action */}
          <div className="p-2.5 rounded bg-black/40 border border-white/10 space-y-1.5">
            <div className="flex items-center justify-between text-[11px]">
              <span className="text-muted">Target Asset:</span>
              <span className="font-mono font-semibold text-main">{currentAlert.affected_asset}</span>
            </div>
            <div className="pt-1.5 border-t border-white/10">
              <div className="flex items-start gap-1.5 text-[11px]">
                <Zap className="w-3.5 h-3.5 text-status-ok flex-shrink-0 mt-0.5" />
                <div>
                  <span className="font-semibold text-status-ok">Automated Response ({currentAlert.response_status}):</span>
                  <span className="text-muted block mt-0.5 leading-tight">{currentAlert.automated_response}</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Footer Navigation & Actions */}
        <div className="p-3 bg-black/40 border-t border-white/10 flex items-center justify-between gap-2">
          {/* Multi-alert paginator */}
          {alerts.length > 1 ? (
            <div className="flex items-center gap-1">
              <button
                disabled={currentIndex === 0}
                onClick={() => setCurrentIndex((prev) => Math.max(0, prev - 1))}
                className="px-2 py-1 rounded bg-white/5 hover:bg-white/10 text-muted hover:text-main text-[11px] disabled:opacity-30"
              >
                Prev
              </button>
              <button
                disabled={currentIndex === alerts.length - 1}
                onClick={() => setCurrentIndex((prev) => Math.min(alerts.length - 1, prev + 1))}
                className="px-2 py-1 rounded bg-white/5 hover:bg-white/10 text-muted hover:text-main text-[11px] disabled:opacity-30"
              >
                Next
              </button>
            </div>
          ) : (
            <div />
          )}

          <div className="flex items-center gap-2">
            {onCreateIncident && (
              <button
                onClick={() => onCreateIncident(currentAlert)}
                className="px-3 py-1.5 rounded-segment font-semibold text-[11px] flex items-center gap-1.5 bg-primary text-black hover:bg-primary/90 transition-all shadow-sm active:scale-95 cursor-pointer"
                title="Create formal incident from this anomaly"
              >
                <Plus className="w-3.5 h-3.5 stroke-[2.5]" />
                <span>Create Incident</span>
              </button>
            )}

            {onInspectTool && (
              <button
                onClick={() => onInspectTool(currentAlert.tool_id)}
                className="px-2.5 py-1.5 rounded-segment border border-white/20 hover:bg-white/10 text-main text-[11px] font-medium flex items-center gap-1 transition-colors"
              >
                <span>Inspect Tool</span>
                <ChevronRight className="w-3 h-3" />
              </button>
            )}

            <button
              onClick={handleAcknowledge}
              className={`px-3 py-1.5 rounded-segment font-semibold text-[11px] flex items-center gap-1.5 transition-colors cursor-pointer ${
                isCritical
                  ? "bg-status-critical text-white hover:bg-status-critical/90"
                  : "bg-status-due_soon text-black hover:bg-status-due_soon/90"
              }`}
            >
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>Acknowledge</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
