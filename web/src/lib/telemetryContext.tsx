import React, {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  useRef,
  type ReactNode,
} from "react"
import {
  type LiveAnomalyAlert,
  type ToolTelemetryHealth,
  ANOMALY_SCENARIOS,
  INITIAL_DEMO_TOOLS,
} from "./liveTelemetryEngine"

export interface LLMStatusData {
  llm_available: boolean
  llm_status: string
  llm_endpoint: string
  llm_model: string | null
  fallback_mode: boolean
  fallback_engine: string | null
  alerts: Array<{
    alert_id: string
    timestamp: string
    alert_type: string
    severity: string
    title: string
    detail: string
    remediation?: string[]
    impact?: Record<string, string>
    automated_response?: Record<string, any>
  }>
  checked_at: string
}

export interface SecurityTelemetryResponse {
  timestamp: string
  summary: {
    total_tools_monitored: number
    healthy_tools: number
    degraded_tools: number
    warning_tools: number
    total_events_per_minute: number
    alert_count_last_2h: number
    critical_alerts: number
  }
  tool_health: ToolTelemetryHealth[]
  recent_alerts: any[]
  llm_status: LLMStatusData
  automated_responses_active: boolean
  response_engine: string
}

interface TelemetryContextType {
  toolsState: ToolTelemetryHealth[]
  telemetry: SecurityTelemetryResponse | null
  activeAnomalies: LiveAnomalyAlert[]
  isStreaming: boolean
  streamSpeedMs: number
  soundEnabled: boolean
  isDrawerOpen: boolean
  openDrawer: () => void
  closeDrawer: () => void
  toggleStreaming: () => void
  setStreamSpeedMs: (speed: number) => void
  toggleSound: () => void
  triggerAnomaly: (scenarioIndex?: number) => void
  dismissAnomaly: (id: string) => void
  dismissAllAnomalies: () => void
  acknowledgeAnomaly: (id: string) => void
  refreshTelemetry: () => Promise<void>
}

const TelemetryContext = createContext<TelemetryContextType | undefined>(undefined)

export function playAlertChime(isCritical: boolean = false) {
  try {
    const AudioContextClass = window.AudioContext || (window as any).webkitAudioContext
    if (!AudioContextClass) return
    const ctx = new AudioContextClass()
    const osc = ctx.createOscillator()
    const gain = ctx.createGain()

    osc.type = isCritical ? "sawtooth" : "sine"
    osc.frequency.setValueAtTime(isCritical ? 880 : 587.33, ctx.currentTime)
    osc.frequency.exponentialRampToValueAtTime(isCritical ? 440 : 880, ctx.currentTime + 0.25)

    gain.gain.setValueAtTime(0.15, ctx.currentTime)
    gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.3)

    osc.connect(gain)
    gain.connect(ctx.destination)

    osc.start()
    osc.stop(ctx.currentTime + 0.3)
  } catch {
    // Audio context may be restricted by browser autoplay policy
  }
}

export const TelemetryProvider: React.FC<{ children: ReactNode }> = ({ children }) => {
  const [toolsState, setToolsState] = useState<ToolTelemetryHealth[]>(INITIAL_DEMO_TOOLS)
  const [telemetry, setTelemetry] = useState<SecurityTelemetryResponse | null>(null)
  const [activeAnomalies, setActiveAnomalies] = useState<LiveAnomalyAlert[]>([])
  const [isStreaming, setIsStreaming] = useState<boolean>(true)
  const [streamSpeedMs, setStreamSpeedMs] = useState<number>(3000)
  const [soundEnabled, setSoundEnabled] = useState<boolean>(true)
  const [isDrawerOpen, setIsDrawerOpen] = useState<boolean>(false)

  const anomaliesRef = useRef(activeAnomalies)
  anomaliesRef.current = activeAnomalies

  const openDrawer = useCallback(() => setIsDrawerOpen(true), [])
  const closeDrawer = useCallback(() => setIsDrawerOpen(false), [])
  const toggleStreaming = useCallback(() => setIsStreaming((prev) => !prev), [])
  const toggleSound = useCallback(() => setSoundEnabled((prev) => !prev), [])

  const triggerAnomaly = useCallback(
    (scenarioIndex?: number) => {
      const idx =
        scenarioIndex !== undefined && scenarioIndex >= 0 && scenarioIndex < ANOMALY_SCENARIOS.length
          ? scenarioIndex
          : Math.floor(Math.random() * ANOMALY_SCENARIOS.length)

      const template = ANOMALY_SCENARIOS[idx]
      const alert: LiveAnomalyAlert = {
        ...template,
        id: `ANOM-${Date.now()}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`,
        timestamp: new Date().toISOString(),
      }

      setActiveAnomalies((prev) => [alert, ...prev.filter((a) => a.tool_id !== alert.tool_id)])

      setToolsState((prev) =>
        prev.map((t) => {
          if (t.tool_id === alert.tool_id) {
            return {
              ...t,
              health: alert.severity === "critical" ? "DEGRADED" : "WARNING",
              active_anomaly: alert.title,
              metrics: {
                ...t.metrics,
                events_per_minute: t.metrics.events_per_minute * 2,
                avg_latency_ms: Math.min(250, t.metrics.avg_latency_ms * 3),
                cpu_usage_pct: Math.min(99.4, t.metrics.cpu_usage_pct + 35),
              },
            }
          }
          return t
        })
      )

      if (soundEnabled) {
        playAlertChime(alert.severity === "critical")
      }
    },
    [soundEnabled]
  )

  const dismissAnomaly = useCallback((id: string) => {
    setActiveAnomalies((prev) => {
      const target = prev.find((a) => a.id === id)
      if (target) {
        setToolsState((currTools) =>
          currTools.map((t) =>
            t.tool_id === target.tool_id
              ? {
                  ...t,
                  health: t.trust_status === "DEGRADED" ? "DEGRADED" : "HEALTHY",
                  active_anomaly: null,
                }
              : t
          )
        )
      }
      return prev.filter((a) => a.id !== id)
    })
  }, [])

  const dismissAllAnomalies = useCallback(() => {
    setActiveAnomalies([])
    setToolsState((currTools) =>
      currTools.map((t) => ({
        ...t,
        health: t.trust_status === "DEGRADED" ? "DEGRADED" : "HEALTHY",
        active_anomaly: null,
      }))
    )
  }, [])

  const acknowledgeAnomaly = useCallback((id: string) => {
    setActiveAnomalies((prev) => {
      const target = prev.find((a) => a.id === id)
      if (target) {
        setToolsState((currTools) =>
          currTools.map((t) =>
            t.tool_id === target.tool_id
              ? {
                  ...t,
                  health: t.trust_status === "DEGRADED" ? "DEGRADED" : "HEALTHY",
                  active_anomaly: null,
                }
              : t
          )
        )
      }
      return prev.filter((a) => a.id !== id)
    })
  }, [])

  // Poll backend telemetry and LLM status
  const refreshTelemetry = useCallback(async () => {
    try {
      const res = await fetch("/api/v1/admin/security-telemetry")
      if (res.ok) {
        const data: SecurityTelemetryResponse = await res.json()
        setTelemetry(data)
        if (data.tool_health && data.tool_health.length > 0) {
          setToolsState((prev) => {
            // Retain active anomalies across refresh
            const anomalyMap = new Map(prev.map((t) => [t.tool_id, t.active_anomaly]))
            return data.tool_health.map((t) => ({
              ...t,
              active_anomaly: anomalyMap.get(t.tool_id) || null,
              health: anomalyMap.get(t.tool_id) ? "DEGRADED" : t.health,
            }))
          })
        }
      }
    } catch {
      // Offline fallback: keep local simulated telemetry
    }
  }, [])

  // Initial fetch
  useEffect(() => {
    refreshTelemetry()
    const timer = setInterval(refreshTelemetry, 10000)
    return () => clearInterval(timer)
  }, [refreshTelemetry])

  // Real-time jitter stream simulation
  useEffect(() => {
    if (!isStreaming) return

    let tickCounter = 0
    const interval = setInterval(() => {
      tickCounter += 1
      if (tickCounter % 15 === 0 && anomaliesRef.current.length === 0) {
        triggerAnomaly()
      }

      setToolsState((prev) =>
        prev.map((tool) => {
          const jitterEps = Math.floor((Math.random() - 0.48) * 15)
          const jitterLatency = Math.floor((Math.random() - 0.5) * 3)
          const jitterCpu = Number(((Math.random() - 0.5) * 1.5).toFixed(1))

          const newEps = Math.max(50, tool.metrics.events_per_minute + jitterEps)
          const newLatency = Math.max(2, tool.metrics.avg_latency_ms + jitterLatency)
          const newCpu = Math.max(5, Math.min(98, Number((tool.metrics.cpu_usage_pct + jitterCpu).toFixed(1))))

          return {
            ...tool,
            metrics: {
              ...tool.metrics,
              events_per_minute: newEps,
              avg_latency_ms: newLatency,
              cpu_usage_pct: newCpu,
            },
          }
        })
      )
    }, streamSpeedMs)

    return () => clearInterval(interval)
  }, [isStreaming, streamSpeedMs])

  return (
    <TelemetryContext.Provider
      value={{
        toolsState,
        telemetry,
        activeAnomalies,
        isStreaming,
        streamSpeedMs,
        soundEnabled,
        isDrawerOpen,
        openDrawer,
        closeDrawer,
        toggleStreaming,
        setStreamSpeedMs,
        toggleSound,
        triggerAnomaly,
        dismissAnomaly,
        dismissAllAnomalies,
        acknowledgeAnomaly,
        refreshTelemetry,
      }}
    >
      {children}
    </TelemetryContext.Provider>
  )
}

export function useTelemetry(): TelemetryContextType {
  const ctx = useContext(TelemetryContext)
  if (!ctx) {
    throw new Error("useTelemetry must be used within a TelemetryProvider")
  }
  return ctx
}
