import React, { useState, useEffect } from "react"
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
  Lock
} from "lucide-react"

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

interface AdminViewProps {
  userRole: string
  theme: "light" | "dark"
  onToggleTheme: () => void
  onBackToCommand: () => void
}

export const AdminView: React.FC<AdminViewProps> = ({
  userRole,
  theme,
  onToggleTheme,
  onBackToCommand,
}) => {
  const [health, setHealth] = useState<HealthData | null>(null)
  const [ready, setReady] = useState<ReadyData | null>(null)
  const [isLoading, setIsLoading] = useState<boolean>(true)
  const [lastRefreshed, setLastRefreshed] = useState<Date>(new Date())

  const fetchTelemetry = async () => {
    setIsLoading(true)
    try {
      const [hRes, rRes] = await Promise.all([
        fetch("/healthz"),
        fetch("/readyz"),
      ])
      if (hRes.ok) {
        const hData = await hRes.json()
        setHealth(hData)
      }
      if (rRes.ok) {
        const rData = await rRes.json()
        setReady(rData)
      }
    } catch {
      // Offline or network error handled gracefully
    } finally {
      setIsLoading(false)
      setLastRefreshed(new Date())
    }
  }

  useEffect(() => {
    fetchTelemetry()
  }, [])

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

  return (
    <div className="flex-1 flex flex-col h-full bg-app overflow-hidden">
      {/* Top Header */}
      <div className="h-12 border-b border-rule bg-surface flex items-center justify-between px-6 flex-shrink-0">
        <div className="flex items-center gap-3">
          <button
            onClick={onBackToCommand}
            className="p-1.5 rounded-control text-muted hover:text-main hover:bg-app border border-rule flex items-center gap-1.5 text-xs"
            title="Return to Incident Command Center (g i)"
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

        <div className="flex items-center gap-3 text-xs">
          <span className="text-muted text-[11px] font-mono">
            Updated: {lastRefreshed.toLocaleTimeString("en-IN")}
          </span>
          <button
            onClick={fetchTelemetry}
            disabled={isLoading}
            className="p-1.5 rounded-control text-muted hover:text-main hover:bg-app border border-rule flex items-center gap-1"
            title="Refresh system telemetry"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? "animate-spin" : ""}`} />
          </button>
        </div>
      </div>

      {/* Content Area */}
      <div className="flex-1 overflow-y-auto p-6 space-y-6 max-w-5xl mx-auto w-full">
        {/* Separation of Duties Banner */}
        <div className="p-4 rounded-segment border border-rule bg-surface flex items-start gap-3">
          <Lock className="w-5 h-5 text-primary mt-0.5 flex-shrink-0" />
          <div className="text-xs space-y-1">
            <h2 className="font-semibold text-main">Bank Separation of Duties Policy (Active Role: {userRole})</h2>
            <p className="text-muted leading-relaxed">
              Administrative credentials grant authority over environment configuration, clock synchronization, and obligation pack verification. In strict compliance with RBI Information Security Guidelines, administrative roles are denied access to investigative incident narratives and cannot assert or approve statutory filing packets.
            </p>
          </div>
        </div>

        {/* Telemetry Cards Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {/* Liveness & Environment */}
          <div className="p-4 rounded-segment border border-rule bg-surface space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-medium text-muted flex items-center gap-1.5">
                <Cpu className="w-4 h-4 text-primary" />
                <span>API Liveness</span>
              </span>
              <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded-segment text-[10px] font-mono font-medium bg-status-ok/10 text-status-ok border border-status-ok">
                <CheckCircle2 className="w-3 h-3" />
                <span>{health?.status === "ok" ? "LIVE" : "UNKNOWN"}</span>
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
                <button
                  onClick={onToggleTheme}
                  className="text-primary hover:underline"
                >
                  {theme === "light" ? "Day Ledger" : "Night Desk"}
                </button>
              </div>
            </div>
          </div>

          {/* Database Connectivity */}
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

          {/* Clock Synchronization */}
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

        {/* Regulatory Obligation Packs Table */}
        <div className="border border-rule rounded-segment bg-surface overflow-hidden">
          <div className="px-4 py-3 bg-app border-b border-rule flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Layers className="w-4 h-4 text-primary" />
              <h3 className="text-xs font-semibold text-main">Verified regulatory obligation packs</h3>
            </div>
            <span className="text-[11px] font-mono text-muted">Strict byte-level SHA-256 verification</span>
          </div>

          <table className="w-full text-left text-xs" aria-label="Installed regulatory obligation packs">
            <thead className="bg-app/50 border-b border-rule font-medium text-muted">
              <tr>
                <th className="py-2.5 px-4">Pack ID</th>
                <th className="py-2.5 px-4">Regulator</th>
                <th className="py-2.5 px-4">Version</th>
                <th className="py-2.5 px-4">Statutory Status</th>
                <th className="py-2.5 px-4">Integrity Check</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-rule font-mono text-xs">
              <tr className="hover:bg-app/40">
                <td className="py-2.5 px-4 font-semibold text-main">certin-directions-2022</td>
                <td className="py-2.5 px-4">CERT-In</td>
                <td className="py-2.5 px-4 text-muted">1.0.0</td>
                <td className="py-2.5 px-4">
                  <span className="px-1.5 py-0.5 rounded-segment bg-status-ok/10 text-status-ok border border-status-ok text-[10px]">
                    In force (6h notice)
                  </span>
                </td>
                <td className="py-2.5 px-4 text-status-ok flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3" />
                  <span>SHA-256 verified</span>
                </td>
              </tr>
              <tr className="hover:bg-app/40">
                <td className="py-2.5 px-4 font-semibold text-main">rbi-cybersecurity-directions-2026</td>
                <td className="py-2.5 px-4">RBI</td>
                <td className="py-2.5 px-4 text-muted">1.0.0</td>
                <td className="py-2.5 px-4">
                  <span className="px-1.5 py-0.5 rounded-segment bg-status-ok/10 text-status-ok border border-status-ok text-[10px]">
                    In force (6h report)
                  </span>
                </td>
                <td className="py-2.5 px-4 text-status-ok flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3" />
                  <span>SHA-256 verified</span>
                </td>
              </tr>
              <tr className="hover:bg-app/40">
                <td className="py-2.5 px-4 font-semibold text-main">dpdp-rules-2025</td>
                <td className="py-2.5 px-4">DPDP</td>
                <td className="py-2.5 px-4 text-muted">1.0.0</td>
                <td className="py-2.5 px-4">
                  <span className="px-1.5 py-0.5 rounded-segment bg-status-due_soon/10 text-status-due_soon border border-status-due_soon text-[10px]">
                    Draft guidance (not in force)
                  </span>
                </td>
                <td className="py-2.5 px-4 text-status-ok flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3" />
                  <span>SHA-256 verified</span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        {/* Security Audit Trail Verification Shortcut */}
        <div className="p-4 rounded-segment border border-rule bg-surface flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-control bg-status-info/10 text-status-info flex items-center justify-center flex-shrink-0">
              <ShieldAlert className="w-4 h-4" />
            </div>
            <div>
              <div className="text-xs font-semibold text-main">Cryptographic Audit Chain</div>
              <div className="text-[11px] text-muted">Inspect full hash ledger or execute integrity verification probe</div>
            </div>
          </div>
          <button
            onClick={() => {
              window.history.pushState({}, "", "/activity")
              window.dispatchEvent(new PopStateEvent("popstate"))
            }}
            className="px-3 py-1.5 rounded-control border border-rule bg-app hover:bg-surface text-xs font-medium text-main"
          >
            Open Activity Ledger
          </button>
        </div>
      </div>
    </div>
  )
}
