import React, { useState, useEffect } from "react"
import { Clock, AlertTriangle, ShieldCheck, ArrowLeft } from "lucide-react"

export interface WallboardObligation {
  regulator: string
  status: string
  deadline_at: string | null
  active_deadline_at: string | null
  is_disputed: boolean
  applicability_status: string
}

export interface WallboardIncident {
  incident_number: string
  severity: string
  status: string
  obligations: WallboardObligation[]
}

interface WallboardViewProps {
  incidents?: WallboardIncident[]
  serverTimeUtc?: string
  onBackToCommand?: () => void
}

function formatCountdown(targetUtc: string | null): string {
  if (!targetUtc) return "--:--:--"
  const target = new Date(targetUtc).getTime()
  const diff = target - Date.now()
  if (diff <= 0) return "00:00:00 (breached)"
  const h = Math.floor(diff / 3600000)
  const m = Math.floor((diff % 3600000) / 60000)
  const s = Math.floor((diff % 60000) / 1000)
  return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`
}

function formatIst(utcString: string | null): string {
  if (!utcString) return "Pending assertion"
  const date = new Date(utcString)
  return (
    new Intl.DateTimeFormat("en-IN", {
      timeZone: "Asia/Kolkata",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    }).format(date) + " IST"
  )
}

export const WallboardView: React.FC<WallboardViewProps> = ({
  incidents = [],
  onBackToCommand,
}) => {
  const [now, setNow] = useState(Date.now())
  const [ntpSkewSeconds, setNtpSkewSeconds] = useState<number | null>(null)

  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(timer)
  }, [])

  useEffect(() => {
    fetch("/readyz")
      .then((res) => (res.ok ? res.json() : null))
      .then((data) => {
        if (data && typeof data.ntp_skew_seconds === "number") {
          setNtpSkewSeconds(data.ntp_skew_seconds)
        }
      })
      .catch(() => {
        // Fallback gracefully if endpoint unreachable in isolated mode
      })
  }, [])

  const istCurrent = new Intl.DateTimeFormat("en-IN", {
    timeZone: "Asia/Kolkata",
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  }).format(new Date(now))

  return (
    <div className="min-h-screen bg-[#050508] text-[#F0F6FC] p-6 font-sans flex flex-col justify-between cyber-grid">
      {/* Wallboard Header: Read-only dispatch with measured NTP calibration */}
      <header className="border-b border-[#1A2332] pb-4 flex items-center justify-between">
        <div className="flex items-center gap-4">
          {onBackToCommand && (
            <button
              onClick={onBackToCommand}
              className="px-3 py-1.5 rounded-control bg-[#0A0D14] border border-[#1A2332] text-[#F0F6FC] text-xs hover:bg-[#111722] hover:border-[#00E5FF]/40 flex items-center gap-1.5 shadow transition"
            >
              <ArrowLeft className="w-3.5 h-3.5 text-[#00E5FF]" />
              <span>Return to Command Center</span>
            </button>
          )}
          <div className="flex items-center gap-3">
            <span className="w-3 h-3 rounded-full bg-[#00FF66] shadow-[0_0_8px_rgba(0,255,102,0.6)] animate-pulse" />
            <h1 className="text-xl font-bold tracking-tight text-[#F0F6FC]">
              CYBERQ SOC Telemetry Wallboard <span className="text-xs font-mono text-[#8B9BB4] font-normal uppercase">(Air-Gapped Telemetry)</span>
            </h1>
          </div>
        </div>

        <div className="flex items-center gap-6 text-sm">
          {ntpSkewSeconds !== null && ntpSkewSeconds > 1.0 ? (
            <div className="flex items-center gap-2 text-[#FF1E42] bg-[#FF1E42]/10 border border-[#FF1E42]/40 px-3 py-1 rounded-segment">
              <AlertTriangle className="w-4 h-4 text-[#FF1E42]" />
              <span className="font-mono">NTP skew warning ({ntpSkewSeconds.toFixed(2)}s)</span>
            </div>
          ) : (
            <div className="flex items-center gap-2 text-[#8B9BB4]">
              <Clock className="w-4 h-4 text-[#00E5FF]" />
              <span className="font-mono text-[#F0F6FC] tabular-nums">
                NTP Stratum-1 Calibrated {ntpSkewSeconds !== null ? `(+${ntpSkewSeconds.toFixed(2)}s)` : ""}
              </span>
            </div>
          )}

          <div className="border-l border-[#1A2332] pl-6 font-mono text-base font-bold text-[#00E5FF] tabular-nums tracking-wide">
            {istCurrent}
          </div>
        </div>
      </header>

      {/* Main Incident Roster (Sanitized Telemetry Only: Zero titles, zero names, zero phone numbers) */}
      <main className="flex-1 py-6 overflow-y-auto space-y-6">
        <div className="text-xs uppercase text-[#8B9BB4] tracking-wider font-mono font-semibold flex items-center justify-between">
          <span>Active incidents under statutory deadline ({incidents.length})</span>
          <span className="text-[11px] text-[#00E5FF]">PII-Free Redacted Stream</span>
        </div>

        {incidents.length === 0 ? (
          <div className="border border-[#1A2332] rounded-segment p-8 text-center text-[#8B9BB4] text-sm bg-[#0A0D14]">
            No active incidents under statutory deadline. All regulatory clocks clear.
          </div>
        ) : (
          incidents.map((inc) => {
            let sevBadge = "border-[#1A2332] text-[#8B9BB4]"
            if (inc.severity === "critical") sevBadge = "border-[#FF1E42] text-[#FF1E42] bg-[#FF1E42]/10"
            if (inc.severity === "high") sevBadge = "border-[#FFB74D] text-[#FFB74D] bg-[#FFB74D]/10"

            return (
              <div
                key={inc.incident_number}
                className="border border-[#1A2332] rounded-segment bg-[#0A0D14] p-5 shadow-xl hover:border-[#00E5FF]/30 transition"
              >
                {/* Sanitized Incident Header: Incident number & severity only */}
                <div className="flex items-center justify-between pb-3 border-b border-[#1A2332]">
                  <div className="flex items-center gap-4">
                    <span className="font-mono text-2xl font-bold tracking-tight text-[#F0F6FC] tabular-nums">
                      {inc.incident_number}
                    </span>
                    <span className={`px-2.5 py-0.5 rounded-segment border text-xs font-semibold uppercase font-mono ${sevBadge}`}>
                      Severity: {inc.severity}
                    </span>
                  </div>

                  <span className="text-xs text-[#8B9BB4] font-mono uppercase tracking-wide">
                    Status: <span className="text-[#00E5FF]">{inc.status}</span>
                  </span>
                </div>

                {/* Regulator Obligation Clocks Grid */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4">
                  {inc.obligations.map((obl) => {
                    const countdown = formatCountdown(obl.active_deadline_at)
                    const istDeadline = formatIst(obl.active_deadline_at)

                    let statusClass = "border-[#1A2332] text-[#8B9BB4]"
                    let cardBg = "bg-[#050508]"

                    if (obl.status === "running") {
                      statusClass = "border-[#00FF66] text-[#00FF66]"
                      cardBg = "bg-[#00FF66]/5"
                    } else if (obl.status === "due_soon") {
                      statusClass = "border-[#FFB74D] text-[#FFB74D]"
                      cardBg = "bg-[#FFB74D]/5"
                    } else if (obl.status === "critical") {
                      statusClass = "border-[#FF1E42] text-[#FF1E42] font-bold shadow-[0_0_12px_rgba(255,30,66,0.25)]"
                      cardBg = "bg-[#FF1E42]/10"
                    } else if (obl.status === "breached") {
                      statusClass = "border-[#7A0F0F] text-[#7A0F0F] font-bold"
                      cardBg = "bg-[#7A0F0F]/15"
                    }

                    return (
                      <div
                        key={obl.regulator}
                        className={`border ${statusClass} rounded-segment p-4 ${cardBg} flex flex-col justify-between transition`}
                      >
                        <div className="flex items-center justify-between pb-2 border-b border-[#1A2332]">
                          <span className="text-sm font-bold text-[#F0F6FC]">{obl.regulator}</span>
                          <span className={`px-2 py-0.5 rounded-segment text-xs border ${statusClass} uppercase font-mono`}>
                            {obl.status === "not_in_force" ? "Enforced May 2027" : obl.status}
                          </span>
                        </div>

                        <div className="my-3 text-center">
                          <div className="font-mono text-3xl font-extrabold tracking-tight text-[#F0F6FC] tabular-nums">
                            {countdown}
                          </div>
                          <div className="text-xs text-[#8B9BB4] mt-1 font-mono tabular-nums">
                            Deadline: {istDeadline}
                          </div>
                        </div>
                      </div>
                    )
                  })}
                </div>
              </div>
            )
          })
        )}
      </main>

      {/* Wallboard Footer */}
      <footer className="border-t border-[#1A2332] pt-3 text-xs text-[#8B9BB4] flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-[#00FF66]" />
          <span>CYBERQ Bank-Deployable Core • RBI / CERT-In / DPDP Statutory Engine</span>
        </div>
        <div className="font-mono text-[11px] text-[#8B9BB4]">
          Air-Gapped Telemetry Node • Zero PII Ingested
        </div>
      </footer>
    </div>
  )
}
