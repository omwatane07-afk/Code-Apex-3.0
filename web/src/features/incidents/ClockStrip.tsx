import { useState, useEffect } from "react"
import type { FC } from "react"
import { AlertTriangle } from "lucide-react"

export interface ObligationItem {
  id: string
  pack_id: string
  regulator: string
  status: string
  deadline_at: string | null
  disputed_deadline_at: string | null
  active_deadline_at: string | null
  next_due_at: string | null
  applicability_status?: string
}

interface ClockStripProps {
  obligations: ObligationItem[]
  serverTimeUtc?: string
}

function formatCountdown(targetUtc: string | null, nowMs: number): { text: string; fractionRemaining: number } {
  if (!targetUtc) return { text: "--:--:--", fractionRemaining: 1.0 }
  const target = new Date(targetUtc).getTime()
  const diff = target - nowMs

  if (diff <= 0) return { text: "00:00:00 (breached)", fractionRemaining: 0.0 }

  const hours = Math.floor(diff / 3600000)
  const minutes = Math.floor((diff % 3600000) / 60000)
  const seconds = Math.floor((diff % 60000) / 1000)

  // Fraction calculated relative to a typical 6-hour base (21,600,000ms)
  const fraction = Math.min(1.0, Math.max(0.0, diff / 21600000))

  return {
    text: `${String(hours).padStart(2, "0")}:${String(minutes).padStart(2, "0")}:${String(seconds).padStart(2, "0")}`,
    fractionRemaining: fraction,
  }
}

function formatIst(utcString: string | null): string {
  if (!utcString) return "Pending trigger assertion"
  const date = new Date(utcString)
  return (
    new Intl.DateTimeFormat("en-IN", {
      timeZone: "Asia/Kolkata",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      day: "2-digit",
      month: "short",
      year: "numeric",
    }).format(date) + " IST"
  )
}

export const ClockStrip: FC<ClockStripProps> = ({ obligations }) => {
  const [nowMs, setNowMs] = useState(Date.now())

  // Throttled clock update: strictly once per second
  useEffect(() => {
    const timer = setInterval(() => {
      setNowMs(Date.now())
    }, 1000)
    return () => clearInterval(timer)
  }, [])

  const certin = obligations.find((o) => o.regulator === "CERT-In")
  const rbi = obligations.find((o) => o.regulator === "RBI")
  const dpdp = obligations.find((o) => o.regulator === "DPDP")

  const renderSegment = (label: string, obligation?: ObligationItem) => {
    const status = obligation?.status || "pending_trigger"
    const activeDeadline = obligation?.active_deadline_at
    const { text: countdown, fractionRemaining } = formatCountdown(activeDeadline ?? null, nowMs)
    const istTime = formatIst(activeDeadline ?? null)

    const isUrgent = status === "due_soon" || status === "critical" || status === "breached"

    let badgeClass = "border-rule text-muted bg-surface"
    let statusLabel = "Pending trigger"
    let strokeColor = "#00E5FF"

    if (status === "running") {
      badgeClass = "border-status-ok text-status-ok bg-app"
      statusLabel = "Active countdown"
      strokeColor = "#00FF66"
    } else if (status === "due_soon") {
      badgeClass = "border-status-due_soon text-status-due_soon bg-app"
      statusLabel = "Due soon"
      strokeColor = "#FFB74D"
    } else if (status === "critical") {
      badgeClass = "border-status-critical text-status-critical bg-app font-semibold shadow-[0_0_8px_rgba(255,30,66,0.3)]"
      statusLabel = "Critical"
      strokeColor = "#FF1E42"
    } else if (status === "breached") {
      badgeClass = "border-status-critical text-status-critical bg-app font-bold"
      statusLabel = "Statutory breach"
      strokeColor = "#7A0F0F"
    } else if (status === "disputed") {
      badgeClass = "border-status-due_soon text-status-due_soon bg-app"
      statusLabel = "Under dispute"
      strokeColor = "#FFB74D"
    } else if (status === "filed") {
      badgeClass = "border-status-ok text-status-ok bg-app"
      statusLabel = "Filed"
      strokeColor = "#00FF66"
    } else if (status === "not_in_force") {
      badgeClass = "border-rule text-muted bg-app"
      statusLabel = "Not in force (13 May 2027)"
    }

    // Depleting arc circumference: r = 24 -> 2 * PI * 24 ≈ 150.8
    const circumference = 150.8
    const strokeDashoffset = circumference * (1 - fractionRemaining)

    return (
      <div
        style={{
          transform: isUrgent ? "translateZ(8px)" : "translateZ(0px)",
        }}
        className={`flex-1 min-w-[260px] border border-rule rounded-segment p-3 bg-surface flex flex-col justify-between transition-transform duration-300 motion-reduce:transform-none shadow-sm ${
          isUrgent ? "ring-1 ring-status-critical/30" : ""
        }`}
      >
        <div className="flex items-center justify-between pb-1 border-b border-rule">
          <span className="text-xs font-semibold text-main">{label}</span>
          <span className={`px-2 py-0.5 rounded-segment text-[11px] font-mono border ${badgeClass}`}>
            {statusLabel}
          </span>
        </div>

        <div className="my-2 flex items-center justify-between gap-3">
          <div>
            <div
              className="font-mono text-xl font-bold text-main tracking-tight tabular-nums"
              title={activeDeadline ? `UTC deadline: ${activeDeadline}` : "No active deadline"}
            >
              {countdown}
            </div>
            <div className="text-[11px] text-muted mt-0.5">
              <span>Deadline: </span>
              <span className="font-mono text-main tabular-nums">{istTime}</span>
            </div>
          </div>

          {/* Depleting Circular Arc Dial */}
          <div className="relative w-12 h-12 flex-shrink-0">
            <svg className="w-12 h-12 -rotate-90" viewBox="0 0 60 60">
              <circle
                cx="30"
                cy="30"
                r="24"
                stroke="currentColor"
                strokeWidth="4"
                className="text-rule/30"
                fill="none"
              />
              <circle
                cx="30"
                cy="30"
                r="24"
                stroke={strokeColor}
                strokeWidth="4"
                strokeDasharray={circumference}
                strokeDashoffset={strokeDashoffset}
                strokeLinecap="round"
                fill="none"
                className="transition-all duration-1000 ease-linear"
              />
            </svg>
          </div>
        </div>

        {/* Dual Deadline / Disputed Banner */}
        {obligation?.disputed_deadline_at && (
          <div className="mt-1 pt-1.5 border-t border-rule flex items-center gap-1.5 text-[11px] text-status-due_soon">
            <AlertTriangle className="w-3 h-3 flex-shrink-0" />
            <span className="truncate">Disputed counter-deadline: {formatIst(obligation.disputed_deadline_at)}</span>
          </div>
        )}

        {/* DPDP Untimed Step Notice */}
        {label.includes("DPDP") && (
          <div className="mt-1 pt-1.5 border-t border-rule text-[11px] text-muted">
            Initial intimation: without delay (untimed step)
          </div>
        )}
      </div>
    )
  }

  return (
    <section
      role="region"
      aria-label="Statutory obligation clock strip"
      style={{ perspective: "800px" }}
      className="p-3 bg-surface border-b border-rule flex flex-wrap gap-3 motion-reduce:perspective-none"
    >
      {renderSegment("CERT-In 6-hour clock", certin)}
      {renderSegment("RBI cyber incident log (DAKSH)", rbi)}
      {renderSegment("DPDP data protection board report", dpdp)}
    </section>
  )
}
