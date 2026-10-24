/**
 * Shared ClockViewModel driving both 2D command center and 3D Deadline Corridor.
 * Implements monotonic, continuous time-to-depth mapping for compressed spatial runway.
 */

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

export type VisualGateState =
  | "running"
  | "due_soon"
  | "critical"
  | "breached"
  | "filed"
  | "not_in_force"
  | "disputed"
  | "pending"
  | "exempt"

export interface ClockViewModel {
  id: string
  regulator: string
  packId: string
  status: string
  visualState: VisualGateState
  deadlineAtUtc: string | null
  activeDeadlineUtc: string | null
  isDisputed: boolean
  secondsRemaining: number
  formattedCountdown: string
  formattedIst: string
  laneIndex: number // 0: CERT-In, 1: RBI DAKSH, 2: DPDP
  depthZ: number // Z position down runway (monotonic, continuous)
}

/**
 * Continuous, monotonic piecewise scale mapping time remaining (seconds) to runway depth Z.
 * - 0s -> 0.0 (Now / Observer position)
 * - 300s (5m) -> 1.25 (Immediately impending)
 * - 7,200s (2h) -> 30.0 (Due soon boundary)
 * - 21,600s (6h) -> 60.0 (CERT-In / RBI standard deadline)
 * - 259,200s (72h) -> 120.0 (DPDP detailed report deadline)
 *
 * Strictly monotonic: for t1 < t2, timeToCorridorZ(t1) < timeToCorridorZ(t2).
 * Continuous: zero step discontinuities at scale boundaries.
 */
export function timeToCorridorZ(secondsRemaining: number): number {
  if (secondsRemaining <= 0) return 0

  if (secondsRemaining <= 7200) {
    // 0 to 2 hours: linear mapping across 0 to 30 depth units
    return (secondsRemaining / 7200) * 30.0
  }

  if (secondsRemaining <= 21600) {
    // 2 to 6 hours: linear mapping across 30 to 60 depth units
    const fraction = (secondsRemaining - 7200) / (21600 - 7200)
    return 30.0 + fraction * 30.0
  }

  if (secondsRemaining <= 259200) {
    // 6 to 72 hours: logarithmic compression mapping across 60 to 120 depth units
    const fraction = (secondsRemaining - 21600) / (259200 - 21600)
    return 60.0 + fraction * 60.0
  }

  // Beyond 72 hours: gentle log asymptote
  return Math.min(150.0, 120.0 + Math.log10(secondsRemaining / 259200) * 15.0)
}

export function determineVisualState(
  status: string,
  secondsRemaining: number,
  deadlineAt: string | null = null,
  applicabilityStatus?: string
): VisualGateState {
  if (status === "not_in_force" || applicabilityStatus === "not_in_force") return "not_in_force"
  if (status === "exempt_pending_approval" || applicabilityStatus === "exempt_pending_approval") return "exempt"
  if (status === "pending_trigger" || !deadlineAt) return "pending"
  if (status === "filed") return "filed"
  if (status === "disputed") return "disputed"
  if (status === "breached") return "breached"
  if (secondsRemaining <= 0) return "breached"
  if (status === "critical" || secondsRemaining <= 1800) return "critical" // < 30m
  if (status === "due_soon" || secondsRemaining <= 7200) return "due_soon" // < 2h
  return "running"
}

export function formatHms(
  seconds: number,
  status?: string,
  deadlineAt?: string | null,
  applicabilityStatus?: string
): string {
  if (status === "not_in_force" || applicabilityStatus === "not_in_force") return "Not in force"
  if (status === "exempt_pending_approval" || applicabilityStatus === "exempt_pending_approval") {
    return "Exempt (pending review)"
  }
  if (status === "pending_trigger" || !deadlineAt) return "Pending trigger"
  if (status === "filed") return "Filed"
  if (seconds <= 0) return "00:00:00 (breached)"
  const h = Math.floor(seconds / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  const s = Math.floor(seconds % 60)
  return `${String(h).padStart(2, "0")}:${String(m).padStart(2, "0")}:${String(s).padStart(2, "0")}`
}

export function formatIstTime(utcString: string | null): string {
  if (!utcString) return "Pending assertion"
  const date = new Date(utcString)
  return (
    new Intl.DateTimeFormat("en-IN", {
      timeZone: "Asia/Kolkata",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      day: "2-digit",
      month: "short",
    }).format(date) + " IST"
  )
}

export function buildViewModels(obligations: ObligationItem[], nowMs: number = Date.now()): ClockViewModel[] {
  const laneOrder: Record<string, number> = {
    "CERT-In": 0,
    RBI: 1,
    DPDP: 2,
  }

  return obligations.map((o) => {
    const activeDeadline = o.active_deadline_at || o.deadline_at
    let secondsRemaining = 0

    if (activeDeadline) {
      const diff = new Date(activeDeadline).getTime() - nowMs
      secondsRemaining = Math.max(0, Math.floor(diff / 1000))
    }

    const visualState = determineVisualState(
      o.status,
      secondsRemaining,
      activeDeadline,
      o.applicability_status
    )

    let depthZ: number
    if (activeDeadline) {
      depthZ = timeToCorridorZ(secondsRemaining)
    } else if (o.regulator === "DPDP" || o.pack_id.includes("dpdp")) {
      depthZ = timeToCorridorZ(259200) // 72h statutory horizon
    } else {
      depthZ = timeToCorridorZ(21600) // 6h statutory horizon
    }

    const laneIndex = laneOrder[o.regulator] ?? 1

    return {
      id: o.id,
      regulator: o.regulator,
      packId: o.pack_id,
      status: o.status,
      visualState,
      deadlineAtUtc: o.deadline_at,
      activeDeadlineUtc: o.active_deadline_at,
      isDisputed: Boolean(o.disputed_deadline_at),
      secondsRemaining,
      formattedCountdown: formatHms(secondsRemaining, o.status, activeDeadline, o.applicability_status),
      formattedIst: formatIstTime(activeDeadline),
      laneIndex,
      depthZ,
    }
  })
}
