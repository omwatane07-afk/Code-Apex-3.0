/**
 * Indian Standard Time (IST) Clock & NTP Drift Calibration Engine.
 *
 * Enforces RBI & CERT-In statutory time synchronization mandates:
 * - Fixed IST offset: UTC+05:30 (19,800,000 ms)
 * - Maximum allowable clock skew / drift: 1.0 second
 */

export const IST_OFFSET_MS = 19800000 // UTC+05:30
export const MAX_ALLOWED_NTP_SKEW_SECONDS = 1.0

export interface CalibrationStatus {
  isCalibrated: boolean
  status: "ok" | "alarm"
  label: string
  utcHover: string
  detail: string
  istDisplay: string
}

/**
 * Formats a UTC ISO string to IST with Asia/Kolkata timezone.
 */
export function formatUtcToIst(utcIso: string, includeDate: boolean = false): string {
  if (!utcIso) return "N/A"
  const d = new Date(utcIso)
  if (isNaN(d.getTime())) return "Invalid Date"

  try {
    if (includeDate) {
      return (
        d.toLocaleString("en-IN", {
          timeZone: "Asia/Kolkata",
          day: "2-digit",
          month: "short",
          year: "numeric",
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
          hour12: false,
        }) + " IST"
      )
    }

    return (
      d.toLocaleTimeString("en-IN", {
        timeZone: "Asia/Kolkata",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false,
      }) + " IST"
    )
  } catch {
    return d.toISOString()
  }
}

/**
 * Calculates drift between client timestamp and server authoritative time.
 * Returns positive if client is ahead of server, negative if behind.
 */
export function calculateNtpDrift(serverTimeIso: string, clientMs: number = Date.now()): number {
  const serverMs = new Date(serverTimeIso).getTime()
  if (isNaN(serverMs)) return 0
  return (clientMs - serverMs) / 1000
}

/**
 * Flags regulatory violation when drift strictly exceeds 1.0s threshold.
 */
export function isNtpDriftExceeded(driftSeconds: number): boolean {
  return Math.abs(driftSeconds) > MAX_ALLOWED_NTP_SKEW_SECONDS
}

/**
 * Evaluates calibration status for UI header badges and alerts.
 */
export function evaluateCalibrationStatus(
  serverTimeIso: string | null,
  clientTime: Date = new Date(),
  customDrift?: number,
): CalibrationStatus {
  const drift = customDrift !== undefined
    ? customDrift
    : (serverTimeIso ? calculateNtpDrift(serverTimeIso, clientTime.getTime()) : 0)

  const exceeded = isNtpDriftExceeded(drift)
  const utcHover = `UTC: ${clientTime.toISOString()}`

  const istDisplay = formatUtcToIst(clientTime.toISOString())

  if (exceeded) {
    const sign = drift > 0 ? "+" : ""
    return {
      isCalibrated: false,
      status: "alarm",
      label: `NTP drift > 1s (${sign}${drift.toFixed(2)}s)`,
      utcHover,
      detail: `CRITICAL NTP SKEW: Drift (${drift.toFixed(2)}s) exceeds statutory 1.0s threshold (RBI Para 182 / CERT-In Directions 2022).`,
      istDisplay,
    }
  }

  return {
    isCalibrated: true,
    status: "ok",
    label: "IST calibrated",
    utcHover,
    detail: "Clock synchronized with Indian Standard Time (Asia/Kolkata, UTC+05:30). NTP drift < 1s.",
    istDisplay,
  }
}
