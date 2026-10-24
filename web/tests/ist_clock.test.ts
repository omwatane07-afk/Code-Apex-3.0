import { describe, it, expect } from "vitest"
import {
  formatUtcToIst,
  calculateNtpDrift,
  isNtpDriftExceeded,
  evaluateCalibrationStatus,
  IST_OFFSET_MS,
  MAX_ALLOWED_NTP_SKEW_SECONDS,
} from "../src/lib/istClock"

describe("IST Clock Calibration & NTP Drift Suite", () => {
  describe("IST Offset & Time Formatting", () => {
    it("confirms Indian Standard Time offset is exactly UTC+05:30 (19,800,000 ms)", () => {
      expect(IST_OFFSET_MS).toBe(19800000)
      expect(MAX_ALLOWED_NTP_SKEW_SECONDS).toBe(1.0)
    })

    it("correctly converts UTC string to IST with Asia/Kolkata timezone", () => {
      // 09:30:00 UTC + 5h30m = 15:00:00 IST
      const utcIso = "2026-10-18T09:30:00.000Z"
      const istStr = formatUtcToIst(utcIso, false)
      expect(istStr).toContain("15:00:00")
      expect(istStr).toContain("IST")
    })

    it("correctly handles midnight day rollover for IST", () => {
      // 20:00:00 UTC on 18-Oct -> 01:30:00 IST on 19-Oct
      const utcIso = "2026-10-18T20:00:00.000Z"
      const istStr = formatUtcToIst(utcIso, true)
      expect(istStr).toContain("01:30:00")
      expect(istStr).toContain("19")
      expect(istStr).toContain("IST")
    })

    it("gracefully handles invalid input without throwing", () => {
      expect(formatUtcToIst("invalid-date-token")).toBe("Invalid Date")
      expect(formatUtcToIst("")).toBe("N/A")
    })
  })

  describe("NTP Drift Calculation", () => {
    it("calculates zero drift when client and server timestamps match", () => {
      const serverTimeIso = "2026-10-18T10:00:00.000Z"
      const clientMs = new Date(serverTimeIso).getTime()
      const drift = calculateNtpDrift(serverTimeIso, clientMs)
      expect(drift).toBe(0)
    })

    it("calculates positive drift when client is ahead of server", () => {
      const serverTimeIso = "2026-10-18T10:00:00.000Z"
      const clientMs = new Date(serverTimeIso).getTime() + 1500 // +1.5s
      const drift = calculateNtpDrift(serverTimeIso, clientMs)
      expect(drift).toBeCloseTo(1.5, 2)
    })

    it("calculates negative drift when client is behind server", () => {
      const serverTimeIso = "2026-10-18T10:00:00.000Z"
      const clientMs = new Date(serverTimeIso).getTime() - 2100 // -2.1s
      const drift = calculateNtpDrift(serverTimeIso, clientMs)
      expect(drift).toBeCloseTo(-2.1, 2)
    })
  })

  describe("Drift Threshold Enforcement (>1s warning flag)", () => {
    it("permits acceptable drift <= 1.0s", () => {
      expect(isNtpDriftExceeded(0.0)).toBe(false)
      expect(isNtpDriftExceeded(0.05)).toBe(false)
      expect(isNtpDriftExceeded(0.99)).toBe(false)
      expect(isNtpDriftExceeded(-0.85)).toBe(false)
    })

    it("flags regulatory violation when drift strictly exceeds 1.0s threshold", () => {
      expect(isNtpDriftExceeded(1.01)).toBe(true)
      expect(isNtpDriftExceeded(2.5)).toBe(true)
      expect(isNtpDriftExceeded(-1.05)).toBe(true)
    })
  })

  describe("UI Header Badge Evaluation", () => {
    it("returns 'IST calibrated' (ok) when drift is within bounds", () => {
      const clientTime = new Date("2026-10-18T10:00:00.000Z")
      const status = evaluateCalibrationStatus(null, clientTime, 0.05)

      expect(status.isCalibrated).toBe(true)
      expect(status.status).toBe("ok")
      expect(status.label).toBe("IST calibrated")
      expect(status.utcHover).toBe("UTC: 2026-10-18T10:00:00.000Z")
    })

    it("returns 'NTP drift > 1s' (alarm) and loud warning when drift exceeds 1.0s", () => {
      const clientTime = new Date("2026-10-18T10:00:00.000Z")
      const status = evaluateCalibrationStatus(null, clientTime, 1.45)

      expect(status.isCalibrated).toBe(false)
      expect(status.status).toBe("alarm")
      expect(status.label).toContain("NTP drift > 1s")
      expect(status.label).toContain("+1.45s")
      expect(status.detail).toContain("CRITICAL NTP SKEW")
    })
  })
})
