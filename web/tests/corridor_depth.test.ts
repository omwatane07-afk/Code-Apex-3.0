import { describe, it, expect } from "vitest"
import { timeToCorridorZ, buildViewModels, ObligationItem } from "../src/features/corridor/ClockViewModel"

describe("Corridor Depth Metric & View Model Invariants", () => {
  it("enforces monotonic depth mapping: larger time-remaining yields strictly deeper Z", () => {
    const timesSeconds = [10, 60, 300, 1800, 3600, 7200, 21600, 86400, 259200]
    const zValues = timesSeconds.map((s) => timeToCorridorZ(s))

    for (let i = 1; i < zValues.length; i++) {
      expect(zValues[i]).toBeGreaterThan(zValues[i - 1])
    }
  })

  it("maps past deadlines (zero or negative seconds) to Z=0", () => {
    expect(timeToCorridorZ(0)).toBe(0)
    expect(timeToCorridorZ(-100)).toBe(0)
    expect(timeToCorridorZ(-86400)).toBe(0)
  })

  it("produces finite, real numbers for extreme durations without NaN", () => {
    expect(Number.isFinite(timeToCorridorZ(1))).toBe(true)
    expect(Number.isFinite(timeToCorridorZ(1000000))).toBe(true)
    expect(isNaN(timeToCorridorZ(3600))).toBe(false)
  })

  it("builds view models with correct lane assignment and priority sorting", () => {
    const future1h = new Date(Date.now() + 3600000).toISOString()
    const future6h = new Date(Date.now() + 21600000).toISOString()

    const mockObligations: ObligationItem[] = [
      {
        id: "obl-rbi",
        regulator: "RBI",
        pack_id: "rbi-cybersecurity-directions-2026",
        status: "running",
        active_deadline_at: future6h,
        deadline_at: future6h,
        disputed_deadline_at: null,
        next_due_at: null,
      },
      {
        id: "obl-cert",
        regulator: "CERT-In",
        pack_id: "certin-directions-2022",
        status: "running",
        active_deadline_at: future1h,
        deadline_at: future1h,
        disputed_deadline_at: null,
        next_due_at: null,
      },
      {
        id: "obl-dpdp",
        regulator: "DPDP",
        pack_id: "dpdp-rules-2025",
        status: "not_in_force",
        active_deadline_at: null,
        deadline_at: null,
        disputed_deadline_at: null,
        next_due_at: null,
      },
    ]

    const vms = buildViewModels(mockObligations)
    expect(vms.length).toBe(3)

    // The most urgent clock (1h CERT-In) must be positioned closer to camera than 6h RBI
    const certVm = vms.find((v) => v.regulator === "CERT-In")!
    const rbiVm = vms.find((v) => v.regulator === "RBI")!
    const dpdpVm = vms.find((v) => v.regulator === "DPDP")!

    expect(certVm.depthZ).toBeLessThan(rbiVm.depthZ)
    expect(certVm.visualState).toBe("due_soon")
    expect(dpdpVm.visualState).toBe("not_in_force")
    expect(dpdpVm.formattedCountdown).toBe("Not in force")
  })

  it("strictly maps pending_trigger obligations with null deadlines to pending state rather than breached", () => {
    const mockPending: ObligationItem[] = [
      {
        id: "obl-pending-cert",
        regulator: "CERT-In",
        pack_id: "certin-directions-2022",
        status: "pending_trigger",
        active_deadline_at: null,
        deadline_at: null,
        disputed_deadline_at: null,
        next_due_at: null,
      },
      {
        id: "obl-pending-dpdp",
        regulator: "DPDP",
        pack_id: "dpdp-rules-2025",
        status: "pending_trigger",
        active_deadline_at: null,
        deadline_at: null,
        disputed_deadline_at: null,
        next_due_at: null,
        applicability_status: "not_in_force",
      },
      {
        id: "obl-exempt",
        regulator: "RBI",
        pack_id: "rbi-cybersecurity-directions-2026",
        status: "exempt_pending_approval",
        active_deadline_at: null,
        deadline_at: null,
        disputed_deadline_at: null,
        next_due_at: null,
        applicability_status: "exempt_pending_approval",
      },
    ]

    const vms = buildViewModels(mockPending)
    const cert = vms.find((v) => v.regulator === "CERT-In")!
    const dpdp = vms.find((v) => v.regulator === "DPDP")!
    const rbi = vms.find((v) => v.regulator === "RBI")!

    expect(cert.visualState).toBe("pending")
    expect(cert.formattedCountdown).toBe("Pending trigger")
    expect(cert.formattedCountdown).not.toContain("breached")
    expect(cert.depthZ).toBeGreaterThan(0) // Positioned at statutory horizon, not breached at 0

    expect(dpdp.visualState).toBe("not_in_force")
    expect(dpdp.formattedCountdown).toBe("Not in force")
    expect(dpdp.formattedCountdown).not.toContain("breached")

    expect(rbi.visualState).toBe("exempt")
    expect(rbi.formattedCountdown).toBe("Exempt (pending review)")
    expect(rbi.formattedCountdown).not.toContain("breached")
  })
})

