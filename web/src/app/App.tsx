import { useState, useEffect, useCallback, useRef, lazy, Suspense } from "react"
import { 
  ShieldAlert, 
  Clock, 
  FileCheck2, 
  BookOpenCheck, 
  Sliders, 
  Moon, 
  Sun, 
  Activity, 
  AlertTriangle, 
  Plus,
  Tv,
  Command,
  Layers,
  LayoutDashboard,
  ClipboardCheck,
  Cpu,
  Sparkles
} from "lucide-react"
import type { IncidentItem, TriggerItem } from "../features/incidents/types"
import type { WallboardIncident } from "../features/wallboard/WallboardView"
import { evaluateCalibrationStatus } from "../lib/istClock"
import { TelemetryProvider, useTelemetry, playAlertChime } from "../lib/telemetryContext"
import type { LiveAnomalyAlert } from "../lib/liveTelemetryEngine"
import { generateRandomIncident } from "../lib/randomIncidentGenerator"

const LiveAnomalyNotificationModal = lazy(() =>
  import("../features/admin/LiveAnomalyNotificationModal").then((m) => ({ default: m.LiveAnomalyNotificationModal }))
)
const LiveTelemetryDrawer = lazy(() =>
  import("../features/telemetry/LiveTelemetryDrawer").then((m) => ({ default: m.LiveTelemetryDrawer }))
)

const ClockStrip = lazy(() =>
  import("../features/incidents/ClockStrip").then((m) => ({ default: m.ClockStrip }))
)

const IncidentDetail = lazy(() =>
  import("../features/incidents/IncidentDetail").then((m) => ({ default: m.IncidentDetail }))
)

const NewIncidentModal = lazy(() =>
  import("../features/incidents/NewIncidentModal").then((m) => ({ default: m.NewIncidentModal }))
)
const AssertTriggerModal = lazy(() =>
  import("../features/incidents/AssertTriggerModal").then((m) => ({ default: m.AssertTriggerModal }))
)
const CorridorView = lazy(() =>
  import("../features/corridor/CorridorView").then((m) => ({ default: m.CorridorView }))
)
const WallboardView = lazy(() =>
  import("../features/wallboard/WallboardView").then((m) => ({ default: m.WallboardView }))
)
const ActivityView = lazy(() =>
  import("../features/activity/ActivityView").then((m) => ({ default: m.ActivityView }))
)
const DecisionsView = lazy(() =>
  import("../features/decisions/DecisionsView").then((m) => ({ default: m.DecisionsView }))
)
const FilingsView = lazy(() =>
  import("../features/filings/FilingsView").then((m) => ({ default: m.FilingsView }))
)
const AdminView = lazy(() =>
  import("../features/admin/AdminView").then((m) => ({ default: m.AdminView }))
)
const VerificationView = lazy(() =>
  import("../features/verification/VerificationView").then((m) => ({ default: m.VerificationView }))
)
const CisoOverviewCard = lazy(() =>
  import("../features/ciso/CisoOverviewCard").then((m) => ({ default: m.CisoOverviewCard }))
)
const CommandPalette = lazy(() =>
  import("../components/CommandPalette").then((m) => ({ default: m.CommandPalette }))
)
const ShiftHandoverModal = lazy(() =>
  import("../features/handover/ShiftHandoverModal").then((m) => ({ default: m.ShiftHandoverModal }))
)
const DemoOverlay = lazy(() =>
  import("../features/demo/DemoOverlay").then((m) => ({ default: m.DemoOverlay }))
)

export type AppView = "command" | "wall" | "activity" | "decisions" | "filings" | "admin" | "verification"
export type UserRole = "analyst" | "compliance_approver" | "ciso" | "admin" | "auditor" | "model_validator"

export const ROLE_LABELS: Record<UserRole, string> = {
  analyst: "Analyst",
  compliance_approver: "Compliance Approver",
  ciso: "CISO",
  auditor: "Auditor",
  model_validator: "Model Validator",
  admin: "Admin",
}

export function getViewFromPath(pathname: string): AppView {
  if (pathname.startsWith("/wall")) return "wall"
  if (pathname.startsWith("/activity")) return "activity"
  if (pathname.startsWith("/decisions")) return "decisions"
  if (pathname.startsWith("/filings")) return "filings"
  if (pathname.startsWith("/admin")) return "admin"
  if (pathname.startsWith("/verification")) return "verification"
  return "command"
}

export function getPathForView(view: AppView): string {
  switch (view) {
    case "wall":
      return "/wall"
    case "activity":
      return "/activity"
    case "decisions":
      return "/decisions"
    case "filings":
      return "/filings"
    case "admin":
      return "/admin"
    case "verification":
      return "/verification"
    default:
      return "/"
  }
}

function AppContent() {
  const {
    toolsState,
    telemetry,
    activeAnomalies,
    soundEnabled,
    toggleSound,
    dismissAnomaly,
    dismissAllAnomalies,
    acknowledgeAnomaly,
    openDrawer,
    triggerAnomaly,
  } = useTelemetry()

  const totalEps = toolsState.reduce((acc, t) => acc + t.metrics.events_per_minute, 0)
  const hasAnomaly = activeAnomalies.length > 0

  const [theme, setTheme] = useState<"light" | "dark">("dark")
  const isProd = import.meta.env.PROD || import.meta.env.MODE === "production"
  const isDemoParam = typeof window !== "undefined" && (
    new URLSearchParams(window.location.search).get("demo") === "1" ||
    new URLSearchParams(window.location.search).has("role")
  )
  const [runtimeEnv, setRuntimeEnv] = useState<string>(() => (isDemoParam ? "DEMO" : (isProd ? "PRODUCTION" : "DEMO")))
  
  const [userRole, setUserRole] = useState<UserRole>(() => {
    if (typeof window !== "undefined") {
      const paramRole = new URLSearchParams(window.location.search).get("role")
      if (paramRole) {
        if (paramRole === "compliance") return "compliance_approver"
        if (paramRole in ROLE_LABELS) return paramRole as UserRole
      }
    }
    return "analyst"
  })

  const [currentUserId, setCurrentUserId] = useState<string>("analyst-01")
  const [csrfToken, setCsrfToken] = useState<string>("")
  const [cisoAlertsCount, setCisoAlertsCount] = useState<number>(0)
  
  // Navigation & Modals
  const [currentView, setCurrentView] = useState<AppView>(() => {
    if (typeof window !== "undefined") {
      return getViewFromPath(window.location.pathname)
    }
    return "command"
  })
  const [activeTab, setActiveTab] = useState<"detail" | "corridor">("corridor")
  const [isNewModalOpen, setIsNewModalOpen] = useState(false)
  const [isAssertModalOpen, setIsAssertModalOpen] = useState(false)
  const [isHandoverOpen, setIsHandoverOpen] = useState(false)
  const [isPaletteOpen, setIsPaletteOpen] = useState(false)
  const [newIncidentInitialData, setNewIncidentInitialData] = useState<{
    title?: string
    summary?: string
    severity?: "low" | "medium" | "high" | "critical"
  } | null>(null)

  // Automated Random Incident Generator State
  const [isAutoGenerating, setIsAutoGenerating] = useState<boolean>(true)
  const [autoGenIntervalSec, setAutoGenIntervalSec] = useState<number>(35)
  const [nextGenCountdown, setNextGenCountdown] = useState<number>(35)
  const [autoGenToast, setAutoGenToast] = useState<{
    id: string
    incidentNumber: string
    title: string
    severity: string
  } | null>(null)

  const cycleAutoGenSpeed = () => {
    setAutoGenIntervalSec((prev) => {
      const next = prev === 20 ? 35 : prev === 35 ? 60 : 20
      setNextGenCountdown(next)
      return next
    })
  }

  const openNewIncident = () => {
    setNewIncidentInitialData(null)
    setIsNewModalOpen(true)
  }

  // Seed demo incidents with realistic commercial banking scenarios
  const [incidents, setIncidents] = useState<IncidentItem[]>([
    {
      id: "demo-inc-01",
      incident_number: "INC-2026-0001",
      title: "Core switch routing loop impacting RTGS settlement channel",
      summary: "Intermittent packet loss and BGP neighbor flapping detected across DC-1 border switches impacting RTGS settlement queues. Traffic rerouted to secondary path. Diagnostic memory capture underway.",
      severity: "high",
      status: "new",
      created_at: new Date(Date.now() - 3600000).toISOString(),
      updated_at: new Date().toISOString(),
      created_by_id: "analyst-01",
      is_major: false,
      triggers: [],
      obligations: [
        {
          id: "obl-1",
          incident_id: "demo-inc-01",
          pack_id: "certin-directions-2022",
          regulator: "CERT-In",
          status: "pending_trigger",
          deadline_at: null,
          disputed_deadline_at: null,
          active_deadline_at: null,
          next_due_at: null,
          escalation_level: 0,
          applicability_status: "assumed_applicable",
        },
        {
          id: "obl-2",
          incident_id: "demo-inc-01",
          pack_id: "rbi-cybersecurity-directions-2026",
          regulator: "RBI",
          status: "pending_trigger",
          deadline_at: null,
          disputed_deadline_at: null,
          active_deadline_at: null,
          next_due_at: null,
          escalation_level: 0,
          applicability_status: "assumed_applicable",
        },
        {
          id: "obl-3",
          incident_id: "demo-inc-01",
          pack_id: "dpdp-rules-2025",
          regulator: "DPDP",
          status: "pending_trigger",
          deadline_at: null,
          disputed_deadline_at: null,
          active_deadline_at: null,
          next_due_at: null,
          escalation_level: 0,
          applicability_status: "not_in_force",
        },
      ],
    },
    {
      id: "demo-inc-02",
      incident_number: "INC-2026-0002",
      title: "External vendor credential exposure on public code repository",
      summary: "API access credentials for payment gateway staging connector identified on third-party public git repository. Immediate token revocation completed; auditing access logs.",
      severity: "critical",
      status: "new",
      created_at: new Date(Date.now() - 7200000).toISOString(),
      updated_at: new Date().toISOString(),
      created_by_id: "analyst-01",
      is_major: false,
      triggers: [],
      obligations: [
        {
          id: "obl-4",
          incident_id: "demo-inc-02",
          pack_id: "certin-directions-2022",
          regulator: "CERT-In",
          status: "pending_trigger",
          deadline_at: null,
          disputed_deadline_at: null,
          active_deadline_at: null,
          next_due_at: null,
          escalation_level: 0,
          applicability_status: "assumed_applicable",
        },
        {
          id: "obl-5",
          incident_id: "demo-inc-02",
          pack_id: "rbi-cybersecurity-directions-2026",
          regulator: "RBI",
          status: "pending_trigger",
          deadline_at: null,
          disputed_deadline_at: null,
          active_deadline_at: null,
          next_due_at: null,
          escalation_level: 0,
          applicability_status: "assumed_applicable",
        },
        {
          id: "obl-6",
          incident_id: "demo-inc-02",
          pack_id: "dpdp-rules-2025",
          regulator: "DPDP",
          status: "pending_trigger",
          deadline_at: null,
          disputed_deadline_at: null,
          active_deadline_at: null,
          next_due_at: null,
          escalation_level: 0,
          applicability_status: "not_in_force",
        },
      ],
    },
    {
      id: "demo-inc-03",
      incident_number: "INC-2026-0003",
      title: "Core Banking System (CBS) NEFT batch processing timeout",
      summary: "EOD clearing batch processing latency exceeded SLA threshold (90 min delay) due to Oracle database tablespace exhaustion during holiday settlement surge. No data loss observed.",
      severity: "medium",
      status: "contained",
      created_at: new Date(Date.now() - 10800000).toISOString(),
      updated_at: new Date(Date.now() - 1800000).toISOString(),
      created_by_id: "analyst-01",
      is_major: false,
      triggers: [],
      obligations: [
        {
          id: "obl-7",
          incident_id: "demo-inc-03",
          pack_id: "certin-directions-2022",
          regulator: "CERT-In",
          status: "pending_trigger",
          deadline_at: null,
          disputed_deadline_at: null,
          active_deadline_at: null,
          next_due_at: null,
          escalation_level: 0,
          applicability_status: "assumed_applicable",
        },
        {
          id: "obl-8",
          incident_id: "demo-inc-03",
          pack_id: "rbi-cybersecurity-directions-2026",
          regulator: "RBI",
          status: "pending_trigger",
          deadline_at: null,
          disputed_deadline_at: null,
          active_deadline_at: null,
          next_due_at: null,
          escalation_level: 0,
          applicability_status: "assumed_applicable",
        },
        {
          id: "obl-9",
          incident_id: "demo-inc-03",
          pack_id: "dpdp-rules-2025",
          regulator: "DPDP",
          status: "pending_trigger",
          deadline_at: null,
          disputed_deadline_at: null,
          active_deadline_at: null,
          next_due_at: null,
          escalation_level: 0,
          applicability_status: "not_in_force",
        },
      ],
    },
  ])

  // Live IST Calibrated Clock and monotonic drift monitor
  const [clockTick, setClockTick] = useState<Date>(() => new Date())
  const [serverUtcIso, setServerUtcIso] = useState<string | null>(null)
  const [ntpSkew, setNtpSkew] = useState<number>(0.05)

  useEffect(() => {
    const timer = setInterval(() => setClockTick(new Date()), 1000)
    return () => clearInterval(timer)
  }, [])

  useEffect(() => {
    const checkTelemetry = async () => {
      try {
        const res = await fetch("/readyz")
        if (res.ok) {
          const data = await res.json()
          if (data.server_time_utc) setServerUtcIso(data.server_time_utc)
          if (typeof data.ntp_skew_seconds === "number") setNtpSkew(data.ntp_skew_seconds)
        }
      } catch {
        // Air-gapped offline resilience
      }
    }
    checkTelemetry()
    const poll = setInterval(checkTelemetry, 30000)
    return () => clearInterval(poll)
  }, [])

  const calibration = evaluateCalibrationStatus(serverUtcIso, clockTick, ntpSkew)

  const [selectedIncidentId, setSelectedIncidentId] = useState<string>("demo-inc-01")

  const rawSelectedIncident = incidents.find((i) => i.id === selectedIncidentId) || incidents[0]

  // Role-based masking matching server policy (Admin cannot see incident narratives; Auditor has masked narrative)
  const selectedIncident = rawSelectedIncident ? {
    ...rawSelectedIncident,
    title: userRole === "admin" 
      ? `${rawSelectedIncident.incident_number} (Narrative masked - Admin role)` 
      : rawSelectedIncident.title,
    summary: userRole === "admin" 
      ? "[REDACTED_FOR_ADMIN: Admin is config-only and cannot view incident narratives]" 
      : userRole === "auditor" 
      ? "[REDACTED_FOR_AUDIT]" 
      : rawSelectedIncident.summary,
  } : undefined

  useEffect(() => {
    const root = document.documentElement
    if (theme === "dark") {
      root.classList.add("dark")
      root.setAttribute("data-theme", "dark")
    } else {
      root.classList.remove("dark")
      root.setAttribute("data-theme", "light")
    }
  }, [theme])

  // Fetch runtime environment from /healthz
  useEffect(() => {
    fetch("/healthz")
      .then((res) => res.json())
      .then((data) => {
        if (data?.environment) {
          setRuntimeEnv(data.environment.toUpperCase())
        }
      })
      .catch(() => {})
  }, [])

  const isDemo = runtimeEnv.toLowerCase() === "demo" || isDemoParam

  // Demo session initialization & role session management
  useEffect(() => {
    const initAuth = async () => {
      try {
        const urlParamRole = typeof window !== "undefined" ? new URLSearchParams(window.location.search).get("role") : null
        const targetRole = urlParamRole === "compliance" 
          ? "compliance_approver" 
          : (urlParamRole && urlParamRole in ROLE_LABELS ? urlParamRole as UserRole : null)

        const meRes = await fetch("/api/v1/auth/me")
        if (meRes.ok) {
          const meData = await meRes.json()
          if (targetRole && targetRole !== meData.active_role && isDemo) {
            await handleRoleChange(targetRole)
            return
          }
          setCurrentUserId(meData.id)
          setCsrfToken(meData.csrf_token)
          if (meData.active_role && meData.active_role in ROLE_LABELS) {
            setUserRole(meData.active_role as UserRole)
          }
          return
        }

        if (isDemo) {
          const roleToUse = targetRole || userRole
          const loginRes = await fetch("/api/v1/auth/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              username: `${roleToUse}_user`,
              role: roleToUse,
              full_name: `Demo ${ROLE_LABELS[roleToUse] || roleToUse}`,
            }),
          })
          if (loginRes.ok) {
            const loginData = await loginRes.json()
            setCurrentUserId(loginData.id)
            setCsrfToken(loginData.csrf_token)
            setUserRole(roleToUse)
          }
        }
      } catch {
        // Safe fallback in offline mode
      }
    }
    initAuth()
  }, [isDemo])

  // CISO action alerts polling
  useEffect(() => {
    if (userRole !== "ciso") return
    const fetchAlerts = async () => {
      try {
        const res = await fetch("/api/v1/governance/ciso-alerts")
        if (res.ok) {
          const json = await res.json()
          setCisoAlertsCount(json.total_alerts || 0)
        }
      } catch {
        // Fallback
      }
    }
    fetchAlerts()
    const timer = setInterval(fetchAlerts, 15000)
    return () => clearInterval(timer)
  }, [userRole])

  const handleRoleChange = async (newRole: UserRole) => {
    setUserRole(newRole)
    const roleName = ROLE_LABELS[newRole] || newRole

    try {
      const res = await fetch("/api/v1/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: `${newRole}_user`,
          role: newRole,
          full_name: `Demo ${roleName}`,
        }),
      })
      if (res.ok) {
        const data = await res.json()
        setCurrentUserId(data.id)
        setCsrfToken(data.csrf_token)
      }
    } catch {
      // Offline fallback
    }

    if (typeof window !== "undefined") {
      const url = new URL(window.location.href)
      url.searchParams.set("role", newRole)
      if (isDemo) {
        url.searchParams.set("demo", "1")
      }
      window.history.replaceState({}, "", url.toString())
    }
  }

  // Browser history sync across all views
  useEffect(() => {
    const handlePop = () => {
      setCurrentView(getViewFromPath(window.location.pathname))
    }
    window.addEventListener("popstate", handlePop)
    return () => window.removeEventListener("popstate", handlePop)
  }, [])

  const navigateTo = (view: AppView) => {
    window.history.pushState({}, "", getPathForView(view))
    setCurrentView(view)
  }

  const navigateToWallboard = () => navigateTo("wall")
  const navigateToCommand = () => navigateTo("command")

  // Global keyboard shortcuts (Ctrl+K palette, 'g' navigation sequences, 'a' assert trigger, 'n' new incident)
  useEffect(() => {
    let gTimer: any = null
    let gPressed = false

    const handleGlobalKeyDown = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement
      const inInput =
        target.tagName === "INPUT" ||
        target.tagName === "TEXTAREA" ||
        target.isContentEditable

      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault()
        setIsPaletteOpen((prev) => !prev)
        return
      }

      if (inInput || isPaletteOpen || isNewModalOpen || isAssertModalOpen || isHandoverOpen) {
        return
      }

      // 'g' navigation sequence (g i, g w, g a, g d, g f, g m)
      if (gPressed) {
        gPressed = false
        if (gTimer) clearTimeout(gTimer)
        const key = e.key.toLowerCase()
        if (key === "i") {
          e.preventDefault()
          navigateTo("command")
          return
        }
        if (key === "w") {
          e.preventDefault()
          navigateTo("wall")
          return
        }
        if (key === "a") {
          e.preventDefault()
          navigateTo("activity")
          return
        }
        if (key === "d") {
          e.preventDefault()
          navigateTo("decisions")
          return
        }
        if (key === "f") {
          e.preventDefault()
          navigateTo("filings")
          return
        }
        if (key === "m") {
          e.preventDefault()
          navigateTo("admin")
          return
        }
        if (key === "v") {
          e.preventDefault()
          navigateTo("verification")
          return
        }
      }

      if (e.key === "g") {
        gPressed = true
        gTimer = setTimeout(() => {
          gPressed = false
        }, 1200)
        return
      }

      if (currentView === "command") {
        if (e.key === "a") {
          e.preventDefault()
          setIsAssertModalOpen(true)
        } else if (e.key === "n") {
          e.preventDefault()
          openNewIncident()
        }
      }
    }

    window.addEventListener("keydown", handleGlobalKeyDown)
    return () => {
      window.removeEventListener("keydown", handleGlobalKeyDown)
      if (gTimer) clearTimeout(gTimer)
    }
  }, [currentView, isPaletteOpen, isNewModalOpen, isAssertModalOpen, isHandoverOpen])

  const toggleTheme = () => {
    setTheme((prev) => (prev === "light" ? "dark" : "light"))
  }

  const handleCreateIncident = async (
    title: string, 
    summary: string, 
    severity: any, 
    _overridePii?: boolean, 
    _overrideReason?: string
  ) => {
    const newInc: IncidentItem = {
      id: `inc-${Date.now()}`,
      incident_number: `INC-2026-${String(incidents.length + 1).padStart(4, "0")}`,
      title,
      summary,
      severity,
      status: "new",
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      created_by_id: currentUserId,
      is_major: false,
      triggers: [],
      obligations: [
        {
          id: `obl-c-${Date.now()}`,
          incident_id: `inc-${Date.now()}`,
          pack_id: "certin-directions-2022",
          regulator: "CERT-In",
          status: "pending_trigger",
          deadline_at: null,
          disputed_deadline_at: null,
          active_deadline_at: null,
          next_due_at: null,
          escalation_level: 0,
          applicability_status: "assumed_applicable",
        },
        {
          id: `obl-r-${Date.now()}`,
          incident_id: `inc-${Date.now()}`,
          pack_id: "rbi-cybersecurity-directions-2026",
          regulator: "RBI",
          status: "pending_trigger",
          deadline_at: null,
          disputed_deadline_at: null,
          active_deadline_at: null,
          next_due_at: null,
          escalation_level: 0,
          applicability_status: "assumed_applicable",
        },
        {
          id: `obl-d-${Date.now()}`,
          incident_id: `inc-${Date.now()}`,
          pack_id: "dpdp-rules-2025",
          regulator: "DPDP",
          status: "pending_trigger",
          deadline_at: null,
          disputed_deadline_at: null,
          active_deadline_at: null,
          next_due_at: null,
          escalation_level: 0,
          applicability_status: "not_in_force",
        },
      ],
    }
    setIncidents([newInc, ...incidents])
    setSelectedIncidentId(newInc.id)
  }

  const handleCreateIncidentFromAnomaly = (alert: LiveAnomalyAlert) => {
    const title = `[${alert.category}] ${alert.title}`
    const summary = `Source Tool: ${alert.tool_name} (${alert.category})\nAffected Asset: ${alert.affected_asset}\nTelemetry Metric Spike: ${alert.anomalous_metric}\nMITRE ATT&CK: ${alert.mitre_attack_id}\n\nThreat Description:\n${alert.description}\n\nAutomated Containment Action: ${alert.automated_response} (${alert.response_status})`
    const severity: "low" | "medium" | "high" | "critical" = alert.severity === "critical" ? "critical" : alert.severity === "high" ? "high" : "medium"

    // Fill form in the incident menu without direct submission
    setNewIncidentInitialData({ title, summary, severity })
    setIsNewModalOpen(true)
    acknowledgeAnomaly(alert.id)
    navigateTo("command")
  }

  const incidentsRef = useRef(incidents)
  incidentsRef.current = incidents

  const handleGenerateRandomIncident = useCallback(async () => {
    const newInc = generateRandomIncident(incidentsRef.current, currentUserId)
    setIncidents((prev) => [newInc, ...prev])
    setSelectedIncidentId(newInc.id)

    setAutoGenToast({
      id: newInc.id,
      incidentNumber: newInc.incident_number,
      title: newInc.title,
      severity: newInc.severity,
    })

    if (soundEnabled) {
      playAlertChime(newInc.severity === "critical")
    }

    setTimeout(() => {
      setAutoGenToast((curr) => (curr?.id === newInc.id ? null : curr))
    }, 7000)

    try {
      await fetch("/api/v1/incidents/simulate-random", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(csrfToken ? { "X-CSRF-Token": csrfToken } : {}),
        },
      })
    } catch {
      // Offline fallback
    }
  }, [currentUserId, soundEnabled, csrfToken])

  // Background auto-generation interval
  useEffect(() => {
    if (!isAutoGenerating) return

    const timer = setInterval(() => {
      setNextGenCountdown((prev) => {
        if (prev <= 1) {
          handleGenerateRandomIncident()
          return autoGenIntervalSec
        }
        return prev - 1
      })
    }, 1000)

    return () => clearInterval(timer)
  }, [isAutoGenerating, autoGenIntervalSec, handleGenerateRandomIncident])

  const handleTransition = (targetStatus: any) => {
    if (!selectedIncident) return
    const updated = incidents.map((inc) => {
      if (inc.id === selectedIncident.id) {
        return {
          ...inc,
          status: targetStatus,
          updated_at: new Date().toISOString(),
        }
      }
      return inc
    })
    setIncidents(updated)
  }

  const handleSeverityChange = async (incidentId: string, severity: "low" | "medium" | "high" | "critical", reason: string) => {
    try {
      const res = await fetch(`/api/v1/incidents/${incidentId}/severity`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(csrfToken ? { "X-CSRF-Token": csrfToken } : {}),
        },
        body: JSON.stringify({
          new_severity: severity,
          rationale: reason,
        }),
      })
      if (res.ok) {
        const data = await res.json()
        setIncidents((prev) => prev.map((inc) => (inc.id === incidentId ? { ...inc, severity: data.severity, updated_at: data.updated_at } : inc)))
        return
      }
    } catch {
      // Fallback
    }
    setIncidents((prev) => prev.map((inc) => (inc.id === incidentId ? { ...inc, severity, updated_at: new Date().toISOString() } : inc)))
  }

  const handleDeclareMajor = async (incidentId: string, reason: string) => {
    try {
      const res = await fetch(`/api/v1/incidents/${incidentId}/declare-major`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(csrfToken ? { "X-CSRF-Token": csrfToken } : {}),
        },
        body: JSON.stringify({ reason }),
      })
      if (res.ok) {
        const data = await res.json()
        setIncidents((prev) => prev.map((inc) => (inc.id === incidentId ? {
          ...inc,
          is_major: true,
          major_declared_at: data.major_declared_at || new Date().toISOString(),
          major_declared_by_id: data.major_declared_by_id || currentUserId,
          major_reason: reason,
          updated_at: data.updated_at || new Date().toISOString(),
        } : inc)))
        return
      }
    } catch {
      // Fallback
    }
    setIncidents((prev) => prev.map((inc) => (inc.id === incidentId ? {
      ...inc,
      is_major: true,
      major_declared_at: new Date().toISOString(),
      major_declared_by_id: currentUserId || "ciso-01",
      major_reason: reason,
      updated_at: new Date().toISOString(),
    } : inc)))
  }

  const handleApproveClosure = async (incidentId: string, closureNotes: string) => {
    try {
      const res = await fetch(`/api/v1/incidents/${incidentId}/approve-closure`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(csrfToken ? { "X-CSRF-Token": csrfToken } : {}),
        },
        body: JSON.stringify({ closure_notes: closureNotes }),
      })
      if (res.ok) {
        const data = await res.json()
        setIncidents((prev) => prev.map((inc) => (inc.id === incidentId ? {
          ...inc,
          status: "closed",
          closed_by_id: data.closed_by_id || currentUserId,
          closed_at: data.closed_at || new Date().toISOString(),
          closure_notes: closureNotes,
          updated_at: data.updated_at || new Date().toISOString(),
        } : inc)))
        return
      }
    } catch {
      // Fallback
    }
    setIncidents((prev) => prev.map((inc) => (inc.id === incidentId ? {
      ...inc,
      status: "closed",
      closed_by_id: currentUserId || "ciso-01",
      closed_at: new Date().toISOString(),
      closure_notes: closureNotes,
      updated_at: new Date().toISOString(),
    } : inc)))
  }

  const handleTriggerDpdpAware = async (incidentId: string) => {
    const nowIso = new Date().toISOString()
    const deadline72hIso = new Date(Date.now() + 72 * 3600000).toISOString()

    setIncidents((prev) =>
      prev.map((inc) => {
        if (inc.id !== incidentId) return inc
        const updatedObls = inc.obligations.map((obl) => {
          if (obl.regulator === "DPDP" || obl.pack_id === "dpdp-rules-2025") {
            return {
              ...obl,
              status: "running",
              deadline_at: deadline72hIso,
              active_deadline_at: deadline72hIso,
              next_due_at: new Date(Date.now() + 68 * 3600000).toISOString(),
              applicability_status: "assumed_applicable",
            }
          }
          return obl
        })
        const newTrigger: TriggerItem = {
          id: `trig-aware-${Date.now()}`,
          incident_id: incidentId,
          trigger_type: "aware",
          occurred_at: nowIso,
          recorded_at: nowIso,
          asserted_by_id: currentUserId || "analyst-01",
          evidence_summary: "Automated personal data leakage detector identified potential data principal record exposure.",
          rationale: "Statutory breach intimation requirement under DPDP Rules 2025 Rule 7 asserted by SOC Analyst.",
          is_disputed: false,
        }
        return {
          ...inc,
          triggers: [...inc.triggers, newTrigger],
          obligations: updatedObls,
          updated_at: nowIso,
        }
      })
    )
  }

  const handleAssertTrigger = async (
    triggerType: string,
    occurredAt: string,
    evidence: string,
    rationale: string,
    assertBothTriggers: boolean = true,
    applicabilityAnswers?: {
      personal_data: "yes" | "no" | "not_sure"
      reportable_category: "yes" | "no" | "not_sure"
      rationale: string
    }
  ) => {
    if (!rawSelectedIncident) return

    const newTriggers: TriggerItem[] = []
    const occurredDate = new Date(occurredAt)
    const deadlineDate6h = new Date(occurredDate.getTime() + 6 * 3600000).toISOString()

    if (assertBothTriggers) {
      newTriggers.push({
        id: `trig-noticed-${Date.now()}`,
        incident_id: rawSelectedIncident.id,
        trigger_type: "noticed",
        occurred_at: occurredAt,
        recorded_at: new Date().toISOString(),
        asserted_by_id: currentUserId,
        evidence_summary: evidence,
        rationale,
        is_disputed: false,
      })
      newTriggers.push({
        id: `trig-detected-${Date.now() + 1}`,
        incident_id: rawSelectedIncident.id,
        trigger_type: "detected",
        occurred_at: occurredAt,
        recorded_at: new Date().toISOString(),
        asserted_by_id: currentUserId,
        evidence_summary: evidence,
        rationale,
        is_disputed: false,
      })
    } else {
      newTriggers.push({
        id: `trig-${Date.now()}`,
        incident_id: rawSelectedIncident.id,
        trigger_type: triggerType,
        occurred_at: occurredAt,
        recorded_at: new Date().toISOString(),
        asserted_by_id: currentUserId,
        evidence_summary: evidence,
        rationale,
        is_disputed: false,
      })
    }

    const updatedObligations = rawSelectedIncident.obligations.map((obl) => {
      let isTriggered = false
      let deadlineIso = deadlineDate6h

      if (assertBothTriggers) {
        if (obl.regulator === "CERT-In" || obl.regulator === "RBI") {
          isTriggered = true
        }
      } else {
        if (triggerType === "noticed" && obl.regulator === "CERT-In") isTriggered = true
        if (triggerType === "detected" && obl.regulator === "RBI") isTriggered = true
        if (triggerType === "aware" && obl.regulator === "DPDP") {
          isTriggered = true
          deadlineIso = new Date(occurredDate.getTime() + 72 * 3600000).toISOString()
        }
      }

      let applicabilityStatus = obl.applicability_status || "assumed_applicable"
      let pendingRationale = obl.applicability_pending_rationale

      if (applicabilityAnswers) {
        if (applicabilityAnswers.reportable_category === "no") {
          applicabilityStatus = "exempt_pending_approval"
          pendingRationale = applicabilityAnswers.rationale
        }
      }

      if (isTriggered) {
        return {
          ...obl,
          status: "running",
          deadline_at: deadlineIso,
          active_deadline_at: deadlineIso,
          next_due_at: new Date(new Date(deadlineIso).getTime() - 4 * 3600000).toISOString(),
          applicability_status: applicabilityStatus,
          applicability_pending_rationale: pendingRationale,
        }
      }
      return {
        ...obl,
        applicability_status: applicabilityStatus,
        applicability_pending_rationale: pendingRationale,
      }
    })

    const updated = incidents.map((inc) => {
      if (inc.id === rawSelectedIncident.id) {
        return {
          ...inc,
          triggers: [...inc.triggers, ...newTriggers],
          obligations: updatedObligations,
          updated_at: new Date().toISOString(),
        }
      }
      return inc
    })

    setIncidents(updated)
  }

  // Sanitized wallboard data (no titles, summaries, or personal identities)
  const wallboardIncidents: WallboardIncident[] = incidents.map((inc) => ({
    incident_number: inc.incident_number,
    severity: inc.severity,
    status: inc.status,
    obligations: inc.obligations.map((o) => ({
      regulator: o.regulator,
      status: o.status,
      deadline_at: o.deadline_at,
      active_deadline_at: o.active_deadline_at,
      is_disputed: !!o.disputed_deadline_at,
      applicability_status: o.applicability_status || "assumed_applicable",
    })),
  }))

  // If Wallboard mode is active, render dedicated SOC display
  if (currentView === "wall") {
    return (
      <div className="h-screen w-screen bg-[#0F1923] overflow-hidden">
        <Suspense fallback={<div className="p-6 text-white text-xs">Loading wallboard...</div>}>
          <WallboardView
            incidents={wallboardIncidents}
            onBackToCommand={navigateToCommand}
          />
        </Suspense>
        {activeAnomalies.length > 0 && (
          <LiveAnomalyNotificationModal
            alerts={activeAnomalies}
            onDismiss={dismissAnomaly}
            onDismissAll={dismissAllAnomalies}
            onAcknowledge={acknowledgeAnomaly}
            onInspectTool={() => openDrawer()}
            onCreateIncident={handleCreateIncidentFromAnomaly}
            soundEnabled={soundEnabled}
            onToggleSound={toggleSound}
          />
        )}
        <LiveTelemetryDrawer 
          onNavigateToAdmin={() => navigateTo("admin")} 
          onCreateIncident={handleCreateIncidentFromAnomaly}
        />
      </div>
    )
  }

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-app text-main font-sans">
      {/* Narrow Left Rail */}
      <aside className="w-16 flex-shrink-0 flex flex-col items-center py-4 border-r border-rule bg-surface">
        <div className="flex items-center justify-center w-10 h-10 rounded-control bg-primary text-primary-fg font-bold tracking-wider text-xs mb-8">
          CQ
        </div>

        <nav className="flex flex-col gap-4 flex-1">
          <button 
            title="Command Center (g i)"
            aria-current={currentView === "command" ? "page" : undefined}
            onClick={() => navigateTo("command")}
            className={currentView === "command" ? "p-2.5 rounded-control bg-app text-primary border border-rule ring-1 ring-primary focus:outline-none" : "p-2.5 rounded-control text-muted hover:text-main hover:bg-app focus:outline-none focus:ring-2 focus:ring-primary"}
          >
            <ShieldAlert className="w-5 h-5" />
          </button>
          <button 
            title="SOC Wallboard Display (/wall - g w)"
            onClick={() => navigateTo("wall")}
            className="p-2.5 rounded-control text-muted hover:text-main hover:bg-app focus:outline-none focus:ring-2 focus:ring-primary"
          >
            <Tv className="w-5 h-5" />
          </button>
          <button 
            title="Activity & Audit Chain (/activity - g a)"
            aria-current={currentView === "activity" ? "page" : undefined}
            onClick={() => navigateTo("activity")}
            className={currentView === "activity" ? "p-2.5 rounded-control bg-app text-primary border border-rule ring-1 ring-primary focus:outline-none" : "p-2.5 rounded-control text-muted hover:text-main hover:bg-app focus:outline-none focus:ring-2 focus:ring-primary"}
          >
            <Activity className="w-5 h-5" />
          </button>
          <button 
            title="Statutory Decision Ledger (/decisions - g d)"
            aria-current={currentView === "decisions" ? "page" : undefined}
            onClick={() => navigateTo("decisions")}
            className={currentView === "decisions" ? "p-2.5 rounded-control bg-app text-primary border border-rule ring-1 ring-primary focus:outline-none" : "p-2.5 rounded-control text-muted hover:text-main hover:bg-app focus:outline-none focus:ring-2 focus:ring-primary"}
          >
            <BookOpenCheck className="w-5 h-5" />
          </button>
          <button 
            title="Regulatory Filing Packets (/filings - g f)"
            aria-current={currentView === "filings" ? "page" : undefined}
            onClick={() => navigateTo("filings")}
            className={currentView === "filings" ? "p-2.5 rounded-control bg-app text-primary border border-rule ring-1 ring-primary focus:outline-none" : "p-2.5 rounded-control text-muted hover:text-main hover:bg-app focus:outline-none focus:ring-2 focus:ring-primary"}
          >
            <FileCheck2 className="w-5 h-5" />
          </button>
          <button 
            title="System Administration & Telemetry (/admin - g m)"
            aria-current={currentView === "admin" ? "page" : undefined}
            onClick={() => navigateTo("admin")}
            className={currentView === "admin" ? "p-2.5 rounded-control bg-app text-primary border border-rule ring-1 ring-primary focus:outline-none" : "p-2.5 rounded-control text-muted hover:text-main hover:bg-app focus:outline-none focus:ring-2 focus:ring-primary"}
          >
            <Sliders className="w-5 h-5" />
          </button>
          <button 
            title="Multi-Agent Verification Lab (/verification - g v)"
            aria-current={currentView === "verification" ? "page" : undefined}
            onClick={() => navigateTo("verification")}
            className={currentView === "verification" ? "p-2.5 rounded-control bg-app text-primary border border-rule ring-1 ring-primary focus:outline-none" : "p-2.5 rounded-control text-muted hover:text-main hover:bg-app focus:outline-none focus:ring-2 focus:ring-primary"}
          >
            <Cpu className="w-5 h-5" />
          </button>
        </nav>

        <div className="flex flex-col gap-3">
          <button
            onClick={toggleTheme}
            title={theme === "light" ? "Switch to Night Desk" : "Switch to Day Ledger"}
            className="p-2 rounded-control text-muted hover:text-main border border-rule bg-app"
            aria-label="Toggle theme"
          >
            {theme === "light" ? <Moon className="w-4 h-4" /> : <Sun className="w-4 h-4" />}
          </button>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col overflow-hidden cyber-grid">
        {/* Top Bar */}
        <header className="h-12 border-b border-rule bg-surface flex items-center justify-between px-4 flex-shrink-0">
          <div className="flex items-center gap-4">
            <span className="font-semibold text-sm tracking-wide">CYBERQ</span>
            <span className="inline-flex items-center px-2 py-0.5 rounded-segment text-xs font-mono font-medium border border-status-due_soon text-status-due_soon bg-app">
              {runtimeEnv}
            </span>
            {runtimeEnv !== "PRODUCTION" && (
              <span className="text-xs text-muted flex items-center gap-1.5 border-l border-rule pl-3">
                <AlertTriangle className="w-3.5 h-3.5 text-status-due_soon" />
                Unverified regulatory data, for demonstration
              </span>
            )}
          </div>

          <div className="flex items-center gap-4 text-xs">
            {/* Command Palette Trigger */}
            <button
              onClick={() => setIsPaletteOpen(true)}
              className="px-2 py-1 rounded-segment border border-rule text-muted hover:text-main hover:bg-app flex items-center gap-1.5 text-[11px]"
            >
              <Command className="w-3 h-3" />
              <span>Palette</span>
              <kbd className="px-1 py-0.2 bg-surface rounded border border-rule text-[9px] font-mono">Ctrl+K</kbd>
            </button>

            {/* Shift Handover Briefing Trigger */}
            <button
              onClick={() => setIsHandoverOpen(true)}
              className="px-2.5 py-1 rounded-segment border border-rule text-muted hover:text-main hover:bg-app flex items-center gap-1.5 text-[11px]"
            >
              <ClipboardCheck className="w-3 h-3" />
              <span>Shift handover</span>
            </button>

            {/* Wallboard shortcut */}
            <button
              onClick={navigateToWallboard}
              className="px-2 py-1 rounded-segment border border-rule text-muted hover:text-main hover:bg-app flex items-center gap-1.5 text-[11px]"
            >
              <Tv className="w-3 h-3" />
              <span>Wallboard</span>
            </button>

            {/* CISO attention queue badge */}
            {userRole === "ciso" && cisoAlertsCount > 0 && (
              <button
                onClick={() => navigateTo("decisions")}
                className="px-2 py-0.5 rounded-segment border border-status-critical/60 bg-status-critical/15 text-status-critical font-medium text-[11px] flex items-center gap-1.5 animate-pulse"
                title="Active CISO governance attention items"
              >
                <ShieldAlert className="w-3.5 h-3.5" />
                <span>CISO alerts: {cisoAlertsCount}</span>
              </button>
            )}

            {/* Auto-Incident Generator Indicator */}
            <button
              onClick={() => setIsAutoGenerating((prev) => !prev)}
              className={`px-2 py-0.5 rounded-segment border font-medium text-[11px] flex items-center gap-1.5 transition-colors cursor-pointer ${
                isAutoGenerating
                  ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-400 hover:bg-emerald-500/20"
                  : "border-rule bg-surface text-muted hover:text-main"
              }`}
              title={
                isAutoGenerating
                  ? `Crisis Generator Active: Synthesizing realistic banking crises every ${autoGenIntervalSec}s (Next in ${nextGenCountdown}s). Click to pause.`
                  : "Crisis Generator Paused. Click to resume."
              }
            >
              <Sparkles className={`w-3.5 h-3.5 ${isAutoGenerating ? "text-emerald-400 animate-spin" : "text-muted"}`} style={{ animationDuration: "5s" }} />
              <span>{isAutoGenerating ? `Auto-Gen: ${nextGenCountdown}s` : "Auto-Gen: Paused"}</span>
            </button>

            {/* Cybersecurity Tool Telemetry Status Indicator & Quick Launcher */}
            <button
              onClick={openDrawer}
              className={`px-2 py-0.5 rounded-segment border font-medium text-[11px] flex items-center gap-1.5 transition-colors cursor-pointer ${
                hasAnomaly
                  ? "border-status-critical/60 bg-status-critical/20 text-status-critical animate-pulse hover:bg-status-critical/30"
                  : "border-status-ok/30 bg-status-ok/10 text-status-ok hover:bg-status-ok/20"
              }`}
              title="Cybersecurity Tool Telemetry Active (12 Connected Tools). Live dynamic random simulation active. Click to open live telemetry monitor & simulation controls."
            >
              <span className={`w-1.5 h-1.5 rounded-full ${hasAnomaly ? "bg-status-critical animate-ping" : "bg-status-ok animate-pulse"}`} />
              <span>
                {hasAnomaly
                  ? `ANOMALY: ${activeAnomalies.length} Active`
                  : `Telemetry: ${totalEps.toLocaleString()} EPS`}
              </span>
            </button>

            {/* Local LLM Online/Fallback Status Badge */}
            <button
              onClick={() => navigateTo("admin")}
              className={`px-2 py-0.5 rounded-segment border font-medium text-[11px] flex items-center gap-1.5 transition-colors ${
                telemetry?.llm_status?.llm_available
                  ? "border-status-ok/40 bg-status-ok/10 text-status-ok hover:bg-status-ok/20"
                  : "border-status-due_soon/40 bg-status-due_soon/10 text-status-due_soon hover:bg-status-due_soon/20"
              }`}
              title={
                telemetry?.llm_status?.llm_available
                  ? `Local LLM Online (${telemetry.llm_status.llm_model || "qwen2.5-coder"}): Air-gapped multi-agent inference active. Click to inspect.`
                  : "Local LLM Unavailable: Rule-Based Fallback Mode Active. Automated responses operating deterministically per air-gap guidelines. Click to inspect."
              }
            >
              {telemetry?.llm_status?.llm_available ? (
                <>
                  <span className="w-1.5 h-1.5 rounded-full bg-status-ok animate-pulse" />
                  <span>LLM: Qwen Coder (Active)</span>
                </>
              ) : (
                <>
                  <AlertTriangle className="w-3 h-3 text-status-due_soon" />
                  <span>LLM: Rule Fallback</span>
                </>
              )}
            </button>

            <div className="flex items-center gap-2 border-r border-rule pr-4 text-muted">
              <span>Next due:</span>
              <span className="font-mono text-main font-semibold">
                {selectedIncident?.obligations.some((o) => o.status === "running")
                  ? "Active timer running"
                  : "None active"}
              </span>
            </div>
            
            <div
              className={`flex items-center gap-2 ${
                calibration.status === "alarm"
                  ? "text-status-critical bg-status-critical/10 px-2 py-0.5 rounded border border-status-critical/30"
                  : "text-muted"
              }`}
              title={`${calibration.detail}\n${calibration.utcHover}`}
            >
              <Clock
                className={`w-3.5 h-3.5 ${
                  calibration.status === "alarm" ? "text-status-critical animate-pulse" : "text-muted"
                }`}
              />
              <span
                className={`font-mono text-[11px] ${
                  calibration.status === "alarm" ? "text-status-critical font-bold" : "text-main"
                }`}
              >
                {calibration.istDisplay} ({calibration.label})
              </span>
            </div>

            {/* Role Switcher (demo only; strictly omitted from production and pilot builds) */}
            {isDemo && (
              <div className="flex items-center gap-2 border-l border-rule pl-4">
                <span className="w-2 h-2 rounded-full bg-status-ok flex-shrink-0" />
                <span className="text-[11px] font-medium text-primary px-2 py-0.5 rounded-segment bg-primary/10 border border-primary/20">
                  Viewing as: {ROLE_LABELS[userRole] || userRole} (demo)
                </span>
                <select
                  aria-label="Viewing as role selection"
                  value={userRole}
                  onChange={(e) => handleRoleChange(e.target.value as UserRole)}
                  className="bg-app border border-rule rounded-segment px-2 py-0.5 text-main font-medium text-[11px] focus:outline-none focus:ring-1 focus:ring-primary cursor-pointer"
                >
                  <option value="analyst">Analyst</option>
                  <option value="compliance_approver">Compliance Approver</option>
                  <option value="ciso">CISO</option>
                  <option value="auditor">Auditor</option>
                  <option value="model_validator">Model Validator</option>
                  <option value="admin">Admin</option>
                </select>
              </div>
            )}
          </div>
        </header>

        {/* View Switcher: Command Center vs Activity vs Decisions vs Filings vs Admin */}
        {currentView === "activity" && (
          <Suspense fallback={<div className="p-6 text-xs text-muted">Loading activity ledger...</div>}>
            <ActivityView 
              userRole={userRole} 
              onBackToCommand={navigateToCommand} 
              isDemo={isDemo}
              csrfToken={csrfToken}
            />
          </Suspense>
        )}

        {currentView === "decisions" && (
          <Suspense fallback={<div className="p-6 text-xs text-muted">Loading decision ledger...</div>}>
            <DecisionsView 
              userRole={userRole}
              currentUserId={currentUserId}
              csrfToken={csrfToken}
              onBackToCommand={navigateToCommand} 
            />
          </Suspense>
        )}

        {currentView === "filings" && (
          <Suspense fallback={<div className="p-6 text-xs text-muted">Loading filing packets...</div>}>
            <FilingsView 
              userRole={userRole}
              onRoleChange={handleRoleChange}
              csrfToken={csrfToken}
              onBackToCommand={navigateToCommand}
              incidents={incidents}
            />
          </Suspense>
        )}

        {currentView === "admin" && (
          <Suspense fallback={<div className="p-6 text-xs text-muted">Loading admin telemetry...</div>}>
            <AdminView
              userRole={userRole}
              theme={theme}
              onToggleTheme={toggleTheme}
              onBackToCommand={navigateToCommand}
            />
          </Suspense>
        )}

        {currentView === "verification" && (
          <Suspense fallback={<div className="p-6 text-xs text-muted">Loading verification lab...</div>}>
            <VerificationView
              userRole={userRole}
              onBackToCommand={navigateToCommand}
              isDemo={isDemo}
            />
          </Suspense>
        )}

        {currentView === "command" && (
          <>
            {/* Obligation Clock Strip */}
            <Suspense fallback={<div className="h-14 bg-surface animate-pulse" />}>
              <ClockStrip obligations={selectedIncident?.obligations || []} />
            </Suspense>

            {/* CISO Executive Overview Card (rendered when active role is CISO) */}
            {userRole === "ciso" && (
              <div className="px-4 pt-3 flex-shrink-0">
                <Suspense fallback={<div className="p-3 text-xs text-muted">Loading executive overview...</div>}>
                  <CisoOverviewCard onNavigateToDecisions={() => navigateTo("decisions")} />
                </Suspense>
              </div>
            )}

            {/* Tab Selector between Standard Detail and 3D Corridor Runway */}
            <div className="h-9 border-b border-rule bg-surface px-4 flex items-center justify-between text-xs flex-shrink-0">
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setActiveTab("detail")}
                  className={`px-3 py-1 rounded-segment text-xs font-medium flex items-center gap-1.5 transition-colors ${
                    activeTab === "detail"
                      ? "bg-app text-primary border border-rule shadow-sm"
                      : "text-muted hover:text-main"
                  }`}
                >
                  <LayoutDashboard className="w-3.5 h-3.5" />
                  <span>Incident triage</span>
                </button>
                <button
                  onClick={() => setActiveTab("corridor")}
                  className={`px-3 py-1 rounded-segment text-xs font-medium flex items-center gap-1.5 transition-colors ${
                    activeTab === "corridor"
                      ? "bg-app text-primary border border-rule shadow-sm"
                      : "text-muted hover:text-main"
                  }`}
                >
                  <Layers className="w-3.5 h-3.5" />
                  <span>3D Depth runway</span>
                </button>
              </div>

              <div className="text-[11px] text-muted">
                {activeTab === "corridor"
                  ? "Statutory deadline corridor (temporal depth perspective)"
                  : "High-contrast triage and statutory clock strip"}
              </div>
            </div>

            {/* Split Pane: Command Center */}
            <main className="flex-1 flex overflow-hidden">
              {/* Left Pane: Incident List */}
              <div className="w-80 border-r border-rule bg-surface flex flex-col flex-shrink-0">
                <div className="p-2.5 border-b border-rule flex flex-col gap-2 bg-surface">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-1.5">
                      <span className="text-xs font-semibold text-main">Incidents ({incidents.length})</span>
                      <button
                        onClick={() => setIsAutoGenerating((prev) => !prev)}
                        onContextMenu={(e) => {
                          e.preventDefault()
                          cycleAutoGenSpeed()
                        }}
                        className={`px-1.5 py-0.5 rounded text-[10px] font-mono flex items-center gap-1 border transition-all cursor-pointer ${
                          isAutoGenerating
                            ? "bg-emerald-500/15 text-emerald-400 border-emerald-500/40 hover:bg-emerald-500/25"
                            : "bg-app text-muted border-rule hover:text-main"
                        }`}
                        title={
                          isAutoGenerating
                            ? `Auto-generator active (${autoGenIntervalSec}s cycle). Left-click to pause/resume. Right-click to cycle speed (20s/35s/60s).`
                            : "Auto-generator paused. Click to resume."
                        }
                      >
                        <span className={`w-1.5 h-1.5 rounded-full ${isAutoGenerating ? "bg-emerald-400 animate-ping" : "bg-muted"}`} />
                        <span>{isAutoGenerating ? `${nextGenCountdown}s` : "Paused"}</span>
                      </button>
                      <button
                        onClick={cycleAutoGenSpeed}
                        className="text-[9px] text-muted hover:text-emerald-400 font-mono px-1 py-0.5 rounded border border-rule/50 hover:border-emerald-500/30 transition-colors cursor-pointer"
                        title="Change auto-gen interval speed (20s -> 35s -> 60s)"
                      >
                        {autoGenIntervalSec}s
                      </button>
                    </div>

                    <div className="flex items-center gap-1">
                      <button
                        onClick={handleGenerateRandomIncident}
                        className="px-2 py-0.5 text-[11px] bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 rounded hover:bg-emerald-500/30 flex items-center gap-1 font-medium transition-all active:scale-95 cursor-pointer shadow-sm"
                        title="Instantly generate a random commercial banking cyber crisis incident"
                      >
                        <Sparkles className="w-3 h-3 text-emerald-400" />
                        <span>Random</span>
                      </button>
                      <button
                        onClick={openNewIncident}
                        className="px-2 py-0.5 text-[11px] bg-primary text-primary-fg rounded hover:bg-primary-hover flex items-center gap-1 font-medium focus:outline-none cursor-pointer"
                        title="Manually create a new custom incident"
                      >
                        <Plus className="w-3 h-3" />
                        <span>New</span>
                      </button>
                    </div>
                  </div>
                </div>

                <div className="flex-1 overflow-y-auto divide-y divide-rule">
                  {incidents.map((inc) => {
                    const displayTitle = userRole === "admin" 
                      ? `${inc.incident_number} (Narrative masked - Admin)` 
                      : inc.title
                    const displaySummary = userRole === "admin" 
                      ? "[REDACTED_FOR_ADMIN: Admin is config-only]" 
                      : userRole === "auditor" 
                      ? "[REDACTED_FOR_AUDIT]" 
                      : inc.summary

                    return (
                      <div
                        key={inc.id}
                        onClick={() => setSelectedIncidentId(inc.id)}
                        className={`p-3 cursor-pointer text-xs transition-colors ${
                          inc.id === selectedIncidentId ? "bg-app border-l-2 border-primary" : "hover:bg-app"
                        }`}
                      >
                        <div className="flex items-center justify-between mb-1">
                          <span className="font-mono font-semibold text-main text-[11px]">
                            {inc.incident_number}
                          </span>
                          <div className="flex items-center gap-1">
                            {inc.is_major && (
                              <span className="px-1 py-0.2 rounded-segment border border-status-critical text-status-critical text-[9px] font-bold">
                                MAJOR
                              </span>
                            )}
                            <span className="px-1.5 py-0.5 rounded-segment border border-rule text-muted text-[10px] capitalize">
                              {inc.status}
                            </span>
                          </div>
                        </div>
                        <div className="font-medium text-main truncate">{displayTitle}</div>
                        <div className="text-muted text-[11px] truncate mt-0.5">{displaySummary}</div>
                      </div>
                    )
                  })}
                </div>
              </div>

              {/* Right Pane: Incident Detail or 3D Corridor */}
              {selectedIncident ? (
                activeTab === "corridor" ? (
                  <div className="flex-1 overflow-hidden p-4 bg-app">
                    <Suspense fallback={<div className="p-4 text-xs text-muted">Loading Corridor...</div>}>
                      <CorridorView
                        obligations={selectedIncident.obligations}
                        isDemo={true}
                        theme={theme}
                      />
                    </Suspense>
                  </div>
                ) : (
                  <Suspense fallback={<div className="p-6 text-xs text-muted">Loading incident details...</div>}>
                    <IncidentDetail
                      incident={selectedIncident}
                      onTransition={handleTransition}
                      onOpenAssertTrigger={() => setIsAssertModalOpen(true)}
                      isAuditor={userRole === "auditor"}
                      userRole={userRole}
                      currentUserId={currentUserId}
                      csrfToken={csrfToken}
                      onRoleChange={handleRoleChange}
                      onSeverityChange={handleSeverityChange}
                      onDeclareMajor={handleDeclareMajor}
                      onApproveClosure={handleApproveClosure}
                      onTriggerDpdpAware={handleTriggerDpdpAware}
                    />
                  </Suspense>
                )
              ) : (
                <div className="flex-1 flex items-center justify-center text-muted text-xs">
                  No incident selected.
                </div>
              )}
            </main>
          </>
        )}
      </div>

      <Suspense fallback={null}>
        {isNewModalOpen && (
          <NewIncidentModal
            isOpen={isNewModalOpen}
            onClose={() => {
              setIsNewModalOpen(false)
              setNewIncidentInitialData(null)
            }}
            onSubmit={async (title, summary, severity, overridePii, overrideReason) => {
              await handleCreateIncident(title, summary, severity, overridePii, overrideReason)
              setIsNewModalOpen(false)
              setNewIncidentInitialData(null)
              setActiveTab("detail")
            }}
            initialData={newIncidentInitialData}
            csrfToken={csrfToken}
          />
        )}

        {isAssertModalOpen && (
          <AssertTriggerModal
            isOpen={isAssertModalOpen}
            onClose={() => setIsAssertModalOpen(false)}
            onSubmit={handleAssertTrigger}
          />
        )}

        {isPaletteOpen && (
          <CommandPalette
            isOpen={isPaletteOpen}
            onClose={() => setIsPaletteOpen(false)}
            onNavigateIncidents={() => {
              navigateTo("command")
              setActiveTab("detail")
            }}
            onNavigateWallboard={navigateToWallboard}
            onNavigateActivity={() => navigateTo("activity")}
            onNavigateDecisions={() => navigateTo("decisions")}
            onNavigateFilings={() => navigateTo("filings")}
            onNavigateAdmin={() => navigateTo("admin")}
            onNavigateVerification={() => navigateTo("verification")}
            onOpenNewIncident={openNewIncident}
            onOpenAssertTrigger={() => setIsAssertModalOpen(true)}
            onOpenHandover={() => setIsHandoverOpen(true)}
            onOpenTelemetry={openDrawer}
            onSimulateAnomaly={() => triggerAnomaly()}
            userRole={userRole}
          />
        )}

        {isHandoverOpen && (
          <ShiftHandoverModal
            isOpen={isHandoverOpen}
            onClose={() => setIsHandoverOpen(false)}
            incidents={incidents}
            userRole={userRole}
          />
        )}

        {/* Global Live Anomaly Notification Modal */}
        {activeAnomalies.length > 0 && (
          <LiveAnomalyNotificationModal
            alerts={activeAnomalies}
            onDismiss={dismissAnomaly}
            onDismissAll={dismissAllAnomalies}
            onAcknowledge={acknowledgeAnomaly}
            onInspectTool={() => openDrawer()}
            onCreateIncident={handleCreateIncidentFromAnomaly}
            soundEnabled={soundEnabled}
            onToggleSound={toggleSound}
          />
        )}

        {/* Interactive Live Telemetry Drawer */}
        <LiveTelemetryDrawer 
          onNavigateToAdmin={() => navigateTo("admin")} 
          onCreateIncident={handleCreateIncidentFromAnomaly}
        />

        {/* Real-time Crisis Auto-Generation Toast Card */}
        {autoGenToast && (
          <div
            onClick={() => {
              setSelectedIncidentId(autoGenToast.id)
              navigateTo("command")
            }}
            className="fixed bottom-5 right-5 z-50 max-w-sm bg-[#0A0D14]/95 border border-[#00FF66]/60 rounded-lg p-3 shadow-2xl backdrop-blur-md cursor-pointer animate-in slide-in-from-bottom duration-300 hover:border-[#00FF66] transition-all"
          >
            <div className="flex items-start gap-2.5">
              <div className="p-1.5 rounded-full bg-[#00FF66]/20 text-[#00FF66] mt-0.5">
                <Sparkles className="w-4 h-4 animate-pulse" />
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-[10px] text-[#00FF66] uppercase font-bold tracking-wider">
                    New Incident Auto-Generated
                  </span>
                  <span className={`px-1.5 py-0.2 rounded text-[9px] uppercase font-mono font-bold ${
                    autoGenToast.severity === "critical"
                      ? "bg-status-critical/20 text-status-critical"
                      : "bg-status-due_soon/20 text-status-due_soon"
                  }`}>
                    {autoGenToast.severity}
                  </span>
                </div>
                <div className="font-semibold text-white text-xs truncate mt-0.5 font-mono">
                  {autoGenToast.incidentNumber}
                </div>
                <div className="text-gray-300 text-[11px] line-clamp-2 mt-0.5">
                  {autoGenToast.title}
                </div>
                <div className="text-[10px] text-muted font-mono mt-1 flex items-center justify-between">
                  <span>Statutory clocks initiated</span>
                  <span className="text-[#00FF66] hover:underline">View Incident &rarr;</span>
                </div>
              </div>
            </div>
          </div>
        )}
      </Suspense>
      <DemoOverlay />
    </div>
  )
}

export default function App() {
  return (
    <TelemetryProvider>
      <AppContent />
    </TelemetryProvider>
  )
}
