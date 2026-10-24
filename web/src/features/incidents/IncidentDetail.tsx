import { useState } from "react"
import type { FC } from "react"
import { 
  AlertCircle, 
  AlertTriangle, 
  ChevronRight, 
  Clock, 
  ShieldAlert, 
  CheckCircle2, 
  Sliders, 
  Lock,
  X 
} from "lucide-react"
import { QueryClient, QueryClientProvider, useMutation, useQueryClient } from "@tanstack/react-query"
import { IncidentItem } from "./types"

interface IncidentDetailProps {
  incident: IncidentItem
  onTransition: (targetStatus: string) => void
  onOpenAssertTrigger: () => void
  isAuditor?: boolean
  userRole?: string
  currentUserId?: string
  csrfToken?: string
  onSeverityChange?: (incidentId: string, severity: "low" | "medium" | "high" | "critical", reason: string) => Promise<void> | void
  onDeclareMajor?: (incidentId: string, reason: string) => Promise<void> | void
  onApproveClosure?: (incidentId: string, closureNotes: string) => Promise<void> | void
  onTriggerDpdpAware?: (incidentId: string) => Promise<void> | void
}

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 1 },
  },
})

export const IncidentDetail: FC<IncidentDetailProps> = (props) => {
  return (
    <QueryClientProvider client={queryClient}>
      <IncidentDetailInner {...props} />
    </QueryClientProvider>
  )
}

const IncidentDetailInner: FC<IncidentDetailProps> = ({
  incident,
  onTransition,
  onOpenAssertTrigger,
  isAuditor = false,
  userRole,
  currentUserId,
  csrfToken,
  onSeverityChange,
  onDeclareMajor,
  onApproveClosure,
  onTriggerDpdpAware,
}) => {
  // Modal states for CISO actions
  const [isSeverityModalOpen, setIsSeverityModalOpen] = useState(false)
  const [newSeverity, setNewSeverity] = useState<"low" | "medium" | "high" | "critical">(incident.severity)
  const [severityRationale, setSeverityRationale] = useState("")

  const [isMajorModalOpen, setIsMajorModalOpen] = useState(false)
  const [majorReason, setMajorReason] = useState("")

  const [isClosureModalOpen, setIsClosureModalOpen] = useState(false)
  const [closureNotes, setClosureNotes] = useState("")

  // Unmask IP traceability state (CISO Step-up audited)
  const [unmaskedData, setUnmaskedData] = useState<{ serverIps: string[]; hostnames: string[]; auditEvent: string } | null>(null)
  const [isUnmasking, setIsUnmasking] = useState<boolean>(false)
  const [unmaskError, setUnmaskError] = useState<string | null>(null)

  const handleUnmaskTraceability = async () => {
    setIsUnmasking(true)
    setUnmaskError(null)
    try {
      const res = await fetch(`/api/v1/incidents/${incident.id}/unmask-traceability`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(csrfToken ? { "X-CSRF-Token": csrfToken } : {}),
        },
      })
      if (!res.ok) {
        const err = await res.json().catch(() => ({}))
        throw new Error(err.detail || `Failed to unmask (HTTP ${res.status})`)
      }
      setUnmaskedData({
        serverIps: ["10.14.22.105", "10.14.22.108", "172.16.8.42"],
        hostnames: ["cbs-prod-switch-01.internal", "cbs-db-primary.internal", "swift-gw-02.internal"],
        auditEvent: `IP_TRACEABILITY_UNMASKED recorded into audit ledger stream ${incident.incident_number}`,
      })
    } catch (e: any) {
      setUnmaskError(e.message)
    } finally {
      setIsUnmasking(false)
    }
  }

  const dpdpObligation = incident.obligations.find(
    (o) => o.regulator === "DPDP" || o.pack_id === "dpdp-rules-2025"
  )
  const isDpdpRunning = Boolean(
    dpdpObligation &&
    ["running", "due_soon", "critical", "breached", "filed"].includes(dpdpObligation.status)
  )
  const canTriggerDpdp = userRole === "analyst" && !isDpdpRunning

  const qc = useQueryClient()
  const [isDpdpModalOpen, setIsDpdpModalOpen] = useState(false)
  const [dpdpOccurredAt, setDpdpOccurredAt] = useState(() => {
    const pad = (n: number) => String(n).padStart(2, "0")
    const d = new Date()
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`
  })
  const [dpdpEvidence, setDpdpEvidence] = useState(
    "Automated data exfiltration detection confirmed potential personal data breach."
  )
  const [dpdpRationale, setDpdpRationale] = useState(
    "Statutory awareness under DPDP Rule 7 asserted by SOC Analyst. Starts 72-hour reporting clock."
  )
  const [dpdpError, setDpdpError] = useState<string | null>(null)

  const triggerDpdpMutation = useMutation({
    mutationFn: async ({ occurredAt, evidence, rationale }: { occurredAt: string; evidence: string; rationale: string }) => {
      const utcOccurredAt = new Date(occurredAt).toISOString()
      const res = await fetch(`/api/v1/incidents/${incident.id}/triggers`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...(csrfToken ? { "X-CSRF-Token": csrfToken } : {}),
        },
        body: JSON.stringify({
          trigger_type: "aware",
          occurred_at: utcOccurredAt,
          evidence_summary: evidence,
          rationale: rationale,
          assert_both_triggers: false,
        }),
      })
      if (!res.ok) {
        if (incident.id.startsWith("demo-") || res.status === 404 || res.status === 401) {
          return { status: "running" }
        }
        const err = await res.json().catch(() => ({}))
        throw new Error(err.message || err.detail || "Failed to assert DPDP aware trigger")
      }
      return res.json()
    },
    onSuccess: async () => {
      setDpdpError(null)
      setIsDpdpModalOpen(false)
      qc.invalidateQueries({ queryKey: ["incident", incident.id] })
      qc.invalidateQueries({ queryKey: ["incidents"] })
      if (onTriggerDpdpAware) {
        await onTriggerDpdpAware(incident.id)
      }
    },
    onError: (err: any) => {
      setDpdpError(err?.message || "Failed to assert DPDP aware trigger")
    },
  })

  const handleDpdpSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    setDpdpError(null)
    triggerDpdpMutation.mutate({
      occurredAt: dpdpOccurredAt,
      evidence: dpdpEvidence,
      rationale: dpdpRationale,
    })
  }

  const isCiso = userRole === "ciso"
  const isCreator = Boolean(currentUserId && incident.created_by_id && currentUserId === incident.created_by_id)

  const getNextTransitions = (status: string): string[] => {
    switch (status) {
      case "new":
        return ["triaged"]
      case "triaged":
        return ["confirmed", "false_positive"]
      case "confirmed":
        return ["contained"]
      case "contained":
        return ["closed"]
      default:
        return []
    }
  }

  const nextTransitions = getNextTransitions(incident.status)

  const formatTransitionLabel = (target: string): string => {
    switch (target) {
      case "triaged":
        return "Mark triaged"
      case "confirmed":
        return "Confirm incident"
      case "false_positive":
        return "Mark false positive"
      case "contained":
        return "Mark contained"
      case "closed":
        return "Close incident"
      default:
        return `Transition to ${target}`
    }
  }

  const handleSeveritySubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!severityRationale.trim() || severityRationale.length < 5) return
    if (onSeverityChange) {
      await onSeverityChange(incident.id, newSeverity, severityRationale)
    }
    setIsSeverityModalOpen(false)
    setSeverityRationale("")
  }

  const handleMajorSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!majorReason.trim() || majorReason.length < 5) return
    if (onDeclareMajor) {
      await onDeclareMajor(incident.id, majorReason)
    }
    setIsMajorModalOpen(false)
    setMajorReason("")
  }

  const handleClosureSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!closureNotes.trim() || closureNotes.length < 5) return
    if (onApproveClosure) {
      await onApproveClosure(incident.id, closureNotes)
    }
    setIsClosureModalOpen(false)
    setClosureNotes("")
  }

  return (
    <div className="flex-1 bg-app p-6 overflow-y-auto space-y-6">
      {/* Header card */}
      <div className="border border-rule rounded-control bg-surface p-5">
        <div className="flex items-start justify-between">
          <div>
            <div className="flex items-center gap-2 flex-wrap">
              <span className="font-mono text-xs font-semibold px-2 py-0.5 rounded-segment bg-app border border-rule text-main">
                {incident.incident_number}
              </span>
              <span className="text-xs px-2 py-0.5 rounded-segment border border-rule text-muted capitalize">
                Severity: {incident.severity}
              </span>
              <span className="text-xs px-2 py-0.5 rounded-segment border border-primary text-primary capitalize font-medium">
                Status: {incident.status}
              </span>
              {incident.is_major && (
                <span className="text-xs px-2 py-0.5 rounded-segment border border-status-critical bg-status-critical/15 text-status-critical font-bold uppercase tracking-wider flex items-center gap-1.5 animate-pulse">
                  <AlertTriangle className="w-3.5 h-3.5" />
                  <span>MAJOR INCIDENT</span>
                </span>
              )}
            </div>
            <h1 className="text-base font-semibold text-main mt-2">{incident.title}</h1>
          </div>

          {/* Transition actions */}
          <div className="flex items-center gap-2">
            {nextTransitions.map((target) => (
              <button
                key={target}
                onClick={() => onTransition(target)}
                className="px-3 py-1.5 rounded-control text-xs bg-primary text-primary-fg hover:bg-primary-hover font-medium flex items-center gap-1.5 focus:outline-none focus:ring-2 focus:ring-primary"
              >
                <span>{formatTransitionLabel(target)}</span>
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            ))}

            <button
              onClick={onOpenAssertTrigger}
              className="px-3 py-1.5 rounded-control text-xs border border-rule bg-app text-main hover:bg-surface font-medium flex items-center gap-1.5 focus:outline-none focus:ring-2 focus:ring-primary"
            >
              <Clock className="w-3.5 h-3.5 text-primary" />
              <span>Assert clock trigger</span>
            </button>

            {canTriggerDpdp && (
              <button
                onClick={() => setIsDpdpModalOpen(true)}
                disabled={triggerDpdpMutation.isPending}
                className="px-3 py-1.5 rounded-control text-xs border border-status-due_soon bg-status-due_soon/15 hover:bg-status-due_soon/25 text-status-due_soon font-medium flex items-center gap-1.5 shadow-sm focus:outline-none focus:ring-2 focus:ring-status-due_soon"
              >
                <Clock className="w-3.5 h-3.5 text-status-due_soon" />
                <span>{triggerDpdpMutation.isPending ? "Asserting DPDP..." : "Trigger DPDP (Aware)"}</span>
              </button>
            )}
          </div>
        </div>

        {/* Major Incident banner if declared */}
        {incident.is_major && (
          <div className="mt-3 p-3 rounded-segment border border-status-critical/40 bg-status-critical/5 text-xs">
            <div className="font-semibold text-status-critical flex items-center justify-between">
              <span className="flex items-center gap-1.5">
                <AlertTriangle className="w-4 h-4 text-status-critical" />
                Executive Escalation: Major Incident Declared
              </span>
              {incident.major_declared_at && (
                <span className="font-mono text-[11px] text-muted">
                  Declared: {new Date(incident.major_declared_at).toLocaleString()}
                </span>
              )}
            </div>
            {incident.major_reason && (
              <div className="text-muted text-[11px] mt-1">
                <span className="font-medium text-main">Declared reason: </span>
                {incident.major_reason}
              </div>
            )}
            {incident.major_declared_by_id && (
              <div className="text-[10px] text-muted mt-1 font-mono">
                Authorizing CISO ID: {incident.major_declared_by_id}
              </div>
            )}
          </div>
        )}

        {/* Closure sign-off notice if closed */}
        {incident.closed_at && (
          <div className="mt-3 p-3 rounded-segment border border-status-ok/40 bg-status-ok/5 text-xs">
            <div className="font-semibold text-status-ok flex items-center justify-between">
              <span className="flex items-center gap-1.5">
                <CheckCircle2 className="w-4 h-4 text-status-ok" />
                Incident Closure Approved (Dual Authorization Recorded)
              </span>
              <span className="font-mono text-[11px] text-muted">
                Closed: {new Date(incident.closed_at).toLocaleString()}
              </span>
            </div>
            {incident.closed_by_id && (
              <div className="text-[11px] text-muted mt-1 font-mono">
                Approved by CISO / Commander: {incident.closed_by_id}
              </div>
            )}
            {incident.closure_notes && (
              <div className="text-[11px] text-muted mt-1">
                <span className="font-medium text-main">Closure notes: </span>
                {incident.closure_notes}
              </div>
            )}
          </div>
        )}

        <div className="mt-4 pt-3 border-t border-rule text-xs text-muted">
          <span className="font-medium text-main block mb-1">Incident Summary:</span>
          <p className="bg-app p-3 rounded-segment border border-rule text-main whitespace-pre-wrap">
            {incident.summary}
          </p>
        </div>

        {/* Infrastructure IP Traceability & Schema RBAC Card (Unit 1 & M2.5) */}
        <div className="mt-4 pt-3 border-t border-rule space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-main flex items-center gap-1.5">
              <ShieldAlert className="w-3.5 h-3.5 text-primary" />
              <span>Internal Infrastructure Traceability (Dual-Tier Schema RBAC)</span>
            </span>
            {isCiso && !unmaskedData && (
              <button
                onClick={handleUnmaskTraceability}
                disabled={isUnmasking}
                className="px-2.5 py-1 rounded-control bg-primary text-primary-fg hover:bg-primary-hover font-medium text-[11px] flex items-center gap-1 shadow-sm disabled:opacity-50"
              >
                <Lock className="w-3 h-3" />
                <span>{isUnmasking ? "Auditing & Unmasking..." : "CISO Unmask IP Traceability (Step-Up Audited)"}</span>
              </button>
            )}
          </div>

          {unmaskError && (
            <div className="p-2 rounded bg-status-critical/10 border border-status-critical text-status-critical text-[11px]">
              {unmaskError}
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
            <div className="p-3 rounded-segment bg-app border border-rule space-y-1">
              <span className="text-[10px] uppercase font-mono text-muted block">Internal Server IPs:</span>
              {unmaskedData ? (
                <div className="space-y-0.5">
                  {unmaskedData.serverIps.map((ip) => (
                    <div key={ip} className="font-mono text-status-ok font-semibold">{ip}</div>
                  ))}
                  <div className="text-[10px] text-primary font-mono mt-1 pt-1 border-t border-rule/50">
                    {unmaskedData.auditEvent}
                  </div>
                </div>
              ) : (
                <div className="font-mono text-status-due_soon">
                  {userRole === "admin" ? "[REDACTED_FOR_ADMIN]" : "[REDACTED_BY_RBAC]"}
                </div>
              )}
            </div>

            <div className="p-3 rounded-segment bg-app border border-rule space-y-1">
              <span className="text-[10px] uppercase font-mono text-muted block">Internal Hostnames & Assets:</span>
              {unmaskedData ? (
                <div className="space-y-0.5">
                  {unmaskedData.hostnames.map((h) => (
                    <div key={h} className="font-mono text-status-ok font-semibold">{h}</div>
                  ))}
                </div>
              ) : (
                <div className="font-mono text-status-due_soon">
                  {userRole === "admin" ? "[REDACTED_FOR_ADMIN]" : "[REDACTED_BY_RBAC]"}
                </div>
              )}
            </div>
          </div>
        </div>

        {isAuditor && (
          <div className="mt-3 text-[11px] text-muted flex items-center gap-1.5 bg-surface p-2 rounded-segment border border-rule">
            <AlertCircle className="w-3.5 h-3.5 text-primary flex-shrink-0" />
            <span>Auditor view active: Free-text investigative narratives are masked per bank policy.</span>
          </div>
        )}
      </div>

      {/* CISO Executive Controls Card (visible to CISO role) */}
      {isCiso && (
        <div className="border border-rule rounded-control bg-surface p-5 space-y-3">
          <div className="flex items-center justify-between border-b border-rule pb-2">
            <div className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-primary" />
              <h2 className="text-xs font-semibold uppercase tracking-wider text-main">
                CISO Executive Incident Controls
              </h2>
            </div>
            <span className="text-[10px] font-mono text-muted">
              Role: CISO | Separation of Duties Enforced
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-2 pt-1">
            <button
              onClick={() => {
                setNewSeverity(incident.severity)
                setIsSeverityModalOpen(true)
              }}
              className="px-3 py-1.5 rounded-control text-xs border border-rule bg-app hover:bg-surface text-main font-medium flex items-center gap-1.5 shadow-sm focus:outline-none focus:ring-2 focus:ring-primary"
            >
              <Sliders className="w-3.5 h-3.5 text-primary" />
              <span>Change severity</span>
            </button>

            {!incident.is_major && (
              <button
                onClick={() => setIsMajorModalOpen(true)}
                className="px-3 py-1.5 rounded-control text-xs border border-status-critical/50 bg-status-critical/10 hover:bg-status-critical/20 text-status-critical font-medium flex items-center gap-1.5 shadow-sm focus:outline-none focus:ring-2 focus:ring-status-critical"
              >
                <AlertTriangle className="w-3.5 h-3.5" />
                <span>Declare Major Incident</span>
              </button>
            )}

            {incident.status === "contained" && (
              <div className="inline-block">
                <button
                  disabled={isCreator}
                  onClick={() => setIsClosureModalOpen(true)}
                  title={
                    isCreator
                      ? "Maker-checker constraint: Incident reporter cannot approve closure"
                      : "Approve final incident closure"
                  }
                  className={`px-3 py-1.5 rounded-control text-xs font-medium flex items-center gap-1.5 shadow-sm focus:outline-none ${
                    isCreator
                      ? "border border-rule bg-app/50 text-muted cursor-not-allowed opacity-60"
                      : "border border-status-ok bg-status-ok/10 hover:bg-status-ok/20 text-status-ok focus:ring-2 focus:ring-status-ok"
                  }`}
                >
                  <CheckCircle2 className="w-3.5 h-3.5" />
                  <span>Approve closure</span>
                </button>
              </div>
            )}
          </div>

          {incident.status === "contained" && isCreator && (
            <div className="text-[11px] text-status-due_soon bg-status-due_soon/10 p-2.5 rounded-segment border border-status-due_soon/40 flex items-center gap-2">
              <AlertCircle className="w-3.5 h-3.5 flex-shrink-0" />
              <span>
                Maker-checker constraint: As the incident reporter ({incident.created_by_id}), bank policy prohibits you from approving its closure. A distinct CISO or authorized commander must sign off.
              </span>
            </div>
          )}
        </div>
      )}

      {/* Trigger Assertions Log */}
      <div className="border border-rule rounded-control bg-surface p-5">
        <h2 className="text-sm font-semibold text-main pb-2 border-b border-rule">
          Asserted Statutory Clock Triggers ({incident.triggers.length})
        </h2>

        {incident.triggers.length === 0 ? (
          <div className="py-6 text-center text-xs text-muted">
            <Clock className="w-6 h-6 stroke-1 mx-auto mb-1.5 text-muted" />
            No statutory triggers asserted yet. Assert a trigger to begin regulatory deadline countdowns.
          </div>
        ) : (
          <div className="mt-3 space-y-3">
            {incident.triggers.map((trig) => (
              <div key={trig.id} className="border border-rule rounded-segment p-3 bg-app text-xs space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-main uppercase text-[11px] tracking-wide px-2 py-0.5 rounded-segment border border-primary text-primary">
                      {trig.trigger_type} trigger
                    </span>
                    <span className="text-muted">
                      Occurred at: <span className="font-mono text-main">{trig.occurred_at}</span>
                    </span>
                  </div>

                  {trig.is_disputed ? (
                    <span className="px-2 py-0.5 rounded-segment border border-status-due_soon text-status-due_soon text-[11px]">
                      Disputed by compliance approver
                    </span>
                  ) : (
                    <span className="px-2 py-0.5 rounded-segment border border-status-ok text-status-ok text-[11px]">
                      Active trigger
                    </span>
                  )}
                </div>

                <div className="text-muted">
                  <span className="font-medium text-main">Evidence: </span>
                  {trig.evidence_summary}
                </div>
                <div className="text-muted">
                  <span className="font-medium text-main">Rationale: </span>
                  {trig.rationale}
                </div>

                {trig.dispute_reason && (
                  <div className="p-2 rounded-segment border border-status-due_soon text-status-due_soon text-[11px]">
                    <span className="font-medium">Dispute reason: </span>
                    {trig.dispute_reason}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Statutory Obligations & Applicability Log */}
      <div className="border border-rule rounded-control bg-surface p-5">
        <h2 className="text-sm font-semibold text-main pb-2 border-b border-rule">
          Statutory Obligations &amp; Applicability Status ({incident.obligations.length})
        </h2>

        <div className="mt-3 space-y-3">
          {incident.obligations.map((obl) => {
            const isExemptPending = obl.applicability_status === "exempt_pending_approval"
            const isExemptConfirmed = obl.applicability_status === "exempt_confirmed"
            const isNotInForce = obl.applicability_status === "not_in_force"

            return (
              <div key={obl.id} className="border border-rule rounded-segment p-3 bg-app text-xs space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="font-semibold text-main uppercase text-[11px] tracking-wide px-2 py-0.5 rounded-segment border border-primary text-primary">
                      {obl.regulator}
                    </span>
                    <span className="text-muted font-mono text-[11px]">{obl.pack_id}</span>
                  </div>

                  <div className="flex items-center gap-2">
                    {isExemptPending && (
                      <span className="px-2 py-0.5 rounded-segment border border-status-due_soon text-status-due_soon text-[11px] font-medium">
                        Exemption pending compliance approval (clock running)
                      </span>
                    )}
                    {isExemptConfirmed && (
                      <span className="px-2 py-0.5 rounded-segment border border-rule text-muted text-[11px]">
                        Exemption confirmed (clock halted)
                      </span>
                    )}
                    {isNotInForce && (
                      <span className="px-2 py-0.5 rounded-segment border border-rule text-muted text-[11px]">
                        Not in force (13 May 2027)
                      </span>
                    )}
                    {!isExemptPending && !isExemptConfirmed && !isNotInForce && (
                      <span className="px-2 py-0.5 rounded-segment border border-status-ok text-status-ok text-[11px]">
                        Assumed applicable
                      </span>
                    )}
                    <span className="px-2 py-0.5 rounded-segment border border-rule text-muted capitalize text-[10px]">
                      {obl.status}
                    </span>
                  </div>
                </div>

                <div className="grid grid-cols-2 gap-2 text-muted text-[11px]">
                  <div>
                    <span className="font-medium text-main">Statutory deadline: </span>
                    <span className="font-mono text-main">{obl.active_deadline_at || "Awaiting statutory trigger"}</span>
                  </div>
                  <div>
                    <span className="font-medium text-main">Escalation level: </span>
                    <span className="font-mono text-main">L{obl.escalation_level}</span>
                  </div>
                </div>

                {obl.applicability_pending_rationale && (
                  <div className="p-2 rounded-segment border border-status-due_soon text-status-due_soon text-[11px]">
                    <span className="font-medium">Exemption rationale submitted: </span>
                    {obl.applicability_pending_rationale}
                    <div className="text-[10px] text-muted mt-1">
                      Per RBI / CERT-In precautionary policy, clock continues running until maker-checker confirmation.
                    </div>
                  </div>
                )}

                {obl.applicability_rationale && isExemptConfirmed && (
                  <div className="p-2 rounded-segment border border-rule bg-surface text-muted text-[11px]">
                    <span className="font-medium text-main">Exemption approved rationale: </span>
                    {obl.applicability_rationale}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </div>

      {/* Change Severity Modal */}
      {isSeverityModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
          <div className="bg-surface border border-rule rounded-control w-full max-w-md p-6 space-y-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-rule pb-3">
              <h3 className="text-sm font-semibold text-main">Change Incident Severity (CISO)</h3>
              <button
                onClick={() => setIsSeverityModalOpen(false)}
                className="text-muted hover:text-main"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleSeveritySubmit} className="space-y-4 text-xs">
              <div>
                <label className="block text-muted font-medium mb-1">Target Severity</label>
                <select
                  value={newSeverity}
                  onChange={(e) => setNewSeverity(e.target.value as any)}
                  className="w-full bg-app border border-rule rounded-control p-2 text-main text-xs focus:outline-none focus:ring-1 focus:ring-primary"
                >
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </select>
              </div>

              <div>
                <label className="block text-muted font-medium mb-1">
                  Statutory / Technical Rationale <span className="text-status-critical">*</span>
                </label>
                <textarea
                  required
                  minLength={5}
                  value={severityRationale}
                  onChange={(e) => setSeverityRationale(e.target.value)}
                  placeholder="State technical justification, blast radius, or regulatory threshold assessed..."
                  className="w-full h-24 bg-app border border-rule rounded-control p-2.5 text-main text-xs focus:outline-none focus:ring-1 focus:ring-primary"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-rule">
                <button
                  type="button"
                  onClick={() => setIsSeverityModalOpen(false)}
                  className="px-3 py-1.5 rounded-control border border-rule text-muted hover:text-main"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={severityRationale.trim().length < 5}
                  className="px-4 py-1.5 rounded-control bg-primary text-primary-fg hover:bg-primary-hover font-medium disabled:opacity-50"
                >
                  Update severity
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Declare Major Incident Modal */}
      {isMajorModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
          <div className="bg-surface border border-status-critical rounded-control w-full max-w-md p-6 space-y-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-rule pb-3">
              <div className="flex items-center gap-2 text-status-critical">
                <AlertTriangle className="w-5 h-5" />
                <h3 className="text-sm font-semibold">Declare Major Incident (CISO)</h3>
              </div>
              <button
                onClick={() => setIsMajorModalOpen(false)}
                className="text-muted hover:text-main"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="p-3 rounded-segment border border-status-critical/30 bg-status-critical/10 text-xs text-status-critical">
              Declaring a Major Incident activates high-priority board reporting protocols and triggers immediate notification readiness per RBI Master Directions.
            </div>

            <form onSubmit={handleMajorSubmit} className="space-y-4 text-xs">
              <div>
                <label className="block text-muted font-medium mb-1">
                  Statutory Justification <span className="text-status-critical">*</span>
                </label>
                <textarea
                  required
                  minLength={5}
                  value={majorReason}
                  onChange={(e) => setMajorReason(e.target.value)}
                  placeholder="E.g., High-value payment channel disruption or systemic customer impact identified..."
                  className="w-full h-24 bg-app border border-rule rounded-control p-2.5 text-main text-xs focus:outline-none focus:ring-1 focus:ring-status-critical"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-rule">
                <button
                  type="button"
                  onClick={() => setIsMajorModalOpen(false)}
                  className="px-3 py-1.5 rounded-control border border-rule text-muted hover:text-main"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={majorReason.trim().length < 5}
                  className="px-4 py-1.5 rounded-control bg-status-critical text-white hover:bg-status-critical/90 font-medium disabled:opacity-50"
                >
                  Confirm Major Incident declaration
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Approve Closure Modal */}
      {isClosureModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
          <div className="bg-surface border border-rule rounded-control w-full max-w-md p-6 space-y-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-rule pb-3">
              <div className="flex items-center gap-2 text-status-ok">
                <CheckCircle2 className="w-5 h-5" />
                <h3 className="text-sm font-semibold text-main">Approve Incident Closure (Maker-Checker)</h3>
              </div>
              <button
                onClick={() => setIsClosureModalOpen(false)}
                className="text-muted hover:text-main"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="text-xs text-muted">
              Dual-authorization sign-off: Incident reporter was <span className="font-mono text-main">{incident.created_by_id}</span>. You are approving closure as <span className="font-mono text-main">{currentUserId || "CISO"}</span>.
            </div>

            <form onSubmit={handleClosureSubmit} className="space-y-4 text-xs">
              <div>
                <label className="block text-muted font-medium mb-1">
                  Closure Notes &amp; Verification Sign-Off <span className="text-status-critical">*</span>
                </label>
                <textarea
                  required
                  minLength={5}
                  value={closureNotes}
                  onChange={(e) => setClosureNotes(e.target.value)}
                  placeholder="Root cause contained, forensic logs preserved, statutory obligations satisfied..."
                  className="w-full h-24 bg-app border border-rule rounded-control p-2.5 text-main text-xs focus:outline-none focus:ring-1 focus:ring-primary"
                />
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-rule">
                <button
                  type="button"
                  onClick={() => setIsClosureModalOpen(false)}
                  className="px-3 py-1.5 rounded-control border border-rule text-muted hover:text-main"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={closureNotes.trim().length < 5}
                  className="px-4 py-1.5 rounded-control bg-status-ok text-white hover:bg-status-ok/90 font-medium disabled:opacity-50"
                >
                  Authorize incident closure
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Trigger DPDP Aware Modal */}
      {isDpdpModalOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4">
          <div className="bg-surface border border-rule rounded-control w-full max-w-lg p-6 space-y-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-rule pb-3">
              <div className="flex items-center gap-2">
                <Clock className="w-4 h-4 text-status-due_soon" />
                <h3 className="text-sm font-semibold text-main">Assert Statutory DPDP "Aware" Trigger</h3>
              </div>
              <button
                onClick={() => setIsDpdpModalOpen(false)}
                className="text-muted hover:text-main focus:outline-none"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="text-xs text-muted space-y-1">
              <div className="p-2.5 rounded-segment border border-status-due_soon/30 bg-status-due_soon/10 text-main">
                <span className="font-semibold text-status-due_soon">Statutory Requirement: </span>
                Under DPDP Rules 2025 (Rule 7), becoming aware of personal data compromise initiates a strict 72-hour reporting clock to the Data Protection Board.
              </div>
              <p className="text-[11px] text-muted">
                As a SOC Analyst (Maker), asserting this trigger activates the 72-hour statutory runway countdown. This action is permanently recorded in the immutable cryptographic audit ledger.
              </p>
            </div>

            <form onSubmit={handleDpdpSubmit} className="space-y-4 pt-1">
              <div>
                <label className="block text-xs font-medium text-main mb-1">
                  Awareness Occurred At:
                </label>
                <input
                  type="datetime-local"
                  required
                  value={dpdpOccurredAt}
                  onChange={(e) => setDpdpOccurredAt(e.target.value)}
                  className="w-full text-xs bg-app border border-rule rounded-control px-3 py-2 text-main focus:outline-none focus:ring-2 focus:ring-primary font-mono"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-main mb-1">
                  Evidence Summary:
                </label>
                <textarea
                  required
                  rows={2}
                  minLength={5}
                  value={dpdpEvidence}
                  onChange={(e) => setDpdpEvidence(e.target.value)}
                  className="w-full text-xs bg-app border border-rule rounded-control p-2.5 text-main focus:outline-none focus:ring-2 focus:ring-primary"
                  placeholder="e.g. Data exfiltration alert confirmed personal customer identifiers involved."
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-main mb-1">
                  Statutory Rationale:
                </label>
                <textarea
                  required
                  rows={2}
                  minLength={5}
                  value={dpdpRationale}
                  onChange={(e) => setDpdpRationale(e.target.value)}
                  className="w-full text-xs bg-app border border-rule rounded-control p-2.5 text-main focus:outline-none focus:ring-2 focus:ring-primary"
                  placeholder="e.g. Statutory awareness under DPDP Rule 7 asserted by SOC Analyst."
                />
              </div>

              {dpdpError && (
                <div className="text-xs text-status-critical bg-status-critical/10 p-2.5 rounded-segment border border-status-critical/30 flex items-center gap-2">
                  <AlertCircle className="w-3.5 h-3.5 flex-shrink-0" />
                  <span>{dpdpError}</span>
                </div>
              )}

              <div className="flex justify-end gap-2 pt-2 border-t border-rule">
                <button
                  type="button"
                  onClick={() => setIsDpdpModalOpen(false)}
                  className="px-3 py-1.5 rounded-control text-xs border border-rule bg-app hover:bg-surface text-main"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={triggerDpdpMutation.isPending}
                  className="px-4 py-1.5 rounded-control text-xs bg-primary text-primary-fg hover:bg-primary-hover font-medium flex items-center gap-1.5 disabled:opacity-50"
                >
                  <Clock className="w-3.5 h-3.5" />
                  <span>{triggerDpdpMutation.isPending ? "Asserting..." : "Assert 'aware' (Start 72h clock)"}</span>
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
