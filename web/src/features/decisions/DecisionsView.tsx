import React, { useState, useEffect } from "react"
import { 
  BookOpenCheck, 
  ArrowLeft, 
  Plus, 
  CheckCircle2, 
  Clock, 
  ShieldCheck, 
  AlertCircle,
  FileText,
  Download,
  AlertTriangle,
  Languages,
  TrendingUp,
  Calculator,
  Zap,
  BarChart2,
  Sliders
} from "lucide-react"
import { downloadFileAsBlob } from "../../lib/downloadUtil"

export interface DecisionItem {
  id: string
  decision_number: string
  incident_id: string | null
  decision_type: string
  status: string
  rationale: string
  compensating_controls: string
  owner: string
  expiry_date: string
  created_by_id: string
  created_at: string
  countersigned_by_id: string | null
  countersigned_at: string | null
  countersign_notes: string | null
  updated_at: string
}

export interface Para59ExceptionItem {
  id: string
  exception_number: string
  asset_or_system: string
  control_reference: string
  rationale: string
  compensating_controls: string
  owner: string
  risk_level: string
  status: string
  computed_status: string
  days_remaining: number
  issue_date: string
  expiry_date: string
  last_reviewed_at: string | null
  reviewed_by_id: string | null
  review_notes: string | null
  created_by_id: string
  created_at: string
}

interface DecisionsViewProps {
  userRole: string
  currentUserId?: string
  csrfToken?: string
  onBackToCommand: () => void
}

export const DecisionsView: React.FC<DecisionsViewProps> = ({ 
  userRole, 
  currentUserId,
  csrfToken,
  onBackToCommand 
}) => {
  const [activeTab, setActiveTab] = useState<"decisions" | "exceptions" | "exposure">("decisions")
  const [lang, setLang] = useState<"en" | "hi">("en")
  
  // Decisions State
  const [decisions, setDecisions] = useState<DecisionItem[]>([])
  const [exceptions, setExceptions] = useState<Para59ExceptionItem[]>([])
  const [isLoading, setIsLoading] = useState<boolean>(true)
  const [error, setError] = useState<string | null>(null)

  // Open FAIR Rupee Cyber Risk Exposure (M5) & MILP Capital Optimizer (M6)
  const [exposureScenario, setExposureScenario] = useState<{
    scenario_id: string
    name: string
    threat_event_frequency_min: number
    threat_event_frequency_mode: number
    threat_event_frequency_max: number
    vulnerability: number
    primary_loss_min_lakhs: number
    primary_loss_mode_lakhs: number
    primary_loss_max_lakhs: number
    secondary_loss_prob: number
    secondary_loss_min_lakhs: number
    secondary_loss_mode_lakhs: number
    secondary_loss_max_lakhs: number
  }>({
    scenario_id: "SCEN-CBS-UPI-01",
    name: "Core Banking Switch & UPI API Gateway Breach",
    threat_event_frequency_min: 0.5,
    threat_event_frequency_mode: 2.0,
    threat_event_frequency_max: 6.0,
    vulnerability: 0.25,
    primary_loss_min_lakhs: 25.0,
    primary_loss_mode_lakhs: 120.0,
    primary_loss_max_lakhs: 600.0,
    secondary_loss_prob: 0.40,
    secondary_loss_min_lakhs: 50.0,
    secondary_loss_mode_lakhs: 500.0,
    secondary_loss_max_lakhs: 2500.0,
  })
  const [exposureResult, setExposureResult] = useState<any | null>(null)
  const [isSimulatingExposure, setIsSimulatingExposure] = useState<boolean>(false)
  const [exposureError, setExposureError] = useState<string | null>(null)

  const [budgetCapLakhs, setBudgetCapLakhs] = useState<number>(150.0)
  const [isOptimizing, setIsOptimizing] = useState<boolean>(false)
  const [optimizationResult, setOptimizationResult] = useState<any | null>(null)
  const [optimizerError, setOptimizerError] = useState<string | null>(null)

  // Draft new decision modal state
  const [isNewModalOpen, setIsNewModalOpen] = useState(false)
  const [decisionType, setDecisionType] = useState<string>("Risk Acceptance")
  const [rationale, setRationale] = useState<string>("")
  const [compensatingControls, setCompensatingControls] = useState<string>("")
  const [owner, setOwner] = useState<string>("Chief Information Security Officer")
  const [expiryDays, setExpiryDays] = useState<number>(30)
  const [isSubmitting, setIsSubmitting] = useState<boolean>(false)
  const [formError, setFormError] = useState<string | null>(null)

  // Draft new Para 59 exception modal state
  const [isNewExceptionModalOpen, setIsNewExceptionModalOpen] = useState(false)
  const [assetOrSystem, setAssetOrSystem] = useState<string>("")
  const [controlRef, setControlRef] = useState<string>("RBI Para 59.2 - Session Timeout & Access Isolation")
  const [excRationale, setExcRationale] = useState<string>("")
  const [excControls, setExcControls] = useState<string>("")
  const [excOwner, setExcOwner] = useState<string>("IT Infrastructure & Cloud Ops")
  const [excRiskLevel, setExcRiskLevel] = useState<string>("high")
  const [excExpiryDays, setExcExpiryDays] = useState<number>(90)

  // Countersign modal state
  const [countersignTarget, setCountersignTarget] = useState<DecisionItem | null>(null)
  const [countersignNotes, setCountersignNotes] = useState<string>("")
  const [isCountersigning, setIsCountersigning] = useState<boolean>(false)
  const [countersignError, setCountersignError] = useState<string | null>(null)

  const isCiso = userRole === "ciso"
  const canCountersign = ["ciso", "compliance_approver"].includes(userRole)

  const fetchDecisions = async () => {
    setIsLoading(true)
    setError(null)
    try {
      const [resDec, resExc] = await Promise.all([
        fetch("/api/v1/decisions"),
        fetch("/api/v1/decisions/exceptions")
      ])
      if (!resDec.ok) {
        throw new Error(`Failed to load decisions: ${resDec.statusText}`)
      }
      const dataDec: DecisionItem[] = await resDec.json()
      setDecisions(dataDec)

      if (resExc.ok) {
        const dataExc: Para59ExceptionItem[] = await resExc.json()
        setExceptions(dataExc)
      }
    } catch (err: any) {
      setError(err.message)
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    fetchDecisions()
  }, [userRole])

  const handleCreateDecision = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!rationale.trim() || rationale.length < 5) {
      setFormError("Rationale must be at least 5 characters.")
      return
    }
    if (!compensatingControls.trim() || compensatingControls.length < 5) {
      setFormError("Compensating controls must be at least 5 characters.")
      return
    }

    setIsSubmitting(true)
    setFormError(null)

    const expiryDate = new Date(Date.now() + expiryDays * 86400000).toISOString()

    try {
      const headers: Record<string, string> = {
        "Content-Type": "application/json",
      }
      if (csrfToken) {
        headers["X-CSRF-Token"] = csrfToken
      }

      const res = await fetch("/api/v1/decisions", {
        method: "POST",
        headers,
        body: JSON.stringify({
          decision_type: decisionType,
          rationale,
          compensating_controls: compensatingControls,
          owner,
          expiry_date: expiryDate,
        }),
      })

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}))
        throw new Error(errData.detail || `Failed to create decision (HTTP ${res.status})`)
      }

      setIsNewModalOpen(false)
      setRationale("")
      setCompensatingControls("")
      fetchDecisions()
    } catch (err: any) {
      setFormError(err.message)
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleCreateException = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!assetOrSystem.trim() || !excRationale.trim() || !excControls.trim()) {
      setFormError("All exception fields are mandatory.")
      return
    }

    setIsSubmitting(true)
    setFormError(null)

    const expiryDate = new Date(Date.now() + excExpiryDays * 86400000).toISOString()

    try {
      const headers: Record<string, string> = {
        "Content-Type": "application/json",
      }
      if (csrfToken) {
        headers["X-CSRF-Token"] = csrfToken
      }

      const res = await fetch("/api/v1/decisions/exceptions", {
        method: "POST",
        headers,
        body: JSON.stringify({
          asset_or_system: assetOrSystem,
          control_reference: controlRef,
          rationale: excRationale,
          compensating_controls: excControls,
          owner: excOwner,
          risk_level: excRiskLevel,
          expiry_date: expiryDate,
        }),
      })

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}))
        throw new Error(errData.detail || `Failed to create exception (HTTP ${res.status})`)
      }

      setIsNewExceptionModalOpen(false)
      setAssetOrSystem("")
      setExcRationale("")
      setExcControls("")
      fetchDecisions()
    } catch (err: any) {
      setFormError(err.message)
    } finally {
      setIsSubmitting(false)
    }
  }

  const handleCountersign = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!countersignTarget) return
    if (!countersignNotes.trim() || countersignNotes.length < 5) {
      setCountersignError("Countersignature notes must be at least 5 characters.")
      return
    }

    setIsCountersigning(true)
    setCountersignError(null)

    try {
      const headers: Record<string, string> = {
        "Content-Type": "application/json",
      }
      if (csrfToken) {
        headers["X-CSRF-Token"] = csrfToken
      }

      const res = await fetch(`/api/v1/decisions/${countersignTarget.id}/countersign`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          notes: countersignNotes,
        }),
      })

      if (!res.ok) {
        const errData = await res.json().catch(() => ({}))
        throw new Error(errData.detail || `Failed to countersign (HTTP ${res.status})`)
      }

      setCountersignTarget(null)
      setCountersignNotes("")
      fetchDecisions()
    } catch (err: any) {
      setCountersignError(err.message)
    } finally {
      setIsCountersigning(false)
    }
  }

  const handleDownloadBoardPack = () => {
    downloadFileAsBlob({
      url: `/api/v1/governance/board-pack/quarterly/pdf?lang=${lang}`,
      fallbackFilename: `cyberq-board-pack-${lang}.pdf`,
      csrfToken,
    })
  }

  // Open FAIR 16,384-iteration Sobol QMC Simulation
  const handleRunExposureSimulation = async () => {
    setIsSimulatingExposure(true)
    setExposureError(null)
    try {
      const res = await fetch("/api/v1/exposure/simulate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(exposureScenario),
      })
      if (!res.ok) {
        const err = await res.json().catch(() => ({}))
        throw new Error(err.detail || `Exposure simulation failed: ${res.statusText}`)
      }
      const data = await res.json()
      setExposureResult(data)
    } catch (err: any) {
      setExposureError(err.message || String(err))
    } finally {
      setIsSimulatingExposure(false)
    }
  }

  // SciPy HiGHS MILP Capital Allocation Optimizer
  const handleRunCapitalOptimization = async (cap?: number) => {
    setIsOptimizing(true)
    setOptimizerError(null)
    const targetBudget = cap !== undefined ? cap : budgetCapLakhs
    try {
      const res = await fetch("/api/v1/exposure/optimize", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          budget_cap_lakhs: targetBudget,
          candidate_controls: [],
        }),
      })
      if (!res.ok) {
        const err = await res.json().catch(() => ({}))
        throw new Error(err.detail || `Optimization failed: ${res.statusText}`)
      }
      const data = await res.json()
      setOptimizationResult(data)
    } catch (err: any) {
      setOptimizerError(err.message || String(err))
    } finally {
      setIsOptimizing(false)
    }
  }

  const activeCount = decisions.filter(d => d.status === "active").length
  const pendingCount = decisions.filter(d => d.status === "awaiting_countersignature").length
  const expiringSoonCount = exceptions.filter(e => e.computed_status === "expiring_soon").length

  return (
    <div className="flex-1 flex flex-col h-full bg-app overflow-hidden">
      {/* Top Header */}
      <div className="h-12 border-b border-rule bg-surface flex items-center justify-between px-6 flex-shrink-0">
        <div className="flex items-center gap-3">
          <button
            onClick={onBackToCommand}
            className="p-1.5 rounded-control text-muted hover:text-main hover:bg-app border border-rule flex items-center gap-1.5 text-xs"
            title="Return to Command Center"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>{lang === "hi" ? "कमांड सेंटर" : "Command Center"}</span>
          </button>
          <span className="text-muted text-xs">/</span>
          <div className="flex items-center gap-2">
            <BookOpenCheck className="w-4 h-4 text-primary" />
            <h1 className="text-sm font-semibold text-main">
              {lang === "hi" ? "वैधानिक जोखिम निर्णय एवं अपवाद रजिस्टर" : "Statutory Risk Decisions & Exceptions"}
            </h1>
          </div>
        </div>

        <div className="flex items-center gap-3 text-xs">
          {/* Language Toggle */}
          <button
            onClick={() => setLang(l => (l === "en" ? "hi" : "en"))}
            className="px-2.5 py-1 rounded-control border border-rule bg-surface text-main hover:bg-app flex items-center gap-1.5 font-medium"
            title="Toggle English / Hindi (Rajbhasha)"
          >
            <Languages className="w-3.5 h-3.5 text-primary" />
            <span>{lang === "en" ? "हिन्दी (HI)" : "English (EN)"}</span>
          </button>

          {/* Export Board Pack PDF */}
          <button
            onClick={handleDownloadBoardPack}
            className="px-2.5 py-1 rounded-control border border-rule bg-surface text-main hover:bg-app flex items-center gap-1.5 font-medium"
            title="Export RBI Para 28(7) Quarterly Board Risk Pack (PDF)"
          >
            <Download className="w-3.5 h-3.5 text-primary" />
            <span>{lang === "hi" ? "बोर्ड पैक (PDF)" : "Board Pack (PDF)"}</span>
          </button>

          {isCiso && activeTab !== "exposure" && (
            <button
              onClick={() => {
                if (activeTab === "decisions") setIsNewModalOpen(true)
                else setIsNewExceptionModalOpen(true)
              }}
              className="px-3 py-1.5 rounded-control bg-primary text-primary-fg hover:bg-primary-hover font-medium flex items-center gap-1.5"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>
                {activeTab === "decisions"
                  ? (lang === "hi" ? "निर्णय प्रारूप बनाएँ" : "Draft risk decision")
                  : (lang === "hi" ? "अपवाद पंजीकृत करें" : "Record Para 59 exception")}
              </span>
            </button>
          )}
        </div>
      </div>

      {/* Content Area */}
      <div className="flex-1 overflow-y-auto p-6 max-w-5xl mx-auto w-full space-y-6">
        {/* Navigation Tabs */}
        <div className="flex items-center gap-2 border-b border-rule pb-2">
          <button
            onClick={() => setActiveTab("decisions")}
            className={`px-3 py-1.5 text-xs font-medium rounded-control transition-colors ${
              activeTab === "decisions"
                ? "bg-primary text-primary-fg"
                : "text-muted hover:text-main hover:bg-surface"
            }`}
          >
            {lang === "hi" ? "जोखिम निर्णय बही" : "CISO Risk Decisions"} ({decisions.length})
          </button>
          <button
            onClick={() => setActiveTab("exceptions")}
            className={`px-3 py-1.5 text-xs font-medium rounded-control transition-colors flex items-center gap-1.5 ${
              activeTab === "exceptions"
                ? "bg-primary text-primary-fg"
                : "text-muted hover:text-main hover:bg-surface"
            }`}
          >
            <span>{lang === "hi" ? "पैरा 59 अपवाद रजिस्टर" : "Para 59 Exceptions Register"}</span>
            <span className="font-mono">({exceptions.length})</span>
            {expiringSoonCount > 0 && (
              <span className="px-1.5 py-0.2 rounded-full bg-status-critical text-white text-[10px] font-bold">
                {expiringSoonCount}
              </span>
            )}
          </button>
          <button
            onClick={() => setActiveTab("exposure")}
            className={`px-3 py-1.5 text-xs font-medium rounded-control transition-colors flex items-center gap-1.5 ${
              activeTab === "exposure"
                ? "bg-primary text-primary-fg"
                : "text-muted hover:text-main hover:bg-surface"
            }`}
          >
            <TrendingUp className="w-3.5 h-3.5" />
            <span>{lang === "hi" ? "ओपन फेयर जोखिम एवं पूंजी अनुकूलक" : "Rupee Risk Exposure & Capital Optimizer"}</span>
            <span className="px-1.5 py-0.2 rounded-full bg-primary/20 text-primary text-[10px] font-mono border border-primary/30">
              M5 / M6
            </span>
          </button>
        </div>

        {/* Status Metrics Strip */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-4 rounded-segment border border-rule bg-surface flex items-center gap-3">
            <div className="w-9 h-9 rounded-control bg-primary/10 text-primary flex items-center justify-center flex-shrink-0">
              <BookOpenCheck className="w-5 h-5" />
            </div>
            <div>
              <div className="text-[11px] text-muted">
                {lang === "hi" ? "कुल दर्ज निर्णय" : "Total recorded decisions"}
              </div>
              <div className="text-lg font-bold font-mono text-main">{decisions.length}</div>
            </div>
          </div>

          <div className="p-4 rounded-segment border border-rule bg-surface flex items-center gap-3">
            <div className="w-9 h-9 rounded-control bg-status-ok/10 text-status-ok flex items-center justify-center flex-shrink-0">
              <CheckCircle2 className="w-5 h-5" />
            </div>
            <div>
              <div className="text-[11px] text-muted">
                {lang === "hi" ? "सक्रिय निर्णय" : "Active decisions"}
              </div>
              <div className="text-lg font-bold font-mono text-status-ok">{activeCount}</div>
            </div>
          </div>

          <div className="p-4 rounded-segment border border-rule bg-surface flex items-center gap-3">
            <div className="w-9 h-9 rounded-control bg-status-due_soon/10 text-status-due_soon flex items-center justify-center flex-shrink-0">
              <Clock className="w-5 h-5" />
            </div>
            <div>
              <div className="text-[11px] text-muted">
                {lang === "hi" ? "प्रतिहस्ताक्षर की प्रतीक्षा" : "Awaiting countersignature"}
              </div>
              <div className="text-lg font-bold font-mono text-status-due_soon">{pendingCount}</div>
            </div>
          </div>
        </div>

        {/* Error message */}
        {error && (
          <div className="p-4 rounded-segment border border-status-critical bg-status-critical/10 text-status-critical text-xs flex items-center gap-2">
            <AlertCircle className="w-4 h-4 flex-shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Tab 1: Risk Decisions Table */}
        {activeTab === "decisions" && (
          isLoading ? (
            <div className="p-12 text-center text-xs text-muted">
              {lang === "hi" ? "निर्णय लोड हो रहे हैं..." : "Loading statutory risk decisions..."}
            </div>
          ) : decisions.length === 0 ? (
            <div className="p-12 rounded-segment border border-rule bg-surface text-center max-w-lg mx-auto space-y-3">
              <div className="w-10 h-10 rounded-full bg-primary/10 text-primary flex items-center justify-center mx-auto">
                <BookOpenCheck className="w-5 h-5" />
              </div>
              <h2 className="text-sm font-semibold text-main">
                {lang === "hi" ? "कोई जोखिम निर्णय दर्ज नहीं है। 0 सक्रिय।" : "No risk decisions recorded. 0 active."}
              </h2>
              <p className="text-xs text-muted leading-relaxed">
                {lang === "hi"
                  ? "प्रत्येक सामग्री निर्णय के लिए दोहरे-नियंत्रण निर्माता-जांचकर्ता प्राधिकरण की आवश्यकता होती है।"
                  : "Every material decision requires dual-control maker-checker authorization and writes immutable audit checkpoints."}
              </p>
            </div>
          ) : (
            <div className="border border-rule rounded-segment bg-surface overflow-hidden">
              <table className="w-full text-left text-xs" aria-label="Statutory risk decisions">
                <thead className="bg-app border-b border-rule font-medium text-muted">
                  <tr>
                    <th className="py-2.5 px-3 w-32">{lang === "hi" ? "निर्णय संख्या" : "Decision #"}</th>
                    <th className="py-2.5 px-3 w-40">{lang === "hi" ? "प्रकार" : "Type"}</th>
                    <th className="py-2.5 px-3 w-36">{lang === "hi" ? "स्थिति" : "Status"}</th>
                    <th className="py-2.5 px-3">{lang === "hi" ? "तर्क एवं नियंत्रण" : "Rationale & Controls"}</th>
                    <th className="py-2.5 px-3 w-40">{lang === "hi" ? "प्रभारी" : "Owner"}</th>
                    <th className="py-2.5 px-3 w-28">{lang === "hi" ? "समाप्ति" : "Expiry"}</th>
                    <th className="py-2.5 px-3 w-28 text-right">{lang === "hi" ? "कार्रवाई" : "Actions"}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-rule">
                  {decisions.map((dec) => {
                    const isAwaiting = dec.status === "awaiting_countersignature"
                    const isMaker = currentUserId && dec.created_by_id === currentUserId
                    return (
                      <tr key={dec.id} className="hover:bg-app/50 transition-colors">
                        <td className="py-2.5 px-3 font-mono font-medium text-main">
                          {dec.decision_number}
                        </td>
                        <td className="py-2.5 px-3 font-medium text-muted">
                          {dec.decision_type}
                        </td>
                        <td className="py-2.5 px-3">
                          <span
                            className={`inline-flex items-center px-2 py-0.5 rounded-segment border text-[10px] font-mono ${
                              dec.status === "active"
                                ? "bg-status-ok/10 border-status-ok text-status-ok"
                                : dec.status === "awaiting_countersignature"
                                ? "bg-status-due_soon/10 border-status-due_soon text-status-due_soon"
                                : "bg-surface border-rule text-muted"
                            }`}
                          >
                            {dec.status.replace(/_/g, " ")}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-muted leading-relaxed max-w-xs">
                          <div className="font-medium text-main truncate">{dec.rationale}</div>
                          <div className="text-[11px] text-muted truncate mt-0.5">
                            Controls: {dec.compensating_controls}
                          </div>
                        </td>
                        <td className="py-2.5 px-3 text-muted text-[11px] truncate">
                          {dec.owner}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-[11px] text-muted whitespace-nowrap">
                          {new Date(dec.expiry_date).toLocaleDateString("en-IN", {
                            day: "2-digit",
                            month: "short",
                            year: "numeric",
                          })}
                        </td>
                        <td className="py-2.5 px-3 text-right">
                          {isAwaiting && canCountersign && !isMaker && (
                            <button
                              onClick={() => {
                                setCountersignTarget(dec)
                                setCountersignNotes("")
                                setCountersignError(null)
                              }}
                              className="px-2 py-1 rounded-control bg-primary text-primary-fg hover:bg-primary-hover font-medium text-[11px] flex items-center gap-1 ml-auto"
                            >
                              <ShieldCheck className="w-3 h-3" />
                              <span>{lang === "hi" ? "प्रतिहस्ताक्षर" : "Countersign"}</span>
                            </button>
                          )}
                          {isAwaiting && isMaker && (
                            <span className="text-[10px] text-muted italic">
                              {lang === "hi" ? "निर्माता अवरुद्ध" : "Maker locked"}
                            </span>
                          )}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )
        )}

        {/* Tab 2: RBI Para 59 Exceptions Register Table */}
        {activeTab === "exceptions" && (
          <div className="border border-rule rounded-segment bg-surface overflow-hidden">
            <table className="w-full text-left text-xs" aria-label="Para 59 Exceptions">
              <thead className="bg-app border-b border-rule font-medium text-muted">
                <tr>
                  <th className="py-2.5 px-3 w-32">{lang === "hi" ? "अपवाद संख्या" : "Exception #"}</th>
                  <th className="py-2.5 px-3 w-40">{lang === "hi" ? "सिस्टम / एसेट" : "Asset / System"}</th>
                  <th className="py-2.5 px-3 w-44">{lang === "hi" ? "नियंत्रण संदर्भ" : "Control Reference"}</th>
                  <th className="py-2.5 px-3 w-28">{lang === "hi" ? "जोखिम स्तर" : "Risk Level"}</th>
                  <th className="py-2.5 px-3 w-36">{lang === "hi" ? "स्थिति / शेष दिन" : "Status & Countdown"}</th>
                  <th className="py-2.5 px-3">{lang === "hi" ? "क्षतिपूरक नियंत्रण" : "Compensating Controls"}</th>
                  <th className="py-2.5 px-3 w-32">{lang === "hi" ? "प्रभारी" : "Owner"}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-rule">
                {exceptions.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="py-8 text-center text-muted">
                      {lang === "hi" ? "कोई पैरा 59 अपवाद दर्ज नहीं है।" : "No Para 59 exceptions recorded."}
                    </td>
                  </tr>
                ) : (
                  exceptions.map((exc) => {
                    const isExpiringSoon = exc.computed_status === "expiring_soon"
                    const isExpired = exc.computed_status === "expired"
                    return (
                      <tr key={exc.id} className="hover:bg-app/50 transition-colors">
                        <td className="py-2.5 px-3 font-mono font-medium text-main">
                          {exc.exception_number}
                        </td>
                        <td className="py-2.5 px-3 font-medium text-main">
                          {exc.asset_or_system}
                        </td>
                        <td className="py-2.5 px-3 text-muted truncate max-w-xs">
                          {exc.control_reference}
                        </td>
                        <td className="py-2.5 px-3">
                          <span className={`inline-flex px-1.5 py-0.5 rounded text-[10px] uppercase font-mono font-bold ${
                            exc.risk_level === "critical"
                              ? "bg-status-critical/10 text-status-critical"
                              : exc.risk_level === "high"
                              ? "bg-status-due_soon/10 text-status-due_soon"
                              : "bg-surface text-muted"
                          }`}>
                            {exc.risk_level}
                          </span>
                        </td>
                        <td className="py-2.5 px-3">
                          {isExpiringSoon ? (
                            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-status-critical/10 text-status-critical border border-status-critical font-bold text-[10px]">
                              <AlertTriangle className="w-3 h-3" />
                              <span>{exc.days_remaining}d left (Expiring)</span>
                            </span>
                          ) : isExpired ? (
                            <span className="inline-flex px-2 py-0.5 rounded bg-status-critical/20 text-status-critical font-bold text-[10px]">
                              Expired
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 text-[11px] font-mono text-status-ok">
                              <CheckCircle2 className="w-3 h-3" />
                              <span>Active ({exc.days_remaining}d)</span>
                            </span>
                          )}
                        </td>
                        <td className="py-2.5 px-3 text-muted truncate max-w-xs">
                          {exc.compensating_controls}
                        </td>
                        <td className="py-2.5 px-3 text-muted text-[11px] truncate">
                          {exc.owner}
                        </td>
                      </tr>
                    )
                  })
                )}
              </tbody>
            </table>
          </div>
        )}

        {/* Tab 3: Open FAIR Rupee Cyber Risk Exposure (M5) & MILP Capital Optimizer (M6) */}
        {activeTab === "exposure" && (
          <div className="space-y-8">
            {/* Model Risk Governance Banner */}
            <div className="p-4 rounded-segment border border-primary/40 bg-primary/5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
              <div>
                <div className="flex items-center gap-2">
                  <span className="p-1 rounded bg-primary/20 text-primary">
                    <TrendingUp className="w-4 h-4" />
                  </span>
                  <h2 className="text-sm font-bold text-main">
                    {lang === "hi"
                      ? "ओपन फेयर मात्रात्मक साइबर जोखिम विश्लेषण एवं पूंजी अनुकूलक"
                      : "Open FAIR Quantitative Rupee Cyber Risk Exposure & HiGHS Capital Optimizer"}
                  </h2>
                </div>
                <p className="text-xs text-muted mt-1">
                  16,384-Iteration Sobol Quasi-Monte Carlo • Kolmogorov-Smirnov Statistical Convergence • SciPy HiGHS Mixed-Integer Linear Program • Zero Mock Return Stubs
                </p>
              </div>
              <div className="flex items-center gap-2 font-mono text-[11px]">
                <span className="px-2 py-0.5 rounded border border-status-ok bg-status-ok/10 text-status-ok font-semibold">
                  RBI Para 28(7) MRM COMPLIANT
                </span>
              </div>
            </div>

            {/* Sub-Section 1: Open FAIR 16,384 Sobol QMC Simulation */}
            <div className="p-5 rounded-segment border border-rule bg-surface space-y-4">
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 border-b border-rule pb-3">
                <div className="flex items-center gap-2">
                  <Calculator className="w-4 h-4 text-primary" />
                  <h3 className="text-sm font-bold text-main">
                    {lang === "hi" ? "1. 16,384-पुनरावृत्ति सोबोल क्यूएमसी जोखिम अनुकरण" : "1. 16,384-Iteration Sobol QMC Rupee VaR Simulation (Open FAIR)"}
                  </h3>
                </div>
                <span className="text-[11px] font-mono text-muted">
                  RFC 8785 Seed Grounding • Two-sided KS Test
                </span>
              </div>

              {/* Scenario Inputs Form */}
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 text-xs">
                <div className="lg:col-span-3">
                  <label className="block text-muted mb-1 font-medium">Risk Scenario Title:</label>
                  <input
                    type="text"
                    value={exposureScenario.name}
                    onChange={e => setExposureScenario({ ...exposureScenario, name: e.target.value })}
                    className="w-full bg-app border border-rule rounded px-2.5 py-1.5 text-main font-medium focus:border-primary outline-none"
                  />
                </div>

                <div>
                  <label className="block text-muted mb-1 font-medium">TEF (Threat Events / Year):</label>
                  <div className="grid grid-cols-3 gap-1">
                    <input
                      type="number"
                      step="0.1"
                      title="Min TEF"
                      placeholder="Min"
                      value={exposureScenario.threat_event_frequency_min}
                      onChange={e => setExposureScenario({ ...exposureScenario, threat_event_frequency_min: parseFloat(e.target.value) || 0.1 })}
                      className="bg-app border border-rule rounded px-2 py-1 font-mono text-main outline-none"
                    />
                    <input
                      type="number"
                      step="0.1"
                      title="Mode TEF"
                      placeholder="Mode"
                      value={exposureScenario.threat_event_frequency_mode}
                      onChange={e => setExposureScenario({ ...exposureScenario, threat_event_frequency_mode: parseFloat(e.target.value) || 1.0 })}
                      className="bg-app border border-rule rounded px-2 py-1 font-mono text-main outline-none"
                    />
                    <input
                      type="number"
                      step="0.1"
                      title="Max TEF"
                      placeholder="Max"
                      value={exposureScenario.threat_event_frequency_max}
                      onChange={e => setExposureScenario({ ...exposureScenario, threat_event_frequency_max: parseFloat(e.target.value) || 5.0 })}
                      className="bg-app border border-rule rounded px-2 py-1 font-mono text-main outline-none"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-muted mb-1 font-medium">Vulnerability % (0.0 to 1.0):</label>
                  <input
                    type="number"
                    step="0.05"
                    min="0"
                    max="1"
                    value={exposureScenario.vulnerability}
                    onChange={e => setExposureScenario({ ...exposureScenario, vulnerability: parseFloat(e.target.value) || 0.1 })}
                    className="w-full bg-app border border-rule rounded px-2.5 py-1 text-main font-mono outline-none"
                  />
                </div>

                <div>
                  <label className="block text-muted mb-1 font-medium">Primary Loss (₹ Lakhs: Min/Mode/Max):</label>
                  <div className="grid grid-cols-3 gap-1">
                    <input
                      type="number"
                      title="Min Primary"
                      value={exposureScenario.primary_loss_min_lakhs}
                      onChange={e => setExposureScenario({ ...exposureScenario, primary_loss_min_lakhs: parseFloat(e.target.value) || 0 })}
                      className="bg-app border border-rule rounded px-2 py-1 font-mono text-main outline-none"
                    />
                    <input
                      type="number"
                      title="Mode Primary"
                      value={exposureScenario.primary_loss_mode_lakhs}
                      onChange={e => setExposureScenario({ ...exposureScenario, primary_loss_mode_lakhs: parseFloat(e.target.value) || 0 })}
                      className="bg-app border border-rule rounded px-2 py-1 font-mono text-main outline-none"
                    />
                    <input
                      type="number"
                      title="Max Primary"
                      value={exposureScenario.primary_loss_max_lakhs}
                      onChange={e => setExposureScenario({ ...exposureScenario, primary_loss_max_lakhs: parseFloat(e.target.value) || 0 })}
                      className="bg-app border border-rule rounded px-2 py-1 font-mono text-main outline-none"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-muted mb-1 font-medium">Secondary Loss (₹ Lakhs: Min/Mode/Max):</label>
                  <div className="grid grid-cols-3 gap-1">
                    <input
                      type="number"
                      title="Min Secondary"
                      value={exposureScenario.secondary_loss_min_lakhs}
                      onChange={e => setExposureScenario({ ...exposureScenario, secondary_loss_min_lakhs: parseFloat(e.target.value) || 0 })}
                      className="bg-app border border-rule rounded px-2 py-1 font-mono text-main outline-none"
                    />
                    <input
                      type="number"
                      title="Mode Secondary"
                      value={exposureScenario.secondary_loss_mode_lakhs}
                      onChange={e => setExposureScenario({ ...exposureScenario, secondary_loss_mode_lakhs: parseFloat(e.target.value) || 0 })}
                      className="bg-app border border-rule rounded px-2 py-1 font-mono text-main outline-none"
                    />
                    <input
                      type="number"
                      title="Max Secondary"
                      value={exposureScenario.secondary_loss_max_lakhs}
                      onChange={e => setExposureScenario({ ...exposureScenario, secondary_loss_max_lakhs: parseFloat(e.target.value) || 0 })}
                      className="bg-app border border-rule rounded px-2 py-1 font-mono text-main outline-none"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-muted mb-1 font-medium">Secondary Loss Probability:</label>
                  <input
                    type="number"
                    step="0.05"
                    min="0"
                    max="1"
                    value={exposureScenario.secondary_loss_prob}
                    onChange={e => setExposureScenario({ ...exposureScenario, secondary_loss_prob: parseFloat(e.target.value) || 0.4 })}
                    className="w-full bg-app border border-rule rounded px-2.5 py-1 text-main font-mono outline-none"
                  />
                </div>

                <div className="flex items-end">
                  <button
                    onClick={handleRunExposureSimulation}
                    disabled={isSimulatingExposure}
                    className="w-full py-2 px-3 rounded bg-primary text-primary-fg hover:bg-primary-hover font-semibold flex items-center justify-center gap-2 transition disabled:opacity-50"
                  >
                    <Calculator className={`w-3.5 h-3.5 ${isSimulatingExposure ? "animate-spin" : ""}`} />
                    <span>{isSimulatingExposure ? "Running 16,384 QMC..." : "Run 16,384 Sobol QMC Simulation"}</span>
                  </button>
                </div>
              </div>

              {exposureError && (
                <div className="p-3 rounded bg-status-critical/10 border border-status-critical text-status-critical text-xs">
                  {exposureError}
                </div>
              )}

              {/* Simulation Results Display */}
              {exposureResult && (
                <div className="p-4 rounded-control bg-app border border-primary/40 space-y-4">
                  <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 border-b border-rule pb-2">
                    <div>
                      <span className="text-[10px] font-mono text-primary font-bold uppercase tracking-wider">
                        SIMULATION COMPLETED (16,384 SAMPLES)
                      </span>
                      <h4 className="text-xs font-bold text-main">{exposureResult.scenario_name}</h4>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-status-ok/10 text-status-ok border border-status-ok">
                        KS Stat: {exposureResult.ks_stat?.toFixed(4)} (CONVERGED)
                      </span>
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-surface border border-rule text-muted">
                        p = {exposureResult.ks_pvalue?.toFixed(3)}
                      </span>
                    </div>
                  </div>

                  {/* 4 VaR Percentile Cards */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center">
                    <div className="p-3 rounded bg-surface border border-rule space-y-1">
                      <div className="text-[10px] text-muted uppercase font-mono">P10 (Optimistic)</div>
                      <div className="text-base font-bold font-mono text-status-ok">₹ {exposureResult.p10_crores?.toFixed(2)} Cr</div>
                      <div className="text-[10px] font-mono text-muted">{exposureResult.p10_lakhs?.toFixed(1)} Lakhs</div>
                    </div>
                    <div className="p-3 rounded bg-surface border border-rule space-y-1">
                      <div className="text-[10px] text-muted uppercase font-mono">P50 (Expected Loss)</div>
                      <div className="text-base font-bold font-mono text-primary">₹ {exposureResult.p50_crores?.toFixed(2)} Cr</div>
                      <div className="text-[10px] font-mono text-muted">{exposureResult.p50_lakhs?.toFixed(1)} Lakhs</div>
                    </div>
                    <div className="p-3 rounded bg-surface border border-rule space-y-1">
                      <div className="text-[10px] text-muted uppercase font-mono">P90 (Value-at-Risk)</div>
                      <div className="text-base font-bold font-mono text-status-due_soon">₹ {exposureResult.p90_crores?.toFixed(2)} Cr</div>
                      <div className="text-[10px] font-mono text-muted">{exposureResult.p90_lakhs?.toFixed(1)} Lakhs</div>
                    </div>
                    <div className="p-3 rounded bg-surface border border-rule space-y-1">
                      <div className="text-[10px] text-muted uppercase font-mono">P99 (Tail Loss)</div>
                      <div className="text-base font-bold font-mono text-status-critical">₹ {exposureResult.p99_crores?.toFixed(2)} Cr</div>
                      <div className="text-[10px] font-mono text-muted">{exposureResult.p99_lakhs?.toFixed(1)} Lakhs</div>
                    </div>
                  </div>

                  <div className="text-[11px] font-mono text-muted flex items-center justify-between border-t border-rule pt-2">
                    <span>Seed Hash: <code className="text-main">{exposureResult.seed_hash?.slice(0, 16)}...</code></span>
                    <span>Expected Annual Loss (EAL): <strong className="text-primary font-bold">₹ {exposureResult.expected_annual_loss_crores?.toFixed(2)} Crores</strong></span>
                  </div>
                </div>
              )}
            </div>

            {/* Sub-Section 2: SciPy HiGHS MILP Capital Allocation Optimizer */}
            <div className="p-5 rounded-segment border border-rule bg-surface space-y-4">
              <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 border-b border-rule pb-3">
                <div className="flex items-center gap-2">
                  <Sliders className="w-4 h-4 text-primary" />
                  <h3 className="text-sm font-bold text-main">
                    {lang === "hi" ? "2. साइबर सुरक्षा पूंजी आवंटन अनुकूलक (HiGHS MILP)" : "2. SciPy HiGHS Mixed-Integer Linear Capital Allocation Optimizer (M6)"}
                  </h3>
                </div>
                <span className="text-[11px] font-mono text-muted">
                  Integer Constraints • Tech Dependencies • Mutex Rules
                </span>
              </div>

              {/* Budget Cap Selector & Action */}
              <div className="flex flex-col sm:flex-row items-start sm:items-end justify-between gap-3 text-xs">
                <div className="w-full sm:w-72 space-y-1.5">
                  <label className="block text-muted font-medium">CISO Investment Budget Cap (₹ Lakhs):</label>
                  <div className="flex items-center gap-2">
                    <input
                      type="number"
                      step="10"
                      min="10"
                      value={budgetCapLakhs}
                      onChange={e => setBudgetCapLakhs(parseFloat(e.target.value) || 50)}
                      className="w-full bg-app border border-rule rounded px-3 py-1.5 font-mono text-main outline-none focus:border-primary"
                    />
                    <div className="flex items-center gap-1">
                      {[50, 100, 150, 200].map(val => (
                        <button
                          key={val}
                          type="button"
                          onClick={() => {
                            setBudgetCapLakhs(val)
                            handleRunCapitalOptimization(val)
                          }}
                          className={`px-2 py-1 rounded text-[10px] font-mono border ${
                            budgetCapLakhs === val
                              ? "bg-primary text-primary-fg border-primary"
                              : "bg-surface border-rule text-muted hover:text-main"
                          }`}
                        >
                          ₹{val}L
                        </button>
                      ))}
                    </div>
                  </div>
                </div>

                <button
                  onClick={() => handleRunCapitalOptimization()}
                  disabled={isOptimizing}
                  className="py-2 px-4 rounded bg-primary text-primary-fg hover:bg-primary-hover font-semibold flex items-center gap-2 transition disabled:opacity-50"
                >
                  <Zap className={`w-3.5 h-3.5 ${isOptimizing ? "animate-spin" : ""}`} />
                  <span>{isOptimizing ? "Solving HiGHS MILP..." : "Solve Optimal Allocation (HiGHS MILP)"}</span>
                </button>
              </div>

              {optimizerError && (
                <div className="p-3 rounded bg-status-critical/10 border border-status-critical text-status-critical text-xs">
                  {optimizerError}
                </div>
              )}

              {/* Optimization Results */}
              {optimizationResult && (
                <div className="space-y-4">
                  {/* Summary Metric Strip */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-center">
                    <div className="p-3 rounded bg-app border border-rule space-y-1">
                      <div className="text-[10px] text-muted uppercase font-mono">Budget Allocated</div>
                      <div className="text-base font-bold font-mono text-main">
                        ₹ {optimizationResult.total_cost_lakhs?.toFixed(1)} L
                      </div>
                      <div className="text-[10px] font-mono text-muted">
                        of ₹ {optimizationResult.budget_cap_lakhs?.toFixed(0)} L Cap
                      </div>
                    </div>
                    <div className="p-3 rounded bg-app border border-rule space-y-1">
                      <div className="text-[10px] text-muted uppercase font-mono">Annual Risk Reduced</div>
                      <div className="text-base font-bold font-mono text-status-ok">
                        ₹ {optimizationResult.total_risk_reduction_crores?.toFixed(2)} Cr
                      </div>
                      <div className="text-[10px] font-mono text-muted">
                        {optimizationResult.total_risk_reduction_lakhs?.toFixed(0)} Lakhs
                      </div>
                    </div>
                    <div className="p-3 rounded bg-app border border-rule space-y-1">
                      <div className="text-[10px] text-muted uppercase font-mono">Capital ROI Ratio</div>
                      <div className="text-base font-bold font-mono text-primary">
                        {optimizationResult.roi_ratio?.toFixed(2)}x
                      </div>
                      <div className="text-[10px] font-mono text-muted">Benefit / Cost</div>
                    </div>
                    <div className="p-3 rounded bg-app border border-rule space-y-1">
                      <div className="text-[10px] text-muted uppercase font-mono">HiGHS Solver Status</div>
                      <div className="text-base font-bold font-mono text-status-ok">
                        {optimizationResult.solver_status || "OPTIMAL"}
                      </div>
                      <div className="text-[10px] font-mono text-muted">Binary Integrality: 1.0</div>
                    </div>
                  </div>

                  {/* Selected Controls Table */}
                  <div className="border border-rule rounded overflow-hidden">
                    <div className="bg-app px-3 py-2 border-b border-rule flex items-center justify-between text-xs font-semibold text-main">
                      <span>Funded Security Controls Portfolio ({optimizationResult.selected_controls?.length} Selected):</span>
                      <span className="font-mono text-[11px] text-muted">Globally Optimal Portfolio</span>
                    </div>
                    <table className="w-full text-left text-xs">
                      <thead className="bg-surface/50 border-b border-rule text-muted font-medium">
                        <tr>
                          <th className="py-2 px-3">Control ID</th>
                          <th className="py-2 px-3">Security Control Name</th>
                          <th className="py-2 px-3">Category</th>
                          <th className="py-2 px-3 font-mono">Cost (₹ Lakhs)</th>
                          <th className="py-2 px-3 font-mono">Risk Reduced</th>
                          <th className="py-2 px-3">Status</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-rule">
                        {optimizationResult.selected_controls?.map((ctrl: any) => (
                          <tr key={ctrl.control_id} className="hover:bg-app/50 font-mono text-[11px]">
                            <td className="py-2 px-3 font-bold text-primary">{ctrl.control_id}</td>
                            <td className="py-2 px-3 font-sans font-medium text-main">{ctrl.name}</td>
                            <td className="py-2 px-3 text-muted">{ctrl.category}</td>
                            <td className="py-2 px-3 font-bold text-main">₹ {ctrl.cost_lakhs?.toFixed(1)} L</td>
                            <td className="py-2 px-3 font-bold text-status-ok">₹ {(ctrl.risk_reduction_lakhs / 100).toFixed(2)} Cr</td>
                            <td className="py-2 px-3">
                              <span className="px-1.5 py-0.5 rounded bg-status-ok/10 text-status-ok border border-status-ok text-[10px] font-bold">
                                FUNDED
                              </span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>

                  {/* 10-Point Pareto Investment Curve */}
                  {optimizationResult.pareto_frontier && (
                    <div className="border border-rule rounded overflow-hidden">
                      <div className="bg-app px-3 py-2 border-b border-rule flex items-center justify-between text-xs font-semibold text-main">
                        <span className="flex items-center gap-1.5">
                          <BarChart2 className="w-3.5 h-3.5 text-primary" />
                          Pareto Optimal Investment Frontier Curve (10 Budget Steps):
                        </span>
                        <span className="text-[10px] font-mono text-muted">Capital Efficiency Frontier</span>
                      </div>
                      <div className="overflow-x-auto">
                        <table className="w-full text-left text-xs font-mono">
                          <thead className="bg-surface/50 border-b border-rule text-muted">
                            <tr>
                              <th className="py-2 px-3">Budget Cap</th>
                              <th className="py-2 px-3">Allocated Cost</th>
                              <th className="py-2 px-3">Risk Reduction</th>
                              <th className="py-2 px-3">Controls</th>
                              <th className="py-2 px-3">ROI Ratio</th>
                              <th className="py-2 px-3">Efficiency</th>
                            </tr>
                          </thead>
                          <tbody className="divide-y divide-rule text-[11px]">
                            {optimizationResult.pareto_frontier.map((pt: any, idx: number) => {
                              const isCurrent = Math.abs(pt.budget_cap_lakhs - budgetCapLakhs) < 0.1
                              return (
                                <tr
                                  key={idx}
                                  className={`hover:bg-app/50 transition-colors ${
                                    isCurrent ? "bg-primary/10 font-bold" : ""
                                  }`}
                                >
                                  <td className="py-1.5 px-3">₹ {pt.budget_cap_lakhs?.toFixed(0)} L</td>
                                  <td className="py-1.5 px-3">₹ {pt.total_cost_lakhs?.toFixed(1)} L</td>
                                  <td className="py-1.5 px-3 text-status-ok">₹ {pt.risk_reduction_crores?.toFixed(2)} Cr</td>
                                  <td className="py-1.5 px-3">{pt.controls_count}</td>
                                  <td className="py-1.5 px-3 text-primary">{pt.roi_ratio?.toFixed(2)}x</td>
                                  <td className="py-1.5 px-3">
                                    <div className="w-24 bg-surface rounded-full h-2 border border-rule overflow-hidden">
                                      <div
                                        className="bg-primary h-full rounded-full"
                                        style={{ width: `${Math.min(100, (pt.risk_reduction_crores / 7.0) * 100)}%` }}
                                      />
                                    </div>
                                  </td>
                                </tr>
                              )
                            })}
                          </tbody>
                        </table>
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Draft New Decision Modal */}
      {isNewModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4">
          <div className="bg-surface border border-rule rounded-segment max-w-lg w-full p-6 space-y-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-rule pb-3">
              <div className="flex items-center gap-2">
                <FileText className="w-4 h-4 text-primary" />
                <h2 className="text-sm font-semibold text-main">
                  {lang === "hi" ? "वैधानिक जोखिम निर्णय प्रारूप तैयार करें" : "Draft statutory risk decision"}
                </h2>
              </div>
              <button
                onClick={() => setIsNewModalOpen(false)}
                className="text-muted hover:text-main text-xs"
              >
                Cancel
              </button>
            </div>

            <form onSubmit={handleCreateDecision} className="space-y-4 text-xs">
              {formError && (
                <div className="p-3 rounded-control bg-status-critical/10 border border-status-critical text-status-critical">
                  {formError}
                </div>
              )}

              <div>
                <label className="block font-medium text-main mb-1">
                  {lang === "hi" ? "निर्णय का प्रकार" : "Decision type"}
                </label>
                <select
                  value={decisionType}
                  onChange={(e) => setDecisionType(e.target.value)}
                  className="w-full px-3 py-1.5 rounded-control border border-rule bg-app text-main focus:outline-none focus:ring-1 focus:ring-primary"
                >
                  <option value="Risk Acceptance">Risk Acceptance (जोखिम स्वीकृति)</option>
                  <option value="Regulatory Deferral">Regulatory Deferral (नियामक स्थगन)</option>
                  <option value="Control Compensating">Control Compensating (क्षतिपूरक नियंत्रण)</option>
                  <option value="Policy Exception">Policy Exception (नीतिगत अपवाद)</option>
                  <option value="ACCEPT">ACCEPT</option>
                  <option value="MITIGATE">MITIGATE</option>
                  <option value="TRANSFER">TRANSFER</option>
                  <option value="AVOID">AVOID</option>
                </select>
              </div>

              <div>
                <label className="block font-medium text-main mb-1">
                  {lang === "hi" ? "तर्क / औचित्य" : "Rationale"}
                </label>
                <textarea
                  rows={3}
                  value={rationale}
                  onChange={(e) => setRationale(e.target.value)}
                  placeholder="Mandatory justification for this risk decision..."
                  className="w-full px-3 py-1.5 rounded-control border border-rule bg-app text-main placeholder:text-muted focus:outline-none focus:ring-1 focus:ring-primary"
                  required
                />
              </div>

              <div>
                <label className="block font-medium text-main mb-1">
                  {lang === "hi" ? "क्षतिपूरक नियंत्रण" : "Compensating controls"}
                </label>
                <textarea
                  rows={2}
                  value={compensatingControls}
                  onChange={(e) => setCompensatingControls(e.target.value)}
                  placeholder="Required risk-mitigating controls during exception period..."
                  className="w-full px-3 py-1.5 rounded-control border border-rule bg-app text-main placeholder:text-muted focus:outline-none focus:ring-1 focus:ring-primary"
                  required
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block font-medium text-main mb-1">
                    {lang === "hi" ? "प्रभारी" : "Owner"}
                  </label>
                  <input
                    type="text"
                    value={owner}
                    onChange={(e) => setOwner(e.target.value)}
                    className="w-full px-3 py-1.5 rounded-control border border-rule bg-app text-main focus:outline-none focus:ring-1 focus:ring-primary"
                    required
                  />
                </div>
                <div>
                  <label className="block font-medium text-main mb-1">
                    {lang === "hi" ? "वैधता अवधि" : "Validity horizon"}
                  </label>
                  <select
                    value={expiryDays}
                    onChange={(e) => setExpiryDays(Number(e.target.value))}
                    className="w-full px-3 py-1.5 rounded-control border border-rule bg-app text-main focus:outline-none focus:ring-1 focus:ring-primary"
                  >
                    <option value={7}>7 days (Urgent deferral)</option>
                    <option value={30}>30 days (Standard exception)</option>
                    <option value={90}>90 days (Quarterly review cycle)</option>
                    <option value={180}>180 days (Semi-annual)</option>
                  </select>
                </div>
              </div>

              <div className="p-3 rounded-control bg-app border border-rule text-[11px] text-muted">
                <strong>Maker-checker notice:</strong> This decision will be saved with status <code>awaiting_countersignature</code>. A second authorized user must countersign before it becomes Active.
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-rule">
                <button
                  type="button"
                  onClick={() => setIsNewModalOpen(false)}
                  className="px-3 py-1.5 rounded-control border border-rule text-muted hover:text-main"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-4 py-1.5 rounded-control bg-primary text-primary-fg hover:bg-primary-hover font-medium disabled:opacity-50"
                >
                  {isSubmitting ? "Submitting..." : (lang === "hi" ? "प्रतिहस्ताक्षर हेतु प्रस्तुत करें" : "Submit for countersignature")}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Record New Para 59 Exception Modal */}
      {isNewExceptionModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4">
          <div className="bg-surface border border-rule rounded-segment max-w-lg w-full p-6 space-y-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-rule pb-3">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-status-due_soon" />
                <h2 className="text-sm font-semibold text-main">
                  {lang === "hi" ? "आरबीआई पैरा 59 अपवाद पंजीकृत करें" : "Record RBI Para 59 Exception"}
                </h2>
              </div>
              <button
                onClick={() => setIsNewExceptionModalOpen(false)}
                className="text-muted hover:text-main text-xs"
              >
                Cancel
              </button>
            </div>

            <form onSubmit={handleCreateException} className="space-y-4 text-xs">
              {formError && (
                <div className="p-3 rounded-control bg-status-critical/10 border border-status-critical text-status-critical">
                  {formError}
                </div>
              )}

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block font-medium text-main mb-1">Asset or Banking System</label>
                  <input
                    type="text"
                    value={assetOrSystem}
                    onChange={(e) => setAssetOrSystem(e.target.value)}
                    placeholder="e.g. Core Banking CBS-01"
                    className="w-full px-3 py-1.5 rounded-control border border-rule bg-app text-main focus:outline-none focus:ring-1 focus:ring-primary"
                    required
                  />
                </div>
                <div>
                  <label className="block font-medium text-main mb-1">Risk Level</label>
                  <select
                    value={excRiskLevel}
                    onChange={(e) => setExcRiskLevel(e.target.value)}
                    className="w-full px-3 py-1.5 rounded-control border border-rule bg-app text-main focus:outline-none focus:ring-1 focus:ring-primary"
                  >
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block font-medium text-main mb-1">Control Reference</label>
                <input
                  type="text"
                  value={controlRef}
                  onChange={(e) => setControlRef(e.target.value)}
                  className="w-full px-3 py-1.5 rounded-control border border-rule bg-app text-main focus:outline-none focus:ring-1 focus:ring-primary"
                  required
                />
              </div>

              <div>
                <label className="block font-medium text-main mb-1">Business Rationale</label>
                <textarea
                  rows={2}
                  value={excRationale}
                  onChange={(e) => setExcRationale(e.target.value)}
                  placeholder="Operational justification for technical control exception..."
                  className="w-full px-3 py-1.5 rounded-control border border-rule bg-app text-main placeholder:text-muted focus:outline-none focus:ring-1 focus:ring-primary"
                  required
                />
              </div>

              <div>
                <label className="block font-medium text-main mb-1">Compensating Controls</label>
                <textarea
                  rows={2}
                  value={excControls}
                  onChange={(e) => setExcControls(e.target.value)}
                  placeholder="Compensating technical & process controls..."
                  className="w-full px-3 py-1.5 rounded-control border border-rule bg-app text-main placeholder:text-muted focus:outline-none focus:ring-1 focus:ring-primary"
                  required
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block font-medium text-main mb-1">System Owner</label>
                  <input
                    type="text"
                    value={excOwner}
                    onChange={(e) => setExcOwner(e.target.value)}
                    className="w-full px-3 py-1.5 rounded-control border border-rule bg-app text-main focus:outline-none focus:ring-1 focus:ring-primary"
                    required
                  />
                </div>
                <div>
                  <label className="block font-medium text-main mb-1">Review Horizon</label>
                  <select
                    value={excExpiryDays}
                    onChange={(e) => setExcExpiryDays(Number(e.target.value))}
                    className="w-full px-3 py-1.5 rounded-control border border-rule bg-app text-main focus:outline-none focus:ring-1 focus:ring-primary"
                  >
                    <option value={30}>30 days</option>
                    <option value={90}>90 days (Quarterly Review)</option>
                    <option value={180}>180 days</option>
                  </select>
                </div>
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-rule">
                <button
                  type="button"
                  onClick={() => setIsNewExceptionModalOpen(false)}
                  className="px-3 py-1.5 rounded-control border border-rule text-muted hover:text-main"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmitting}
                  className="px-4 py-1.5 rounded-control bg-primary text-primary-fg hover:bg-primary-hover font-medium disabled:opacity-50"
                >
                  {isSubmitting ? "Recording..." : (lang === "hi" ? "अपवाद पंजीकृत करें" : "Register Exception")}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Countersignature Modal */}
      {countersignTarget && (
        <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4">
          <div className="bg-surface border border-rule rounded-segment max-w-md w-full p-6 space-y-4 shadow-xl">
            <div className="flex items-center justify-between border-b border-rule pb-3">
              <div className="flex items-center gap-2">
                <ShieldCheck className="w-4 h-4 text-primary" />
                <h2 className="text-sm font-semibold text-main">
                  Countersign {countersignTarget.decision_number}
                </h2>
              </div>
              <button
                onClick={() => setCountersignTarget(null)}
                className="text-muted hover:text-main text-xs"
              >
                Cancel
              </button>
            </div>

            <form onSubmit={handleCountersign} className="space-y-4 text-xs">
              {countersignError && (
                <div className="p-3 rounded-control bg-status-critical/10 border border-status-critical text-status-critical">
                  {countersignError}
                </div>
              )}

              <div className="p-3 rounded-control bg-app border border-rule space-y-1 text-muted text-[11px]">
                <div>Type: <strong className="text-main">{countersignTarget.decision_type}</strong></div>
                <div>Owner: <strong className="text-main">{countersignTarget.owner}</strong></div>
                <div>Rationale: <span className="text-main">{countersignTarget.rationale}</span></div>
                <div>Controls: <span className="text-main">{countersignTarget.compensating_controls}</span></div>
              </div>

              <div>
                <label className="block font-medium text-main mb-1">Countersignature review notes</label>
                <textarea
                  rows={3}
                  value={countersignNotes}
                  onChange={(e) => setCountersignNotes(e.target.value)}
                  placeholder="Record formal review comments and verification of compensating controls..."
                  className="w-full px-3 py-1.5 rounded-control border border-rule bg-app text-main placeholder:text-muted focus:outline-none focus:ring-1 focus:ring-primary"
                  required
                />
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-rule">
                <button
                  type="button"
                  onClick={() => setCountersignTarget(null)}
                  className="px-3 py-1.5 rounded-control border border-rule text-muted hover:text-main"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isCountersigning}
                  className="px-4 py-1.5 rounded-control bg-primary text-primary-fg hover:bg-primary-hover font-medium disabled:opacity-50"
                >
                  {isCountersigning ? "Countersigning..." : "Confirm countersignature"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
