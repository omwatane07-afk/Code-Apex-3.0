import { useState, useEffect, useMemo, type FC, type FormEvent } from "react"
import { 
  AlertCircle, 
  X, 
  ShieldAlert, 
  Sparkles, 
  ShieldCheck, 
  CheckCircle2, 
  Lock,
  Info,
  BrainCircuit,
  Wand2,
  RefreshCw,
  Cpu,
  ChevronDown,
  ChevronUp,
  Zap
} from "lucide-react"
import { scanForPII, redactPII, type DetectedPII } from "../../lib/piiGuard"

interface NewIncidentModalProps {
  isOpen: boolean
  onClose: () => void
  onSubmit: (
    title: string, 
    summary: string, 
    severity: string, 
    overridePii?: boolean, 
    overrideReason?: string
  ) => Promise<void>
  initialData?: {
    title?: string
    summary?: string
    severity?: string
  } | null
  csrfToken?: string
}

interface AIDraftMeta {
  model: string
  fallback: boolean
  mitre: string
  clauses: string[]
  reason?: string
}

export const NewIncidentModal: FC<NewIncidentModalProps> = ({ 
  isOpen, 
  onClose, 
  onSubmit,
  initialData,
  csrfToken
}) => {
  const [title, setTitle] = useState(initialData?.title || "")
  const [summary, setSummary] = useState(initialData?.summary || "")
  const [severity, setSeverity] = useState(initialData?.severity || "high")
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const [hasScrubbedNotice, setHasScrubbedNotice] = useState(false)
  
  // Audited override controls
  const [enableOverride, setEnableOverride] = useState(false)
  const [overrideReason, setOverrideReason] = useState("")

  // AI Incident Drafter controls
  const [aiPanelOpen, setAiPanelOpen] = useState(false)
  const [rawThreatInput, setRawThreatInput] = useState("")
  const [isGeneratingDraft, setIsGeneratingDraft] = useState(false)
  const [isRefiningSummary, setIsRefiningSummary] = useState(false)
  const [refineNotice, setRefineNotice] = useState<string | null>(null)
  const [aiDraftMeta, setAiDraftMeta] = useState<AIDraftMeta | null>(null)

  // Sync state whenever modal opens or initialData changes
  useEffect(() => {
    if (isOpen) {
      if (initialData) {
        setTitle(initialData.title || "")
        setSummary(initialData.summary || "")
        setSeverity(initialData.severity || "high")
        setAiPanelOpen(false)
      } else {
        setTitle("")
        setSummary("")
        setSeverity("high")
        setAiPanelOpen(false)
      }
      setError(null)
      setEnableOverride(false)
      setOverrideReason("")
      setRawThreatInput("")
      setAiDraftMeta(null)
      setRefineNotice(null)
    }
  }, [isOpen, initialData])

  // Real-time pre-flight PII scan
  const titleFindings = useMemo(() => scanForPII(title), [title])
  const summaryFindings = useMemo(() => scanForPII(summary), [summary])

  const allFindings = useMemo(() => {
    const map = new Map<string, DetectedPII>()
    for (const f of [...titleFindings, ...summaryFindings]) {
      map.set(f.match, f)
    }
    return Array.from(map.values())
  }, [titleFindings, summaryFindings])

  const hasDetectedPII = allFindings.length > 0

  if (!isOpen) return null

  // Instant 1-click pre-flight redaction
  const handleScrubNow = () => {
    setTitle(redactPII(title))
    setSummary(redactPII(summary))
    setEnableOverride(false)
    setOverrideReason("")
    setHasScrubbedNotice(true)
    setTimeout(() => setHasScrubbedNotice(false), 4000)
  }

  // AI Drafting & Synthesis Handler
  const handleGenerateAIDraft = async (overrideInput?: string) => {
    const isRefining = !!overrideInput && overrideInput === summary
    const textToDraft = overrideInput || rawThreatInput || summary
    if (!textToDraft || textToDraft.trim().length < 5) {
      setError("Please provide at least 5 characters of threat notes or raw telemetry for AI drafting.")
      return
    }

    setError(null)
    if (isRefining) {
      setIsRefiningSummary(true)
    } else {
      setIsGeneratingDraft(true)
    }

    // Pre-flight client scrub: ensure no customer PII leaves browser
    const sanitizedInput = redactPII(textToDraft)

    // 12-second client-side safety abort in case local Ollama is cold or lagging
    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), 12000)

    try {
      const headers: Record<string, string> = { "Content-Type": "application/json" }
      if (csrfToken) {
        headers["X-CSRF-Token"] = csrfToken
      }

      const response = await fetch("/api/v1/incidents/ai-draft", {
        method: "POST",
        headers,
        credentials: "include",
        signal: controller.signal,
        body: JSON.stringify({
          raw_input: sanitizedInput,
          source_tool: "SOC Console",
          affected_asset: "Core Banking Infrastructure",
        }),
      })

      clearTimeout(timeoutId)

      if (response.ok) {
        const data = await response.json()
        if (isRefining) {
          // Keep existing non-empty title when refining summary
          if (!title || title.trim().length < 5) {
            setTitle(data.suggested_title)
          }
        } else {
          setTitle(data.suggested_title)
        }
        setSummary(data.suggested_summary)
        if (data.recommended_severity) {
          setSeverity(data.recommended_severity)
        }
        setAiDraftMeta({
          model: data.model_used,
          fallback: data.fallback_mode,
          mitre: data.mitre_attack,
          clauses: data.statutory_applicability || [],
          reason: data.fallback_reason,
        })
        setRefineNotice(data.fallback_mode ? "Refined via Banking Heuristic Engine" : `Refined with ${data.model_used || "AI"}`)
        setTimeout(() => setRefineNotice(null), 3500)
        return
      }
      throw new Error(`HTTP ${response.status}`)
    } catch {
      clearTimeout(timeoutId)
      // Deterministic Client-Side Fallback if backend API is unreachable or times out
      // Strip previously added structured headers so repeated clicks do not accumulate duplicate blocks
      const cleanInput = sanitizedInput
        .replace(/Executive (?:Incident )?Overview:\s*/gi, "")
        .replace(/Technical Threat Telemetry:\s*/gi, "")
        .replace(/MITRE ATT&CK Classification:\s*/gi, "")
        .replace(/Statutory Reporting Assessment:\s*/gi, "")
        .replace(/Technique:\s*[^\n]+\n?/gi, "")
        .replace(/Window:\s*[^\n]+\n?/gi, "")
        .replace(/Applicable Directives:\s*[^\n]+\n?/gi, "")
        .trim()

      const lower = (cleanInput || sanitizedInput).toLowerCase()
      let draftSeverity = "high"
      let mitre = "T1059 - Command and Scripting Interpreter"
      let draftTitle = `[Security Anomaly] Suspicious activity detected on Core Network`
      let statutory = ["CERT-In Directions 2022 Section 70B Clause (ii): 6-Hour Mandatory Reporting Window"]

      if (lower.includes("lsass") || lower.includes("credential") || lower.includes("mimikatz")) {
        draftSeverity = "critical"
        mitre = "T1003.001 - OS Credential Dumping: LSASS Memory"
        draftTitle = "[EDR] Credential access and memory dumping detected on CBS host"
        statutory = ["CERT-In Directions 2022 Section 70B Annexure I (Item 9: Unauthorized access of IT systems/data)"]
      } else if (lower.includes("payment") || lower.includes("rtgs") || lower.includes("upi") || lower.includes("cbs")) {
        draftSeverity = "critical"
        mitre = "T1047 - WMI Execution / Payment Channel Manipulation"
        draftTitle = "[Switch] Telemetry anomaly impacting RTGS settlement channel"
        statutory = [
          "CERT-In Directions 2022 Section 70B Annexure I (Item 15: Attacks or incidents affecting Digital Payment systems)",
          "RBI Cybersecurity Framework Directions Para 182: Mandatory 6-Hour DAKSH Incident Intimation",
        ]
      } else if (lower.includes("ransomware") || lower.includes("encrypt") || lower.includes("vssadmin")) {
        draftSeverity = "critical"
        mitre = "T1486 - Data Encrypted for Impact"
        draftTitle = "[EDR] Ransomware activity and canary file encryption detected"
        statutory = [
          "CERT-In Directions 2022 Section 70B Annexure I (Item 11: Malicious code attacks such as Ransomware / Trojan / Virus)",
          "RBI Cybersecurity Framework Directions Para 182: Mandatory 6-Hour DAKSH Incident Intimation",
        ]
      }

      const draftSummary = 
`Executive Overview:
Automated security detection observed suspicious telemetry requiring expedited review.

Technical Threat Telemetry:
${cleanInput || sanitizedInput}

MITRE ATT&CK Classification:
Technique: ${mitre}

Statutory Reporting Assessment:
Window: ${draftSeverity === "critical" ? "6 Hours (Mandatory Initial Notice)" : "Statutory Verification"}
Applicable Directives: ${statutory.join(", ")}`

      if (isRefining) {
        if (!title || title.trim().length < 5) {
          setTitle(draftTitle)
        }
      } else {
        setTitle(draftTitle)
      }
      setSummary(draftSummary)
      setSeverity(draftSeverity)
      setAiDraftMeta({
        model: "Deterministic Banking Rule Engine (Client-Side Fallback)",
        fallback: true,
        mitre,
        clauses: statutory,
        reason: "Offline fallback mode engaged.",
      })
      setRefineNotice("Refined via Client-Side Heuristics")
      setTimeout(() => setRefineNotice(null), 3500)
    } finally {
      setIsGeneratingDraft(false)
      setIsRefiningSummary(false)
    }
  }

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setError(null)

    if (title.trim().length < 5) {
      setError("Title must be at least 5 characters.")
      return
    }
    if (summary.trim().length < 10) {
      setError("Summary must be at least 10 characters.")
      return
    }

    if (hasDetectedPII && enableOverride && overrideReason.trim().length < 5) {
      setError("An audited PII override requires a mandatory justification (minimum 5 characters).")
      return
    }

    // Determine final payload: if PII is detected and override is not active, automatically scrub
    let finalTitle = title
    let finalSummary = summary

    if (hasDetectedPII && !enableOverride) {
      finalTitle = redactPII(title)
      finalSummary = redactPII(summary)
    }

    try {
      setSubmitting(true)
      await onSubmit(
        finalTitle, 
        finalSummary, 
        severity, 
        hasDetectedPII ? enableOverride : false, 
        hasDetectedPII && enableOverride ? overrideReason.trim() : undefined
      )
      setTitle("")
      setSummary("")
      setEnableOverride(false)
      setOverrideReason("")
      onClose()
    } catch (err: any) {
      setError(err?.message || "Failed to create incident.")
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 backdrop-blur-sm p-4">
      <div className="w-full max-w-2xl rounded-control bg-surface border border-rule shadow-2xl text-main max-h-[92vh] flex flex-col overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-rule flex-shrink-0 bg-surface">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-primary" />
            <h2 className="text-sm font-semibold">Report statutory security incident</h2>
            {initialData ? (
              <span className="text-[10px] font-mono font-medium px-2 py-0.5 rounded-segment bg-primary/10 text-primary border border-primary/20">
                Pre-filled from Alert
              </span>
            ) : (
              <button
                type="button"
                onClick={() => setAiPanelOpen((prev) => !prev)}
                className="text-[11px] font-medium px-2.5 py-0.5 rounded-segment bg-primary/10 text-primary border border-primary/20 hover:bg-primary/20 flex items-center gap-1 transition-colors"
                title="Open local AI incident drafter"
              >
                <BrainCircuit className="w-3.5 h-3.5" />
                <span>AI Drafter</span>
                {aiPanelOpen ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
              </button>
            )}
          </div>
          <button 
            onClick={onClose} 
            className="text-muted hover:text-main p-1 rounded-segment hover:bg-app transition-colors"
            aria-label="Close dialog"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Scrollable Form Body */}
        <form onSubmit={handleSubmit} className="p-4 space-y-4 text-xs overflow-y-auto flex-1">
          {error && (
            <div className="p-2.5 rounded-segment border border-status-critical text-status-critical bg-status-critical/10 flex items-start gap-2">
              <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {hasScrubbedNotice && (
            <div className="p-2.5 rounded-segment border border-status-ok text-status-ok bg-status-ok/10 flex items-center gap-2 transition-all">
              <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
              <span>Personal data successfully redacted to statutory token placeholders.</span>
            </div>
          )}

          {/* Collapsible Local AI Incident Drafter Panel */}
          {aiPanelOpen && (
            <div className="p-3 rounded-control border border-primary/30 bg-primary/5 space-y-2.5">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Wand2 className="w-4 h-4 text-primary" />
                  <span className="font-semibold text-main text-xs">Local AI Incident Drafter (Air-Gapped)</span>
                </div>
                <span className="text-[10px] text-muted font-mono flex items-center gap-1">
                  <Cpu className="w-3 h-3 text-status-ok" />
                  <span>Zero Cloud Calls</span>
                </span>
              </div>

              <p className="text-[11px] text-muted">
                Paste raw SIEM logs, EDR alert telemetry, or rough notes. The local Qwen 2.5 Coder model (or deterministic fallback) will synthesize Title, Summary, and Severity.
              </p>

              <textarea
                rows={2}
                value={rawThreatInput}
                onChange={(e) => setRawThreatInput(e.target.value)}
                placeholder="e.g. CrowdStrike flagged lsass.exe memory dump attempt on CBS-PROD-APP01 by svchost.exe. Process terminated."
                className="w-full px-2.5 py-1.5 rounded-segment bg-app border border-rule focus:outline-none focus:ring-1 focus:ring-primary text-[11px] text-main font-mono"
              />

              {/* Sample Threat Chips */}
              <div className="flex flex-wrap items-center gap-1.5 text-[10px]">
                <span className="text-muted font-medium">Quick Scenarios:</span>
                <button
                  type="button"
                  onClick={() => {
                    const text = "CrowdStrike detected suspicious LSASS memory dump attempt by svchost.exe on CBS-PROD-APP01. Automated containment isolated host."
                    setRawThreatInput(text)
                    handleGenerateAIDraft(text)
                  }}
                  className="px-2 py-0.5 rounded-segment bg-app border border-rule hover:border-primary text-muted hover:text-main"
                >
                  CBS LSASS Memory Dump
                </button>
                <button
                  type="button"
                  onClick={() => {
                    const text = "Border switch BGP neighbor flapping causing intermittent packet loss on RTGS settlement channel. Queues diverted to DC-2 secondary link."
                    setRawThreatInput(text)
                    handleGenerateAIDraft(text)
                  }}
                  className="px-2 py-0.5 rounded-segment bg-app border border-rule hover:border-primary text-muted hover:text-main"
                >
                  RTGS Route Flap
                </button>
                <button
                  type="button"
                  onClick={() => {
                    const text = "Canary file encrypted in payment gateway staging share. Process executing vssadmin delete shadows command."
                    setRawThreatInput(text)
                    handleGenerateAIDraft(text)
                  }}
                  className="px-2 py-0.5 rounded-segment bg-app border border-rule hover:border-primary text-muted hover:text-main"
                >
                  Ransomware Canary
                </button>
              </div>

              <div className="flex items-center justify-end gap-2 pt-1">
                <button
                  type="button"
                  disabled={isGeneratingDraft}
                  onClick={() => handleGenerateAIDraft()}
                  className="px-3 py-1 rounded-control bg-primary text-primary-fg hover:bg-primary-hover font-medium text-xs flex items-center gap-1.5 disabled:opacity-50 transition-opacity"
                >
                  {isGeneratingDraft ? (
                    <>
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      <span>Synthesizing Draft...</span>
                    </>
                  ) : (
                    <>
                      <Sparkles className="w-3.5 h-3.5" />
                      <span>Generate Draft</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          )}

          {/* AI Draft Result Metadata Pill */}
          {aiDraftMeta && (
            <div className="p-2.5 rounded-control border border-rule bg-app flex flex-wrap items-center justify-between gap-2 text-[11px]">
              <div className="flex items-center gap-2">
                <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-segment text-[10px] font-mono font-medium ${
                  aiDraftMeta.fallback 
                    ? "bg-status-due_soon/10 text-status-due_soon border border-status-due_soon/30" 
                    : "bg-status-ok/10 text-status-ok border border-status-ok/30"
                }`}>
                  <Zap className="w-3 h-3" />
                  <span>{aiDraftMeta.model}</span>
                </span>
                <span className="text-muted font-mono text-[10px]">
                  MITRE: <strong className="text-main">{aiDraftMeta.mitre}</strong>
                </span>
              </div>
              <span className="text-muted text-[10px]">
                {aiDraftMeta.fallback ? "Fallback rule engine active" : "Local inference verified"}
              </span>
            </div>
          )}

          {/* Interactive Pre-Flight PII Soft-Guard Banner */}
          {hasDetectedPII && (
            <div className="p-3 rounded-control border border-status-due_soon/40 bg-status-due_soon/10 space-y-2.5">
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-start gap-2">
                  <ShieldAlert className="w-4 h-4 text-status-due_soon flex-shrink-0 mt-0.5" />
                  <div>
                    <span className="font-semibold text-status-due_soon block">
                      Customer PII detected in narrative ({allFindings.length} {allFindings.length === 1 ? "item" : "items"})
                    </span>
                    <span className="text-[11px] text-muted">
                      Per RBI and DPDP invariants, customer account numbers, PANs, and Aadhaar numbers are strictly prohibited from persistence.
                    </span>
                  </div>
                </div>

                <button
                  type="button"
                  onClick={handleScrubNow}
                  className="px-2.5 py-1 rounded-segment bg-status-due_soon text-black font-semibold text-[11px] hover:opacity-90 flex items-center gap-1.5 flex-shrink-0 transition-opacity"
                  title="Instantly replace all detected personal numbers with [REDACTED_...] tokens"
                >
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>Scrub PII</span>
                </button>
              </div>

              {/* Detected Items Pill Badges */}
              <div className="flex flex-wrap items-center gap-1.5 pt-1 border-t border-status-due_soon/20">
                <span className="text-[10px] text-muted font-medium">Detected entities:</span>
                {allFindings.map((f, idx) => (
                  <span 
                    key={idx}
                    className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded-segment bg-app border border-status-due_soon/40 text-[10px] font-mono text-main"
                  >
                    <span className="font-bold text-status-due_soon">{f.type}:</span>
                    <span>{f.maskedPreview}</span>
                  </span>
                ))}
              </div>

              {/* Audited Override Accordion */}
              <div className="pt-2 border-t border-status-due_soon/20">
                <label className="flex items-center gap-2 cursor-pointer select-none">
                  <input
                    type="checkbox"
                    checked={enableOverride}
                    onChange={(e) => setEnableOverride(e.target.checked)}
                    className="rounded border-rule text-primary focus:ring-primary"
                  />
                  <span className="text-[11px] text-main font-medium">
                    This is non-personal technical telemetry (Require audited override)
                  </span>
                </label>

                {enableOverride && (
                  <div className="mt-2 space-y-1 pl-5">
                    <input
                      type="text"
                      value={overrideReason}
                      onChange={(e) => setOverrideReason(e.target.value)}
                      placeholder="Mandatory justification (e.g. Device serial or network trace hash matching regex)"
                      className="w-full px-2.5 py-1.5 rounded-segment bg-app border border-rule focus:outline-none focus:ring-1 focus:ring-primary text-[11px] text-main"
                    />
                    <span className="text-[10px] text-muted block">
                      ⚠ This override will be recorded permanently in the tamper-evident audit hash chain.
                    </span>
                  </div>
                )}
              </div>
            </div>
          )}

          <div>
            <label className="block font-medium mb-1 text-muted">Incident title</label>
            <input
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="e.g. Core banking settlement queue latency spike observed"
              className="w-full px-3 py-2 rounded-control bg-app border border-rule focus:outline-none focus:ring-1 focus:ring-primary text-main"
            />
          </div>

          <div>
            <label className="block font-medium mb-1 text-muted">Initial severity classification</label>
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
              className="w-full px-3 py-2 rounded-control bg-app border border-rule focus:outline-none focus:ring-1 focus:ring-primary text-main"
            >
              <option value="low">Low (Routine perimeter drop / Non-critical anomaly)</option>
              <option value="medium">Medium (Internal policy deviation / Elevated probe)</option>
              <option value="high">High (Active lateral movement / Production system affected)</option>
              <option value="critical">Critical (Mandatory 6-Hour reporting: Core banking, SWIFT, Payment Switch)</option>
            </select>
          </div>

          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="block font-medium text-muted">
                Technical incident summary
              </label>
              <div className="flex items-center gap-2">
                {summary.trim().length > 10 && (
                  <button
                    type="button"
                    onClick={() => handleGenerateAIDraft(summary)}
                    disabled={isGeneratingDraft || isRefiningSummary}
                    className="text-[10px] text-primary hover:text-primary-hover flex items-center gap-1 font-medium transition-colors disabled:opacity-50"
                    title="Re-structure summary using local AI synthesis"
                  >
                    {isRefiningSummary ? (
                      <>
                        <RefreshCw className="w-3 h-3 animate-spin text-primary" />
                        <span>Refining...</span>
                      </>
                    ) : (
                      <>
                        <Wand2 className="w-3 h-3" />
                        <span>AI Refine</span>
                      </>
                    )}
                  </button>
                )}
                {refineNotice && (
                  <span className="text-[10px] text-status-ok flex items-center gap-1">
                    <CheckCircle2 className="w-3 h-3" />
                    <span>{refineNotice}</span>
                  </span>
                )}
                <span className="text-[10px] text-muted flex items-center gap-1">
                  <Lock className="w-3 h-3 text-status-ok" />
                  <span>Protected by Verhoeff / Luhn PII Guard</span>
                </span>
              </div>
            </div>
            <textarea
              rows={5}
              value={summary}
              onChange={(e) => setSummary(e.target.value)}
              placeholder="Technical summary of observed security anomaly, affected hosts, indicators of compromise..."
              className="w-full px-3 py-2 rounded-control bg-app border border-rule focus:outline-none focus:ring-1 focus:ring-primary text-main font-mono text-[11px]"
            />
            <div className="flex items-center justify-between mt-1 text-[11px] text-muted">
              <span>Aadhaar, PAN, Card, Account, Phone & Email are monitored in real time.</span>
              <span>{summary.length} characters</span>
            </div>
          </div>

          {/* Statutory Notice */}
          <div className="p-2.5 rounded-segment bg-app border border-rule flex items-start gap-2 text-muted text-[11px]">
            <Info className="w-3.5 h-3.5 flex-shrink-0 mt-0.5 text-primary" />
            <span>
              Submission will start statutory clock evaluation (CERT-In 6h, RBI DAKSH, DPDP 72h) and write a genesis event to the immutable decision ledger.
            </span>
          </div>

          {/* Footer Actions */}
          <div className="flex justify-end gap-2 pt-3 border-t border-rule">
            <button
              type="button"
              onClick={onClose}
              className="px-3 py-1.5 rounded-control border border-rule hover:bg-app text-muted hover:text-main transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="px-4 py-1.5 rounded-control bg-primary text-primary-fg hover:bg-primary-hover font-medium disabled:opacity-50 flex items-center gap-1.5 transition-colors"
            >
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>{submitting ? "Securing & Creating..." : "Create incident"}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
