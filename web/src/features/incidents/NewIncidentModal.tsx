import { useState, useEffect, useMemo, type FC, type FormEvent } from "react"
import { 
  AlertCircle, 
  X, 
  ShieldAlert, 
  Sparkles, 
  ShieldCheck, 
  CheckCircle2, 
  Lock,
  Info
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
}

export const NewIncidentModal: FC<NewIncidentModalProps> = ({ 
  isOpen, 
  onClose, 
  onSubmit,
  initialData 
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

  // Sync state whenever modal opens or initialData changes
  useEffect(() => {
    if (isOpen) {
      if (initialData) {
        setTitle(initialData.title || "")
        setSummary(initialData.summary || "")
        setSeverity(initialData.severity || "high")
      } else {
        setTitle("")
        setSummary("")
        setSeverity("high")
      }
      setError(null)
      setEnableOverride(false)
      setOverrideReason("")
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
      <div className="w-full max-w-xl rounded-control bg-surface border border-rule shadow-2xl text-main max-h-[92vh] flex flex-col overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-rule flex-shrink-0">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-primary" />
            <h2 className="text-sm font-semibold">Report statutory security incident</h2>
            {initialData && (
              <span className="text-[10px] font-mono font-medium px-2 py-0.5 rounded-segment bg-primary/10 text-primary border border-primary/20">
                Pre-filled from Alert
              </span>
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
                      Per RBI and DPDP invariants, customer account numbers and identities are strictly prohibited from persistence.
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
              <span className="text-[10px] text-muted flex items-center gap-1">
                <Lock className="w-3 h-3 text-status-ok" />
                <span>Protected by Verhoeff / Luhn PII Guard</span>
              </span>
            </div>
            <textarea
              rows={4}
              value={summary}
              onChange={(e) => setSummary(e.target.value)}
              placeholder="Technical summary of observed security anomaly, affected hosts, indicators of compromise..."
              className="w-full px-3 py-2 rounded-control bg-app border border-rule focus:outline-none focus:ring-1 focus:ring-primary text-main font-mono text-[11px]"
            />
            <div className="flex items-center justify-between mt-1 text-[11px] text-muted">
              <span>Aadhaar, PAN, and card numbers are monitored in real time.</span>
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
