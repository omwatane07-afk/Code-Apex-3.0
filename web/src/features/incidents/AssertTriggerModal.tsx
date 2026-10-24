import { useState, useEffect, useCallback, type FC, type FormEvent } from "react"
import { AlertCircle, Clock, X, Info, CheckCircle2, ShieldAlert } from "lucide-react"

interface AssertTriggerModalProps {
  isOpen: boolean
  onClose: () => void
  onSubmit: (
    triggerType: string,
    occurredAt: string,
    evidence: string,
    rationale: string,
    assertBothTriggers?: boolean,
    applicabilityAnswers?: {
      personal_data: "yes" | "no" | "not_sure"
      reportable_category: "yes" | "no" | "not_sure"
      rationale: string
    }
  ) => Promise<void>
}

interface PreviewItem {
  pack_id: string
  regulator: string
  trigger_event: string
  deadline_hours: number
  status: string
  deadline_at: string | null
  consequence_text: string
}

function formatToLocalInput(d: Date): string {
  const pad = (n: number) => String(n).padStart(2, "0")
  const year = d.getFullYear()
  const month = pad(d.getMonth() + 1)
  const day = pad(d.getDate())
  const hours = pad(d.getHours())
  const minutes = pad(d.getMinutes())
  return `${year}-${month}-${day}T${hours}:${minutes}`
}

function formatIst(utcIso: string | null): string {
  if (!utcIso) return "Not in force"
  try {
    const d = new Date(utcIso)
    return (
      new Intl.DateTimeFormat("en-IN", {
        timeZone: "Asia/Kolkata",
        day: "2-digit",
        month: "short",
        hour: "2-digit",
        minute: "2-digit",
      }).format(d) + " IST"
    )
  } catch {
    return utcIso
  }
}

export const AssertTriggerModal: FC<AssertTriggerModalProps> = ({ isOpen, onClose, onSubmit }) => {
  const [triggerType, setTriggerType] = useState("noticed")
  const [assertBoth, setAssertBoth] = useState(true)
  const [occurredAt, setOccurredAt] = useState(() => formatToLocalInput(new Date()))
  const [evidence, setEvidence] = useState("")
  const [rationale, setRationale] = useState("")
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  // Applicability diagnostics
  const [personalData, setPersonalData] = useState<"yes" | "no" | "not_sure">("not_sure")
  const [reportableCategory, setReportableCategory] = useState<"yes" | "no" | "not_sure">("not_sure")

  // Consequence preview
  const [previewItems, setPreviewItems] = useState<PreviewItem[]>([])
  const [previewLoading, setPreviewLoading] = useState(false)

  // PII detection check
  const [piiWarning, setPiiWarning] = useState<string | null>(null)
  const [overridePii, setOverridePii] = useState(false)

  // Relative time helper
  const setRelativeTime = (minutesAgo: number) => {
    const d = new Date(Date.now() - minutesAgo * 60000)
    setOccurredAt(formatToLocalInput(d))
  }

  // Soft PII pre-scan in evidence or rationale
  useEffect(() => {
    const text = `${evidence} ${rationale}`
    const aadhaarRegex = /(?<!\d)([2-9][0-9]{3}[\s\-._]*[0-9]{4}[\s\-._]*[0-9]{4})(?!\d)/
    const has12Digits = aadhaarRegex.test(text)
    if (has12Digits) {
      setPiiWarning(
        "Potential 12-digit Aadhaar number detected in text. Bank policy forbids personal data in statutory triggers. If this is a synthetic or technical identifier, confirm override below."
      )
    } else {
      setPiiWarning(null)
    }
  }, [evidence, rationale])

  // Fetch consequence preview from backend
  const fetchPreview = useCallback(async () => {
    if (!occurredAt) return
    setPreviewLoading(true)
    try {
      const utcIso = new Date(occurredAt).toISOString()
      const primaryTrigger = assertBoth ? "noticed" : triggerType

      const res = await fetch("/api/v1/incidents/preview-trigger", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          occurred_at: utcIso,
          trigger_type: primaryTrigger,
        }),
      })

      if (res.ok) {
        const data = await res.json()
        let items: PreviewItem[] = data.preview_items || []
        if (assertBoth) {
          const hasRbi = items.some((i) => i.regulator === "RBI")
          if (!hasRbi) {
            const rbiRes = await fetch("/api/v1/incidents/preview-trigger", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                occurred_at: utcIso,
                trigger_type: "detected",
              }),
            })
            if (rbiRes.ok) {
              const rbiData = await rbiRes.json()
              items = [...items, ...(rbiData.preview_items || [])]
            }
          }
        }
        setPreviewItems(items)
      } else {
        const occDate = new Date(utcIso).getTime()
        const fallbackItems: PreviewItem[] = []
        if (assertBoth || triggerType === "noticed") {
          fallbackItems.push({
            pack_id: "certin-directions-2022",
            regulator: "CERT-In",
            trigger_event: "noticed",
            deadline_hours: 6,
            status: "running",
            deadline_at: new Date(occDate + 6 * 3600000).toISOString(),
            consequence_text: "Asserting 'noticed' starts CERT-In 6h statutory clock.",
          })
        }
        if (assertBoth || triggerType === "detected") {
          fallbackItems.push({
            pack_id: "rbi-cybersecurity-directions-2026",
            regulator: "RBI",
            trigger_event: "detected",
            deadline_hours: 6,
            status: "running",
            deadline_at: new Date(occDate + 6 * 3600000).toISOString(),
            consequence_text: "Asserting 'detected' starts RBI 6h DAKSH clock.",
          })
        }
        if (!assertBoth && triggerType === "aware") {
          fallbackItems.push({
            pack_id: "dpdp-rules-2025",
            regulator: "DPDP",
            trigger_event: "aware",
            deadline_hours: 72,
            status: "running",
            deadline_at: new Date(occDate + 72 * 3600000).toISOString(),
            consequence_text: "Asserting 'aware' starts DPDP 72h Data Protection Board clock.",
          })
        }
        setPreviewItems(fallbackItems)
      }
    } catch {
      const occDate = new Date(occurredAt).getTime()
      setPreviewItems([
        {
          pack_id: "certin-directions-2022",
          regulator: "CERT-In",
          trigger_event: "noticed",
          deadline_hours: 6,
          status: "running",
          deadline_at: new Date(occDate + 6 * 3600000).toISOString(),
          consequence_text: "Asserting 'noticed' starts CERT-In 6h statutory clock.",
        },
      ])
    } finally {
      setPreviewLoading(false)
    }
  }, [occurredAt, triggerType, assertBoth])

  useEffect(() => {
    if (isOpen) {
      fetchPreview()
    }
  }, [isOpen, fetchPreview])

  if (!isOpen) return null

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault()
    setError(null)

    if (evidence.trim().length < 5) {
      setError("Evidence summary must be at least 5 characters.")
      return
    }
    if (rationale.trim().length < 5) {
      setError("Rationale must be at least 5 characters.")
      return
    }
    if (piiWarning && !overridePii) {
      setError("Please resolve the PII warning or check the audited override.")
      return
    }

    try {
      setSubmitting(true)
      const utcIso = new Date(occurredAt).toISOString()
      await onSubmit(
        assertBoth ? "noticed" : triggerType,
        utcIso,
        evidence,
        rationale,
        assertBoth,
        {
          personal_data: personalData,
          reportable_category: reportableCategory,
          rationale,
        }
      )
      setEvidence("")
      setRationale("")
      onClose()
    } catch (err: any) {
      setError(err?.message || "Failed to assert clock trigger.")
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm p-4 overflow-y-auto">
      <div className="w-full max-w-xl rounded-control bg-surface border border-rule shadow-xl text-main my-8">
        <div className="flex items-center justify-between p-4 border-b border-rule">
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4 text-primary" />
            <h2 className="text-sm font-semibold">Assert statutory clock trigger</h2>
          </div>
          <button onClick={onClose} className="text-muted hover:text-main" aria-label="Close modal">
            <X className="w-4 h-4" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-4 space-y-4 text-xs">
          {error && (
            <div className="p-2.5 rounded-segment border border-status-critical text-status-critical bg-app flex items-start gap-2">
              <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {/* Dual trigger option */}
          <div className="p-3 rounded-control border border-rule bg-app space-y-2">
            <label className="flex items-start gap-2 cursor-pointer">
              <input
                type="checkbox"
                checked={assertBoth}
                onChange={(e) => setAssertBoth(e.target.checked)}
                className="mt-0.5 rounded border-rule text-primary focus:ring-primary"
              />
              <div>
                <span className="font-semibold text-main block">
                  Simultaneous CERT-In & RBI DAKSH trigger (bank standard)
                </span>
                <span className="text-[11px] text-muted block mt-0.5">
                  Records both &lsquo;noticed&rsquo; (CERT-In) and &lsquo;detected&rsquo; (RBI) assertions at the same time. Default per Incident Commander SOP.
                </span>
              </div>
            </label>
          </div>

          {!assertBoth && (
            <div>
              <label className="block font-medium mb-1 text-muted">Statutory trigger type</label>
              <select
                value={triggerType}
                onChange={(e) => setTriggerType(e.target.value)}
                className="w-full px-3 py-2 rounded-control bg-app border border-rule focus:outline-none focus:ring-1 focus:ring-primary text-main"
              >
                <option value="noticed">Noticed (CERT-In 6-hour statutory clock)</option>
                <option value="detected">Detected (RBI Directions 2026 6-hour DAKSH clock)</option>
                <option value="aware">Aware (DPDP Rules 2025 72-hour Data Protection Board clock)</option>
              </select>
            </div>
          )}

          {/* Timestamp with quick relative pickers */}
          <div>
            <div className="flex items-center justify-between mb-1">
              <label className="block font-medium text-muted">
                Trigger occurred timestamp (IST / local)
              </label>
              <div className="flex items-center gap-1.5">
                <button
                  type="button"
                  onClick={() => setRelativeTime(0)}
                  className="px-2 py-0.5 rounded-segment border border-rule text-[11px] hover:bg-app text-muted hover:text-main"
                >
                  Just now
                </button>
                <button
                  type="button"
                  onClick={() => setRelativeTime(10)}
                  className="px-2 py-0.5 rounded-segment border border-rule text-[11px] hover:bg-app text-muted hover:text-main"
                >
                  10m ago
                </button>
                <button
                  type="button"
                  onClick={() => setRelativeTime(30)}
                  className="px-2 py-0.5 rounded-segment border border-rule text-[11px] hover:bg-app text-muted hover:text-main"
                >
                  30m ago
                </button>
                <button
                  type="button"
                  onClick={() => setRelativeTime(60)}
                  className="px-2 py-0.5 rounded-segment border border-rule text-[11px] hover:bg-app text-muted hover:text-main"
                >
                  1h ago
                </button>
              </div>
            </div>
            <input
              type="datetime-local"
              value={occurredAt}
              onChange={(e) => setOccurredAt(e.target.value)}
              className="w-full px-3 py-2 rounded-control bg-app border border-rule focus:outline-none focus:ring-1 focus:ring-primary text-main font-mono"
            />
            <span className="text-[11px] text-muted block mt-1">
              Stored in UTC, bound monotonically to statutory deadlines. Cannot be in the future.
            </span>
          </div>

          {/* Consequence preview box */}
          <div className="p-3 rounded-control border border-rule bg-app/60 space-y-2">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-1.5 text-xs font-semibold text-main">
                <Info className="w-3.5 h-3.5 text-primary" />
                <span>Statutory consequence preview (server calculated)</span>
              </div>
              {previewLoading && (
                <span className="text-[10px] text-muted animate-pulse">Calculating...</span>
              )}
            </div>

            <div className="space-y-1.5">
              {previewItems.map((item, idx) => (
                <div
                  key={idx}
                  className="p-2 rounded-segment border border-rule bg-surface flex items-center justify-between text-[11px]"
                >
                  <div>
                    <span className="font-semibold text-main mr-2">{item.regulator}</span>
                    <span className="text-muted">{item.consequence_text}</span>
                  </div>
                  <div className="text-right flex-shrink-0 font-mono font-medium text-primary">
                    {formatIst(item.deadline_at)}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Precautionary applicability questions */}
          <div className="p-3 rounded-control border border-rule bg-surface space-y-3">
            <span className="font-semibold text-main block text-xs">
              Obligation applicability diagnostics
            </span>

            <div>
              <span className="text-muted block mb-1.5 text-[11px]">
                1. Is personal data (customer or employee) involved?
              </span>
              <div className="flex gap-2">
                {(["yes", "no", "not_sure"] as const).map((opt) => (
                  <button
                    key={opt}
                    type="button"
                    onClick={() => setPersonalData(opt)}
                    className={`px-3 py-1 rounded-segment border text-[11px] capitalize ${
                      personalData === opt
                        ? "border-primary text-primary bg-app font-medium"
                        : "border-rule text-muted hover:text-main hover:bg-app"
                    }`}
                  >
                    {opt === "not_sure" ? "Not sure yet" : opt}
                  </button>
                ))}
              </div>
            </div>

            <div>
              <span className="text-muted block mb-1.5 text-[11px]">
                2. Is this incident in a reportable statutory category?
              </span>
              <div className="flex gap-2">
                {(["yes", "no", "not_sure"] as const).map((opt) => (
                  <button
                    key={opt}
                    type="button"
                    onClick={() => setReportableCategory(opt)}
                    className={`px-3 py-1 rounded-segment border text-[11px] capitalize ${
                      reportableCategory === opt
                        ? "border-primary text-primary bg-app font-medium"
                        : "border-rule text-muted hover:text-main hover:bg-app"
                    }`}
                  >
                    {opt === "not_sure" ? "Not sure yet" : opt}
                  </button>
                ))}
              </div>
            </div>

            {reportableCategory === "no" && (
              <div className="p-2.5 rounded-segment border border-status-due_soon bg-app text-status-due_soon text-[11px] flex items-start gap-2">
                <AlertCircle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />
                <span>
                  <strong>Precautionary rule:</strong> A &lsquo;No&rsquo; answer keeps the statutory clock running as &lsquo;pending approval&rsquo; until a compliance approver confirms exemption with a mandatory reason. SOC analysts cannot stop statutory clocks.
                </span>
              </div>
            )}
          </div>

          {/* Evidence summary */}
          <div>
            <label className="block font-medium mb-1 text-muted">Evidence summary</label>
            <textarea
              rows={2}
              value={evidence}
              onChange={(e) => setEvidence(e.target.value)}
              placeholder="e.g. SIEM correlation alert ID #89201 or SOC analyst ticket"
              className="w-full px-3 py-2 rounded-control bg-app border border-rule focus:outline-none focus:ring-1 focus:ring-primary text-main"
            />
          </div>

          {/* Rationale */}
          <div>
            <label className="block font-medium mb-1 text-muted">Rationale</label>
            <textarea
              rows={2}
              value={rationale}
              onChange={(e) => setRationale(e.target.value)}
              placeholder="Justification for statutory assertion..."
              className="w-full px-3 py-2 rounded-control bg-app border border-rule focus:outline-none focus:ring-1 focus:ring-primary text-main"
            />
          </div>

          {/* Soft PII warning with audited override */}
          {piiWarning && (
            <div className="p-3 rounded-control border border-status-due_soon bg-app space-y-2">
              <div className="flex items-start gap-2 text-status-due_soon text-[11px]">
                <ShieldAlert className="w-4 h-4 flex-shrink-0 mt-0.5" />
                <span>{piiWarning}</span>
              </div>
              <label className="flex items-center gap-2 cursor-pointer pt-1 text-[11px] text-main font-medium">
                <input
                  type="checkbox"
                  checked={overridePii}
                  onChange={(e) => setOverridePii(e.target.checked)}
                  className="rounded border-rule text-primary focus:ring-primary"
                />
                <span>Confirm this is not personal data (audited override)</span>
              </label>
            </div>
          )}

          <div className="flex justify-end gap-2 pt-3 border-t border-rule">
            <button
              type="button"
              onClick={onClose}
              className="px-3 py-1.5 rounded-control border border-rule hover:bg-app text-muted hover:text-main"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={submitting}
              className="px-3 py-1.5 rounded-control bg-primary text-primary-fg hover:bg-primary-hover font-medium disabled:opacity-50 flex items-center gap-1.5"
            >
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>{submitting ? "Asserting..." : "Assert trigger"}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
