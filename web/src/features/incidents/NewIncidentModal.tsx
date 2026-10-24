import { useState, type FC, type FormEvent } from "react"
import { AlertCircle, X } from "lucide-react"

interface NewIncidentModalProps {
  isOpen: boolean
  onClose: () => void
  onSubmit: (title: string, summary: string, severity: string) => Promise<void>
}

export const NewIncidentModal: FC<NewIncidentModalProps> = ({ isOpen, onClose, onSubmit }) => {
  const [title, setTitle] = useState("")
  const [summary, setSummary] = useState("")
  const [severity, setSeverity] = useState("high")
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  if (!isOpen) return null

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

    try {
      setSubmitting(true)
      await onSubmit(title, summary, severity)
      setTitle("")
      setSummary("")
      onClose()
    } catch (err: any) {
      setError(err?.message || "Failed to create incident.")
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm p-4">
      <div className="w-full max-w-lg rounded-control bg-surface border border-rule shadow-xl text-main">
        <div className="flex items-center justify-between p-4 border-b border-rule">
          <h2 className="text-sm font-semibold">Report security incident</h2>
          <button onClick={onClose} className="text-muted hover:text-main">
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

          <div>
            <label className="block font-medium mb-1 text-muted">Incident title</label>
            <input
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="e.g. Core switch packet loss observed in DC-1"
              className="w-full px-3 py-2 rounded-control bg-app border border-rule focus:outline-none focus:ring-1 focus:ring-primary text-main"
            />
          </div>

          <div>
            <label className="block font-medium mb-1 text-muted">Severity level</label>
            <select
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
              className="w-full px-3 py-2 rounded-control bg-app border border-rule focus:outline-none focus:ring-1 focus:ring-primary text-main"
            >
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </div>

          <div>
            <label className="block font-medium mb-1 text-muted">
              Summary (Strictly no customer PII / account numbers)
            </label>
            <textarea
              rows={4}
              value={summary}
              onChange={(e) => setSummary(e.target.value)}
              placeholder="Technical summary of observed security anomaly..."
              className="w-full px-3 py-2 rounded-control bg-app border border-rule focus:outline-none focus:ring-1 focus:ring-primary text-main"
            />
            <span className="text-[11px] text-muted block mt-1">
              Protected by bank PII guard: Aadhaar, PAN, and payment cards are automatically blocked.
            </span>
          </div>

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
              className="px-3 py-1.5 rounded-control bg-primary text-primary-fg hover:bg-primary-hover font-medium disabled:opacity-50"
            >
              {submitting ? "Creating..." : "Create incident"}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
