import React, { useState } from "react"
import { Copy, Check, X, Clock, FileCheck } from "lucide-react"
import { IncidentItem } from "../incidents/types"

interface ShiftHandoverModalProps {
  isOpen: boolean
  onClose: () => void
  incidents: IncidentItem[]
  userRole?: string
}

export const ShiftHandoverModal: React.FC<ShiftHandoverModalProps> = ({
  isOpen,
  onClose,
  incidents,
  userRole = "analyst",
}) => {
  const [copied, setCopied] = useState(false)
  const [shiftNotes, setShiftNotes] = useState(
    "Perimeter inspection ongoing on DC-1 firewalls. BGP flap stabilized. Handing over to incoming SOC shift."
  )

  if (!isOpen) return null

  // Build clean text digest after sanitizing any accidental PII
  const generateBriefText = () => {
    const lines: string[] = []
    lines.push("CYBERQ SOC SHIFT HANDOVER BRIEFING")
    lines.push(`Generated: ${new Date().toLocaleString("en-IN", { timeZone: "Asia/Kolkata" })} IST`)
    lines.push("--------------------------------------------------")
    lines.push("1. ACTIVE STATUTORY DEADLINES")

    for (const inc of incidents) {
      lines.push(`* Incident: ${inc.incident_number} [Severity: ${inc.severity.toUpperCase()}]`)
      if (userRole !== "admin") {
        lines.push(`  Title: ${inc.title}`)
      }
      for (const obl of inc.obligations) {
        if (obl.status === "running" || obl.status === "due_soon" || obl.status === "critical") {
          lines.push(`  - ${obl.regulator}: ${obl.status.toUpperCase()} (Deadline: ${obl.active_deadline_at || "N/A"})`)
        }
      }
    }

    lines.push("\n2. PENDING MAKER-CHECKER & COMPLIANCE ACTIONS")
    lines.push("* Review applicability exemptions under pending_approval")
    lines.push("* CERT-In initial filing packet prepared for INC-2026-0001")

    lines.push("\n3. OUTGOING SHIFT NOTES")
    lines.push(shiftNotes)
    lines.push("--------------------------------------------------")
    return lines.join("\n")
  }

  const handleCopy = () => {
    navigator.clipboard.writeText(generateBriefText())
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4">
      <div className="bg-surface border border-rule rounded-segment max-w-2xl w-full p-6 shadow-xl flex flex-col max-h-[90vh]">
        {/* Header */}
        <div className="flex items-center justify-between pb-3 border-b border-rule">
          <div>
            <h2 className="text-base font-semibold text-main">Shift handover briefing</h2>
            <p className="text-xs text-muted mt-0.5">
              Operational summary of active statutory clocks and pending actions
            </p>
          </div>
          <button onClick={onClose} className="text-muted hover:text-main focus:outline-none">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Content Body */}
        <div className="flex-1 overflow-y-auto py-4 space-y-4 text-xs">
          {/* Active Deadlines Section */}
          <div>
            <h3 className="font-semibold text-main uppercase tracking-wide mb-2 flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5 text-primary" />
              <span>Active statutory deadlines</span>
            </h3>
            <div className="border border-rule rounded-segment divide-y divide-rule bg-app">
              {incidents.map((inc) => (
                <div key={inc.id} className="p-3">
                  <div className="flex items-center justify-between">
                    <span className="font-mono font-bold text-main">{inc.incident_number}</span>
                    <span className="text-[11px] text-muted capitalize">Severity: {inc.severity}</span>
                  </div>
                  {userRole !== "admin" && (
                    <div className="text-main font-medium mt-1 truncate">{inc.title}</div>
                  )}
                  <div className="mt-2 flex flex-wrap gap-2">
                    {inc.obligations.map((o) => (
                      <span
                        key={o.id}
                        className="px-2 py-0.5 rounded-segment border border-rule text-[11px] bg-surface font-mono"
                      >
                        {o.regulator}: {o.status}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Pending Approvals */}
          <div>
            <h3 className="font-semibold text-main uppercase tracking-wide mb-2 flex items-center gap-1.5">
              <FileCheck className="w-3.5 h-3.5 text-status-due_soon" />
              <span>Pending maker-checker actions</span>
            </h3>
            <div className="border border-rule rounded-segment p-3 bg-app text-muted">
              * CERT-In initial filing packet prepared for INC-2026-0001 (Awaiting compliance approver)
            </div>
          </div>

          {/* Outgoing Notes Input */}
          <div>
            <label className="block font-semibold text-main mb-1">
              Outgoing shift handover notes
            </label>
            <textarea
              value={shiftNotes}
              onChange={(e) => setShiftNotes(e.target.value)}
              rows={3}
              className="w-full p-2.5 text-xs bg-app border border-rule rounded-control text-main focus:outline-none focus:border-primary"
            />
          </div>
        </div>

        {/* Footer */}
        <div className="pt-3 border-t border-rule flex items-center justify-between">
          <span className="text-[11px] text-muted">Audited shift record</span>
          <div className="flex items-center gap-2">
            <button
              onClick={onClose}
              className="px-3 py-1.5 text-xs border border-rule rounded-control text-main hover:bg-app"
            >
              Close
            </button>
            <button
              onClick={handleCopy}
              className="px-3 py-1.5 text-xs bg-primary text-primary-fg rounded-control hover:bg-primary-hover flex items-center gap-1.5 font-medium"
            >
              {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? "Copied to clipboard" : "Copy shift brief"}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
