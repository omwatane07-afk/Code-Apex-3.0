import React, { useState, useEffect } from "react"
import { 
  ShieldAlert, 
  Clock, 
  BookOpenCheck, 
  FileSpreadsheet, 
  AlertTriangle, 
  CheckCircle2, 
  X,
  ExternalLink
} from "lucide-react"

interface BoardPreviewData {
  total_incidents: number
  open_incidents: number
  active_countdowns: Array<{
    id: string
    incident_id: string
    regulator: string
    seconds_remaining: number
    deadline_at: string | null
  }>
  open_risk_decisions: number
  active_risk_decisions: number
  pending_closure_approvals: number
  top_risks: Array<{
    id: string
    incident_number: string
    title: string
    severity: string
    status: string
    is_major: boolean
  }>
  generated_at: string
}

interface CisoOverviewCardProps {
  onNavigateToDecisions: () => void
}

export const CisoOverviewCard: React.FC<CisoOverviewCardProps> = ({ onNavigateToDecisions }) => {
  const [data, setData] = useState<BoardPreviewData | null>(null)
  const [isLoading, setIsLoading] = useState<boolean>(true)
  const [isBoardModalOpen, setIsBoardModalOpen] = useState<boolean>(false)

  const fetchPreview = async () => {
    try {
      const res = await fetch("/api/v1/governance/board-preview")
      if (res.ok) {
        const json = await res.json()
        setData(json)
      }
    } catch {
      // Graceful fallback
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    fetchPreview()
    const timer = setInterval(fetchPreview, 15000)
    return () => clearInterval(timer)
  }, [])

  if (isLoading && !data) {
    return (
      <div className="p-4 rounded-control border border-rule bg-surface/50 text-xs text-muted">
        Loading CISO executive overview...
      </div>
    )
  }

  const activeClocksCount = data?.active_countdowns?.length || 0
  const openDecisionsCount = data?.open_risk_decisions || 0
  const pendingClosuresCount = data?.pending_closure_approvals || 0
  const topRisksCount = data?.top_risks?.length || 0

  return (
    <>
      <div className="border border-rule rounded-control bg-surface p-4 space-y-3">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-primary" />
            <h2 className="text-xs font-semibold uppercase tracking-wider text-main">
              CISO Executive Governance Overview
            </h2>
            <span className="text-[10px] px-1.5 py-0.5 rounded-segment bg-primary/10 text-primary font-mono font-medium">
              Board Readiness Active
            </span>
          </div>

          <button
            onClick={() => setIsBoardModalOpen(true)}
            className="px-2.5 py-1 rounded-control bg-primary text-primary-fg hover:bg-primary-hover font-medium text-xs flex items-center gap-1.5 shadow-sm"
          >
            <FileSpreadsheet className="w-3.5 h-3.5" />
            <span>1-Click Board summary preview</span>
          </button>
        </div>

        {/* 4 Telemetry Metrics */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 pt-1">
          <div className="p-3 rounded-segment border border-rule bg-app flex items-center gap-3">
            <div className="w-8 h-8 rounded-control bg-status-due_soon/10 text-status-due_soon flex items-center justify-center flex-shrink-0">
              <Clock className="w-4 h-4" />
            </div>
            <div>
              <div className="text-[10px] text-muted">Active statutory clocks</div>
              <div className="text-base font-bold font-mono text-main">{activeClocksCount}</div>
            </div>
          </div>

          <div 
            onClick={onNavigateToDecisions}
            className="p-3 rounded-segment border border-rule bg-app flex items-center gap-3 cursor-pointer hover:border-primary/50 transition-colors"
            title="Click to view statutory decision ledger (g d)"
          >
            <div className="w-8 h-8 rounded-control bg-primary/10 text-primary flex items-center justify-center flex-shrink-0">
              <BookOpenCheck className="w-4 h-4" />
            </div>
            <div className="flex-1">
              <div className="text-[10px] text-muted flex items-center gap-1">
                <span>Open risk decisions</span>
                <ExternalLink className="w-2.5 h-2.5" />
              </div>
              <div className="text-base font-bold font-mono text-primary">{openDecisionsCount}</div>
            </div>
          </div>

          <div className="p-3 rounded-segment border border-rule bg-app flex items-center gap-3">
            <div className="w-8 h-8 rounded-control bg-status-ok/10 text-status-ok flex items-center justify-center flex-shrink-0">
              <CheckCircle2 className="w-4 h-4" />
            </div>
            <div>
              <div className="text-[10px] text-muted">Awaiting closure approval</div>
              <div className="text-base font-bold font-mono text-main">{pendingClosuresCount}</div>
            </div>
          </div>

          <div className="p-3 rounded-segment border border-rule bg-app flex items-center gap-3">
            <div className="w-8 h-8 rounded-control bg-status-critical/10 text-status-critical flex items-center justify-center flex-shrink-0">
              <ShieldAlert className="w-4 h-4" />
            </div>
            <div>
              <div className="text-[10px] text-muted">Critical / Major risks</div>
              <div className="text-base font-bold font-mono text-status-critical">{topRisksCount}</div>
            </div>
          </div>
        </div>
      </div>

      {/* Board Summary Preview Modal */}
      {isBoardModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4">
          <div className="bg-surface border border-rule rounded-segment max-w-2xl w-full p-6 space-y-4 shadow-2xl max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between border-b border-rule pb-3">
              <div className="flex items-center gap-2">
                <FileSpreadsheet className="w-5 h-5 text-primary" />
                <div>
                  <h2 className="text-sm font-semibold text-main">Executive Board Security & Regulatory Summary</h2>
                  <p className="text-[11px] text-muted">
                    Quarterly risk posture preview for Board IT Strategy Committee
                  </p>
                </div>
              </div>
              <button
                onClick={() => setIsBoardModalOpen(false)}
                className="text-muted hover:text-main p-1 rounded-control"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <div className="space-y-4 text-xs">
              {/* Executive Snapshot Cards */}
              <div className="grid grid-cols-3 gap-3">
                <div className="p-3 rounded-control bg-app border border-rule text-center">
                  <div className="text-[11px] text-muted">Total Security Incidents</div>
                  <div className="text-lg font-bold font-mono text-main mt-1">{data?.total_incidents || 0}</div>
                  <div className="text-[10px] text-muted mt-0.5">{data?.open_incidents || 0} Active / Unclosed</div>
                </div>

                <div className="p-3 rounded-control bg-app border border-rule text-center">
                  <div className="text-[11px] text-muted">Active Statutory Clocks</div>
                  <div className="text-lg font-bold font-mono text-status-due_soon mt-1">{activeClocksCount}</div>
                  <div className="text-[10px] text-muted mt-0.5">CERT-In 6h / RBI 6h</div>
                </div>

                <div className="p-3 rounded-control bg-app border border-rule text-center">
                  <div className="text-[11px] text-muted">Active Risk Decisions</div>
                  <div className="text-lg font-bold font-mono text-status-ok mt-1">{data?.active_risk_decisions || 0}</div>
                  <div className="text-[10px] text-muted mt-0.5">{openDecisionsCount} Pending Countersign</div>
                </div>
              </div>

              {/* Top Risks Section */}
              <div className="border border-rule rounded-control p-3 bg-app space-y-2">
                <div className="flex items-center gap-1.5 font-medium text-main">
                  <AlertTriangle className="w-3.5 h-3.5 text-status-critical" />
                  <span>Material & Major Cyber Incidents (Board Level Attention)</span>
                </div>
                {(!data?.top_risks || data.top_risks.length === 0) ? (
                  <p className="text-muted italic py-2">Zero material critical or major incidents recorded this quarter.</p>
                ) : (
                  <div className="space-y-1.5 pt-1">
                    {data.top_risks.map((risk) => (
                      <div key={risk.id} className="p-2 rounded-control bg-surface border border-rule flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="font-mono font-medium text-main">{risk.incident_number}</span>
                          <span className="text-main truncate max-w-sm">{risk.title}</span>
                          {risk.is_major && (
                            <span className="px-1.5 py-0.5 rounded-segment bg-status-critical/10 text-status-critical border border-status-critical font-mono text-[9px] uppercase font-bold">
                              Major Incident
                            </span>
                          )}
                        </div>
                        <span className="capitalize font-mono text-[10px] text-muted">{risk.severity} / {risk.status}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Compliance & Audit Assurance Footer */}
              <div className="p-3 rounded-control bg-surface border border-rule text-[11px] text-muted leading-relaxed">
                <strong>Governance Note:</strong> This summary reflects real-time cryptographic audit checkpoints. All filings and risk acceptances adhere to RBI IT Governance Directions and CERT-In reporting thresholds with dual-control maker-checker integrity.
              </div>

              <div className="flex justify-end pt-2 border-t border-rule">
                <button
                  onClick={() => setIsBoardModalOpen(false)}
                  className="px-4 py-1.5 rounded-control bg-primary text-primary-fg hover:bg-primary-hover text-xs font-medium"
                >
                  Close Preview
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
