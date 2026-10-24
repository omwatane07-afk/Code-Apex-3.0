import React, { useState, useEffect } from "react"
import { 
  ShieldCheck, 
  ShieldAlert, 
  Search, 
  ArrowLeft, 
  CheckCircle2, 
  XCircle, 
  Copy, 
  Check, 
  FileLock2, 
  Lock
} from "lucide-react"

interface AuditEventItem {
  id: string
  sequence_number: number
  timestamp: string
  prev_hash: string
  hash: string
  actor_id: string
  actor_role: string
  client_ip: string
  request_id: string
  action: string
  entity_type: string
  entity_id: string
  before_state: any
  after_state: any
}

interface VerifyResult {
  is_valid: boolean
  reason: string
  event_count: number
  checkpoint_count: number
  latest_hash: string | null
}

interface ActivityViewProps {
  userRole: string
  onBackToCommand: () => void
  isDemo?: boolean
  csrfToken?: string
}

export const ActivityView: React.FC<ActivityViewProps> = ({ userRole, onBackToCommand, isDemo = false, csrfToken }) => {
  const [events, setEvents] = useState<AuditEventItem[]>([])
  const [publicKey, setPublicKey] = useState<string>("")
  const [isLoading, setIsLoading] = useState<boolean>(true)
  const [error, setError] = useState<string | null>(null)
  const [searchTerm, setSearchTerm] = useState<string>("")
  const [isVerifying, setIsVerifying] = useState<boolean>(false)
  const [verifyResult, setVerifyResult] = useState<VerifyResult | null>(null)
  const [copiedHash, setCopiedHash] = useState<string | null>(null)

  const canReadEvents = ["ciso", "auditor", "model_validator"].includes(userRole)
  const canVerify = ["ciso", "auditor", "model_validator", "admin"].includes(userRole)

  const loadAuditExport = () => {
    if (!canReadEvents) {
      setIsLoading(false)
      return
    }

    setIsLoading(true)
    setError(null)

    fetch("/api/v1/audit/export")
      .then((res) => {
        if (!res.ok) {
          if (res.status === 403) {
            throw new Error("HTTP 403: Role not authorized to inspect audit chain.")
          }
          throw new Error(`Failed to load audit export: ${res.statusText}`)
        }
        return res.json()
      })
      .then((data) => {
        setEvents(data.events || [])
        setPublicKey(data.public_key || "")
        setIsLoading(false)
      })
      .catch((err) => {
        setError(err.message)
        setIsLoading(false)
      })
  }

  useEffect(() => {
    loadAuditExport()
  }, [userRole, canReadEvents, csrfToken])

  const handleVerifyChain = async () => {
    setIsVerifying(true)
    try {
      const res = await fetch("/api/v1/audit/verify")
      if (!res.ok) {
        throw new Error(`Verification endpoint returned HTTP ${res.status}`)
      }
      const data: VerifyResult = await res.json()
      setVerifyResult(data)
    } catch (err: any) {
      setVerifyResult({
        is_valid: false,
        reason: err.message,
        event_count: 0,
        checkpoint_count: 0,
        latest_hash: null,
      })
    } finally {
      setIsVerifying(false)
    }
  }

  const handleCopy = (text: string) => {
    navigator.clipboard?.writeText(text)
    setCopiedHash(text)
    setTimeout(() => setCopiedHash(null), 2000)
  }

  const filteredEvents = events.filter((e) => {
    const q = searchTerm.toLowerCase()
    return (
      e.action.toLowerCase().includes(q) ||
      e.actor_role.toLowerCase().includes(q) ||
      e.entity_type.toLowerCase().includes(q) ||
      e.hash.toLowerCase().includes(q)
    )
  })

  const formatTimestamp = (utcStr: string) => {
    try {
      const d = new Date(utcStr)
      return (
        d.toLocaleString("en-IN", {
          timeZone: "Asia/Kolkata",
          day: "2-digit",
          month: "short",
          year: "numeric",
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
        }) + " IST"
      )
    } catch {
      return utcStr
    }
  }

  return (
    <div className="flex-1 flex flex-col h-full bg-app overflow-hidden">
      {/* Top Header */}
      <div className="h-12 border-b border-rule bg-surface flex items-center justify-between px-6 flex-shrink-0">
        <div className="flex items-center gap-3">
          <button
            onClick={onBackToCommand}
            className="p-1.5 rounded-control text-muted hover:text-main hover:bg-app border border-rule flex items-center gap-1.5 text-xs"
            title="Return to Incident Command Center (g i)"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>Command Center</span>
          </button>
          <span className="text-muted text-xs">/</span>
          <div className="flex items-center gap-2">
            <FileLock2 className="w-4 h-4 text-primary" />
            <h1 className="text-sm font-semibold text-main">Tamper-evident activity ledger</h1>
          </div>
        </div>

        <div className="flex items-center gap-3 text-xs">
          <button
            onClick={handleVerifyChain}
            disabled={isVerifying || !canVerify}
            className="px-3 py-1.5 rounded-control bg-primary text-primary-fg hover:bg-primary-hover font-medium flex items-center gap-1.5 focus:outline-none focus:ring-2 focus:ring-primary disabled:opacity-50"
          >
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>{isVerifying ? "Verifying cryptographic chain..." : "Verify audit chain"}</span>
          </button>
        </div>
      </div>

      {/* Content Area */}
      <div className="flex-1 overflow-y-auto p-6 space-y-6">
        {/* Verification Summary Banner (if verified) */}
        {verifyResult && (
          <div
            className={`p-4 rounded-segment border ${
              verifyResult.is_valid
                ? "bg-status-ok/10 border-status-ok text-status-ok"
                : "bg-status-critical/10 border-status-critical text-status-critical"
            }`}
          >
            <div className="flex items-start justify-between">
              <div className="flex items-center gap-2.5">
                {verifyResult.is_valid ? (
                  <CheckCircle2 className="w-5 h-5 flex-shrink-0" />
                ) : (
                  <XCircle className="w-5 h-5 flex-shrink-0" />
                )}
                <div>
                  <h2 className="text-sm font-semibold">
                    {verifyResult.is_valid
                      ? "Cryptographic chain verified: Unbroken SHA-256 hash sequence"
                      : "Verification failed: Chain integrity anomaly detected"}
                  </h2>
                  <p className="text-xs opacity-90 mt-0.5">{verifyResult.reason}</p>
                </div>
              </div>
              <div className="text-right font-mono text-xs">
                <div>Events verified: {verifyResult.event_count}</div>
                <div>Checkpoints: {verifyResult.checkpoint_count}</div>
              </div>
            </div>
            {verifyResult.latest_hash && (
              <div className="mt-3 pt-3 border-t border-rule/50 text-[11px] font-mono flex items-center gap-2">
                <span className="text-muted">Latest root hash:</span>
                <span className="truncate">{verifyResult.latest_hash}</span>
              </div>
            )}
          </div>
        )}

        {/* Role Separation Notice for Analyst / Approver */}
        {!canVerify ? (
          <div className="p-6 rounded-segment border border-rule bg-surface text-center max-w-xl mx-auto my-12">
            <div className="w-10 h-10 rounded-full bg-status-info/10 text-status-info flex items-center justify-center mx-auto mb-3">
              <Lock className="w-5 h-5" />
            </div>
            <h2 className="text-base font-semibold text-main">Separation of duties enforcement</h2>
            <p className="text-xs text-muted mt-2 leading-relaxed">
              Separation of duties: your role cannot read the raw audit ledger. Permitted roles: Auditor, CISO, Model Validator.
            </p>
            <div className="mt-4 p-3 rounded-control bg-app border border-rule text-xs text-muted text-left">
              <div className="font-medium text-main mb-1">Permitted roles:</div>
              <ul className="list-disc list-inside space-y-0.5 font-mono text-[11px]">
                <li>Auditor (Read and verify)</li>
                <li>CISO (Read and verify)</li>
                <li>Model Validator (Read and verify)</li>
                <li>Admin (Verification probe)</li>
              </ul>
            </div>
            {isDemo && (
              <p className="text-[11px] text-muted mt-4">
                In demo environment, switch role in the top header to inspect the ledger.
              </p>
            )}
          </div>
        ) : !canReadEvents ? (
          <div className="p-6 rounded-segment border border-rule bg-surface text-center max-w-xl mx-auto my-12">
            <div className="w-10 h-10 rounded-full bg-primary/10 text-primary flex items-center justify-center mx-auto mb-3">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <h2 className="text-base font-semibold text-main">Administrative verification probe</h2>
            <p className="text-xs text-muted mt-2 leading-relaxed">
              You are authorized to execute cryptographic verification probes to validate audit chain integrity. Raw audit event narratives and actor activity logs are restricted to Auditor, CISO, and Model Validator.
            </p>
            <div className="mt-4 flex justify-center">
              <button
                onClick={handleVerifyChain}
                disabled={isVerifying}
                className="px-4 py-2 rounded-control bg-primary text-primary-fg hover:bg-primary-hover font-medium text-xs flex items-center gap-2"
              >
                <ShieldCheck className="w-4 h-4" />
                <span>{isVerifying ? "Verifying cryptographic chain..." : "Verify audit chain integrity"}</span>
              </button>
            </div>
          </div>
        ) : (
          <>
            {/* Filter and stats row */}
            <div className="flex items-center justify-between gap-4">
              <div className="relative flex-1 max-w-md">
                <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-muted pointer-events-none" />
                <input
                  type="text"
                  placeholder="Filter events by action, actor role, or entity..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full pl-9 pr-3 py-1.5 rounded-control border border-rule bg-surface text-xs text-main placeholder:text-muted focus:outline-none focus:ring-1 focus:ring-primary"
                />
              </div>

              <div className="text-xs text-muted font-mono flex items-center gap-4">
                <span>Total records: <strong className="text-main">{events.length}</strong></span>
                {publicKey && (
                  <span className="truncate max-w-xs" title={`Ed25519 Signer Key: ${publicKey}`}>
                    Signer: <strong className="text-main">{publicKey.slice(0, 12)}...</strong>
                  </span>
                )}
              </div>
            </div>

            {/* Error state */}
            {error && (
              <div className="p-4 rounded-segment border border-status-critical bg-status-critical/10 text-status-critical text-xs flex items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 flex-shrink-0" />
                  <span>{error}</span>
                </div>
                <button
                  onClick={loadAuditExport}
                  className="px-2.5 py-1 rounded bg-status-critical/20 hover:bg-status-critical/30 font-medium text-[11px] focus:outline-none"
                >
                  Retry
                </button>
              </div>
            )}

            {/* Loading state */}
            {isLoading && (
              <div className="p-12 text-center text-xs text-muted">
                Loading cryptographic audit chain...
              </div>
            )}

            {/* Events Table */}
            {!isLoading && !error && (
              <div className="border border-rule rounded-segment bg-surface overflow-hidden">
                <table className="w-full text-left text-xs" aria-label="Cryptographic audit event ledger">
                  <thead className="bg-app border-b border-rule font-medium text-muted">
                    <tr>
                      <th className="py-2.5 px-3 w-16 text-center">Seq</th>
                      <th className="py-2.5 px-3 w-44">Timestamp (IST)</th>
                      <th className="py-2.5 px-3 w-32">Actor</th>
                      <th className="py-2.5 px-3 w-40">Action</th>
                      <th className="py-2.5 px-3">Entity</th>
                      <th className="py-2.5 px-3 font-mono">SHA-256 Hash</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-rule font-sans">
                    {filteredEvents.length === 0 ? (
                      <tr>
                        <td colSpan={6} className="py-8 text-center text-muted">
                          {searchTerm ? "No audit events match search filter." : "No audit events recorded."}
                        </td>
                      </tr>
                    ) : (
                      filteredEvents.map((evt) => (
                        <tr key={evt.id} className="hover:bg-app/50 transition-colors">
                          <td className="py-2.5 px-3 text-center font-mono font-medium text-muted">
                            #{evt.sequence_number}
                          </td>
                          <td className="py-2.5 px-3 whitespace-nowrap text-muted font-mono text-[11px]" title={`UTC: ${evt.timestamp}`}>
                            {formatTimestamp(evt.timestamp)}
                          </td>
                          <td className="py-2.5 px-3">
                            <span className="inline-flex items-center px-1.5 py-0.5 rounded-segment border border-rule bg-app font-mono text-[10px]">
                              {evt.actor_role}
                            </span>
                          </td>
                          <td className="py-2.5 px-3 font-medium text-main">
                            {evt.action}
                          </td>
                          <td className="py-2.5 px-3 text-muted text-[11px] truncate max-w-xs">
                            <span className="font-mono text-main">{evt.entity_type}</span>: {evt.entity_id}
                          </td>
                          <td className="py-2.5 px-3 font-mono text-[11px] text-muted">
                            <div className="flex items-center gap-1.5">
                              <span className="truncate max-w-[140px]" title={evt.hash}>
                                {evt.hash.slice(0, 16)}...
                              </span>
                              <button
                                onClick={() => handleCopy(evt.hash)}
                                className="p-1 hover:text-main rounded hover:bg-app transition-colors"
                                title="Copy full SHA-256 hash"
                                aria-label="Copy hash"
                              >
                                {copiedHash === evt.hash ? (
                                  <Check className="w-3 h-3 text-status-ok" />
                                ) : (
                                  <Copy className="w-3 h-3" />
                                )}
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            )}

            {/* Offline Verification Notice */}
            <div className="p-4 rounded-segment border border-rule bg-surface/50 text-xs text-muted flex items-start gap-3">
              <FileLock2 className="w-4 h-4 text-primary mt-0.5 flex-shrink-0" />
              <div>
                <strong className="text-main">Air-gapped verification:</strong> RBI inspectors and IS auditors can verify this entire hash sequence offline without running the live CYBERQ application via:
                <pre className="mt-1.5 p-2 rounded-control bg-app border border-rule font-mono text-[11px] text-main">
                  python tools/verify-audit/verify.py --export audit_export.json --public-key {publicKey || "&lt;ed25519-key&gt;"}
                </pre>
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
