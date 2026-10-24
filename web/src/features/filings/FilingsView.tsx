import React, { useState, useEffect } from "react"
import { 
  FileCheck2, 
  ArrowLeft, 
  ShieldCheck, 
  Download, 
  AlertCircle, 
  FileText, 
  CheckCircle2, 
  Languages,
  Send,
  Lock
} from "lucide-react"

export interface FilingPacketSummary {
  id: string
  incident_id: string
  regulator: string
  version: number
  status: string
  packet_hash: string
  is_break_glass: boolean
  approved_by_id: string | null
  approved_at: string | null
  acknowledgement_ref: string | null
  created_at: string
}

interface FilingsViewProps {
  onBackToCommand: () => void
}

export const FilingsView: React.FC<FilingsViewProps> = ({ onBackToCommand }) => {
  const [lang, setLang] = useState<"en" | "hi">("en")
  const [packets, setPackets] = useState<FilingPacketSummary[]>([])
  const [isLoading, setIsLoading] = useState<boolean>(true)
  const [selectedIncidentId, setSelectedIncidentId] = useState<string>("")
  const [recordAckModal, setRecordAckModal] = useState<FilingPacketSummary | null>(null)
  const [ackRef, setAckRef] = useState<string>("")
  const [portalName, setPortalName] = useState<string>("RBI DAKSH")
  const [isSubmittingAck, setIsSubmittingAck] = useState<boolean>(false)
  const [ackError, setAckError] = useState<string | null>(null)

  const fetchPackets = async () => {
    setIsLoading(true)
    try {
      // Fetch prepared or approved packets if an incident is chosen or default query
      const url = selectedIncidentId 
        ? `/api/v1/filings?incident_id=${selectedIncidentId}`
        : `/api/v1/filings`
      const res = await fetch(url)
      if (res.ok) {
        const data = await res.json()
        setPackets(data)
      }
    } catch {
      // Graceful fallback for air-gapped demo
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    fetchPackets()
  }, [selectedIncidentId])

  const handleDownloadPdf = (packetId: string) => {
    window.open(`/api/v1/filings/${packetId}/pdf`, "_blank")
  }

  const handleRecordAcknowledgement = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!recordAckModal || !ackRef.trim()) return
    setIsSubmittingAck(true)
    setAckError(null)

    try {
      const res = await fetch(`/api/v1/filings/${recordAckModal.id}/filed`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          acknowledgement_ref: ackRef,
          portal_name: portalName,
        }),
      })

      if (!res.ok) {
        const err = await res.json().catch(() => ({}))
        throw new Error(err.detail || "Failed to record acknowledgement.")
      }

      setRecordAckModal(null)
      setAckRef("")
      fetchPackets()
    } catch (err: any) {
      setAckError(err.message)
    } finally {
      setIsSubmittingAck(false)
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
            title="Return to Incident Command Center"
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            <span>{lang === "hi" ? "कमांड सेंटर" : "Command Center"}</span>
          </button>
          <span className="text-muted text-xs">/</span>
          <div className="flex items-center gap-2">
            <FileCheck2 className="w-4 h-4 text-primary" />
            <h1 className="text-sm font-semibold text-main">
              {lang === "hi" ? "वैधानिक विनियामक फाइलिंग पैकेट" : "Regulatory Filing Packets"}
            </h1>
          </div>
        </div>

        <div className="flex items-center gap-2">
          {/* Language Toggle */}
          <button
            onClick={() => setLang(l => (l === "en" ? "hi" : "en"))}
            className="px-2.5 py-1 rounded-control border border-rule bg-surface text-main hover:bg-app flex items-center gap-1.5 text-xs font-medium"
            title="Toggle English / Hindi (Rajbhasha)"
          >
            <Languages className="w-3.5 h-3.5 text-primary" />
            <span>{lang === "en" ? "हिन्दी (HI)" : "English (EN)"}</span>
          </button>

          <span className="px-2 py-0.5 rounded-segment border border-status-ok text-status-ok bg-status-ok/10 text-xs font-mono font-medium">
            M3 / M4 Production Active
          </span>
        </div>
      </div>

      {/* Content Area */}
      <div className="flex-1 overflow-y-auto p-6 max-w-5xl mx-auto w-full space-y-6">
        <div className="p-6 rounded-segment border border-rule bg-surface space-y-4">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-control bg-primary/10 text-primary flex items-center justify-center flex-shrink-0">
              <FileCheck2 className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-base font-semibold text-main">
                {lang === "hi"
                  ? "विनियामक फाइलिंग पैकेट एवं निर्माता-जांचकर्ता प्रेषण"
                  : "Filing Packets & Maker-Checker Dispatch"}
              </h2>
              <p className="text-xs text-muted mt-0.5">
                {lang === "hi"
                  ? "भारतीय विनियामकों (CERT-In, RBI DAKSH, DPDP) हेतु बाइट-पुनरुत्पादक फाइलिंग संकलन।"
                  : "Byte-reproducible statutory filing packet compilation for Indian regulators (CERT-In, RBI DAKSH, DPDP)."}
              </p>
            </div>
          </div>

          <div className="text-xs text-muted leading-relaxed space-y-2 border-t border-rule pt-4">
            <p>
              {lang === "hi"
                ? "साइबरक्यू घटना ट्राइएज डेटा को विनियामक-विशिष्ट प्रारूपों में स्वचालित रूप से संकलित करता है तथा एयर-गैप्ड मानव सबमिशन को सख्ती से लागू करता है।"
                : "CYBERQ automatically packages incident triage data into regulator-specific statutory formats while strictly enforcing air-gapped human submission and maker-checker approval locks."}
            </p>
          </div>
        </div>

        {/* Non-Negotiable Bank Guardrail Alert */}
        <div className="p-4 rounded-segment border border-status-due_soon bg-status-due_soon/10 text-xs text-main space-y-1.5">
          <div className="flex items-center gap-2 font-semibold text-status-due_soon">
            <AlertCircle className="w-4 h-4 flex-shrink-0" />
            <span>
              {lang === "hi"
                ? "सख्त बैंक सुरक्षा नियम: विनियामक पोर्टलों पर कभी स्वचालित सबमिशन न करें"
                : "Strict Architectural Invariant: Never Auto-Submit to Regulator Portals"}
            </span>
          </div>
          <p className="text-muted leading-relaxed pl-6">
            {lang === "hi"
              ? "साइबरक्यू कभी भी CERT-In, RBI (DAKSH), या DPDP पोर्टलों पर आउटबाउंड API कॉल नहीं करता है। अधिकृत अनुपालन अधिकारी सत्यापित पैकेट डाउनलोड करते हैं, मैन्युअल रूप से अपलोड करते हैं, और वैधानिक घड़ी को रोकने के लिए पावती संदर्भ आईडी दर्ज करते हैं।"
              : "CYBERQ never makes outbound API calls to CERT-In, RBI (DAKSH), or DPDP portals. A designated human compliance officer downloads the verified filing packet, uploads it through the regulator's authenticated portal, and manually enters the official acknowledgement reference ID to stop the statutory clock."}
          </p>
        </div>

        {/* Regulator Filing Packets Specifications Grid */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-4 rounded-segment border border-rule bg-surface space-y-2.5">
            <div className="flex items-center gap-2 text-primary font-medium text-xs">
              <FileText className="w-4 h-4" />
              <span>{lang === "hi" ? "सर्ट-इन अनुलग्नक-1" : "CERT-In Annexure-1"}</span>
            </div>
            <div className="text-[11px] font-mono text-muted">
              {lang === "hi" ? "6-घंटे का प्रारंभिक सूचना पैकेट" : "6-Hour Initial Notice Packet"}
            </div>
            <p className="text-xs text-muted leading-relaxed">
              Standardized format covering incident type, affected systems, initial impact, and remediation steps per CERT-In Directions 2022.
            </p>
            <div className="pt-2 border-t border-rule flex items-center gap-1.5 text-[11px] text-muted">
              <CheckCircle2 className="w-3.5 h-3.5 text-status-ok" />
              <span>Byte-reproducible PDF & JSON</span>
            </div>
          </div>

          <div className="p-4 rounded-segment border border-rule bg-surface space-y-2.5">
            <div className="flex items-center gap-2 text-primary font-medium text-xs">
              <ShieldCheck className="w-4 h-4" />
              <span>{lang === "hi" ? "आरबीआई दक्ष रिपोर्ट (पैरा 182)" : "RBI DAKSH Report (Para 182)"}</span>
            </div>
            <div className="text-[11px] font-mono text-muted">
              {lang === "hi" ? "6-घंटे / 24-घंटे / 30-दिन की रिपोर्ट" : "6-Hour / 24-Hour / 30-Day"}
            </div>
            <p className="text-xs text-muted leading-relaxed">
              Commercial bank cybersecurity reporting schema compliant with RBI Master Directions and DAKSH supervisory filing guidelines.
            </p>
            <div className="pt-2 border-t border-rule flex items-center gap-1.5 text-[11px] text-muted">
              <CheckCircle2 className="w-3.5 h-3.5 text-status-ok" />
              <span>HSM-signed readiness attestation</span>
            </div>
          </div>

          <div className="p-4 rounded-segment border border-rule bg-surface space-y-2.5">
            <div className="flex items-center gap-2 text-primary font-medium text-xs">
              <Lock className="w-4 h-4" />
              <span>{lang === "hi" ? "डीपीडीपी डेटा उल्लंघन सूचना" : "DPDP Breach Notice"}</span>
            </div>
            <div className="text-[11px] font-mono text-muted">
              {lang === "hi" ? "72-घंटे डेटा उल्लंघन सूचना (नियम 7)" : "72-Hour Breach Notice (Rule 7)"}
            </div>
            <p className="text-xs text-muted leading-relaxed">
              Personal data breach intimation packet under DPDP Rules 2025. Strictly aggregate-only with zero raw customer PII.
            </p>
            <div className="pt-2 border-t border-rule flex items-center gap-1.5 text-[11px] text-muted">
              <CheckCircle2 className="w-3.5 h-3.5 text-status-ok" />
              <span>Rule 7 strict schema</span>
            </div>
          </div>
        </div>

        {/* Filing Packets Table / Activity */}
        <div className="border border-rule rounded-segment bg-surface overflow-hidden">
          <div className="p-3 bg-app border-b border-rule flex items-center justify-between">
            <h3 className="text-xs font-semibold text-main">
              {lang === "hi" ? "तैयार किए गए विनियामक पैकेट" : "Compiled Statutory Packets"}
            </h3>
            <div className="flex items-center gap-3">
              <input
                type="text"
                value={selectedIncidentId}
                onChange={(e) => setSelectedIncidentId(e.target.value)}
                placeholder="Filter by Incident ID..."
                className="px-2 py-1 rounded-control bg-surface border border-rule text-xs text-main placeholder:text-muted focus:outline-none"
              />
              <span className="text-[11px] text-muted font-mono">{packets.length} recorded</span>
            </div>
          </div>

          {isLoading ? (
            <div className="p-8 text-center text-xs text-muted">
              {lang === "hi" ? "पैकेट लोड हो रहे हैं..." : "Loading statutory filing packets..."}
            </div>
          ) : packets.length === 0 ? (
            <div className="p-8 text-center text-xs text-muted">
              {lang === "hi"
                ? "वर्तमान में कोई लंबित पैकेट नहीं है। घटना नियंत्रण कक्ष से पैकेट तैयार करें।"
                : "No statutory packets currently compiled for dispatch. Prepare filing packets from the active incident view."}
            </div>
          ) : (
            <table className="w-full text-left text-xs">
              <thead className="bg-app border-b border-rule font-medium text-muted">
                <tr>
                  <th className="py-2.5 px-3 w-32">Regulator</th>
                  <th className="py-2.5 px-3 w-20">Ver</th>
                  <th className="py-2.5 px-3 w-32">Status</th>
                  <th className="py-2.5 px-3">Packet Hash (SHA-256)</th>
                  <th className="py-2.5 px-3 w-40">Acknowledgement Ref</th>
                  <th className="py-2.5 px-3 w-28 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-rule">
                {packets.map((pkt) => (
                  <tr key={pkt.id} className="hover:bg-app/50 transition-colors">
                    <td className="py-2.5 px-3 font-semibold text-main">{pkt.regulator}</td>
                    <td className="py-2.5 px-3 font-mono text-muted">v{pkt.version}</td>
                    <td className="py-2.5 px-3">
                      <span className={`inline-flex px-1.5 py-0.5 rounded text-[10px] font-mono ${
                        pkt.status === "FILED"
                          ? "bg-status-ok/10 text-status-ok border border-status-ok"
                          : pkt.status === "APPROVED"
                          ? "bg-primary/10 text-primary border border-primary"
                          : "bg-surface border border-rule text-muted"
                      }`}>
                        {pkt.status}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[11px] text-muted truncate max-w-xs">
                      {pkt.packet_hash}
                    </td>
                    <td className="py-2.5 px-3 font-mono text-[11px] text-main">
                      {pkt.acknowledgement_ref || <span className="text-muted italic">Pending Portal Upload</span>}
                    </td>
                    <td className="py-2.5 px-3 text-right flex items-center justify-end gap-1.5">
                      <button
                        onClick={() => handleDownloadPdf(pkt.id)}
                        className="px-2 py-1 rounded bg-surface hover:bg-app border border-rule text-main text-[11px] flex items-center gap-1"
                        title="Download byte-reproducible statutory PDF"
                      >
                        <Download className="w-3 h-3 text-primary" />
                        <span>PDF</span>
                      </button>
                      {pkt.status !== "FILED" && (
                        <button
                          onClick={() => {
                            setRecordAckModal(pkt)
                            setAckRef("")
                            setAckError(null)
                          }}
                          className="px-2 py-1 rounded bg-primary text-primary-fg hover:bg-primary-hover text-[11px] flex items-center gap-1"
                          title="Record portal upload acknowledgement reference"
                        >
                          <Send className="w-3 h-3" />
                          <span>Record Ack</span>
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {/* Record Acknowledgement Reference Modal */}
      {recordAckModal && (
        <div className="fixed inset-0 z-50 bg-black/60 flex items-center justify-center p-4">
          <div className="bg-surface border border-rule rounded-segment max-w-md w-full p-6 space-y-4 shadow-xl text-xs">
            <div className="flex items-center justify-between border-b border-rule pb-3">
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-status-ok" />
                <h2 className="text-sm font-semibold text-main">Record Regulator Acknowledgement</h2>
              </div>
              <button
                onClick={() => setRecordAckModal(null)}
                className="text-muted hover:text-main"
              >
                Cancel
              </button>
            </div>

            <form onSubmit={handleRecordAcknowledgement} className="space-y-4">
              {ackError && (
                <div className="p-3 rounded-control bg-status-critical/10 border border-status-critical text-status-critical">
                  {ackError}
                </div>
              )}

              <p className="text-muted leading-relaxed">
                Enter the official acknowledgement reference receipt issued by <strong>{recordAckModal.regulator}</strong> upon manual portal submission.
              </p>

              <div>
                <label className="block font-medium text-main mb-1">Acknowledgement Reference ID</label>
                <input
                  type="text"
                  value={ackRef}
                  onChange={(e) => setAckRef(e.target.value)}
                  placeholder="e.g. CERTIN-INC-2026-9812 or DAKSH-ACK-77291"
                  className="w-full px-3 py-1.5 rounded-control border border-rule bg-app text-main focus:outline-none focus:ring-1 focus:ring-primary font-mono"
                  required
                />
              </div>

              <div>
                <label className="block font-medium text-main mb-1">Authenticated Portal Name</label>
                <input
                  type="text"
                  value={portalName}
                  onChange={(e) => setPortalName(e.target.value)}
                  className="w-full px-3 py-1.5 rounded-control border border-rule bg-app text-main focus:outline-none focus:ring-1 focus:ring-primary"
                  required
                />
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-rule">
                <button
                  type="button"
                  onClick={() => setRecordAckModal(null)}
                  className="px-3 py-1.5 rounded-control border border-rule text-muted hover:text-main"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={isSubmittingAck}
                  className="px-4 py-1.5 rounded-control bg-primary text-primary-fg hover:bg-primary-hover font-medium disabled:opacity-50"
                >
                  {isSubmittingAck ? "Recording..." : "Record Acknowledgement"}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
