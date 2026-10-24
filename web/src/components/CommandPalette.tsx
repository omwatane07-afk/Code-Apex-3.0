import React, { useState, useEffect } from "react"
import { Search, Plus, Clock, LayoutGrid, FileText, X, Activity, BookOpenCheck, FileCheck2, Sliders, ShieldCheck, Flame, Radio } from "lucide-react"

interface CommandPaletteProps {
  isOpen: boolean
  onClose: () => void
  onNavigateIncidents: () => void
  onNavigateWallboard: () => void
  onNavigateActivity?: () => void
  onNavigateDecisions?: () => void
  onNavigateFilings?: () => void
  onNavigateAdmin?: () => void
  onNavigateVerification?: () => void
  onOpenNewIncident: () => void
  onOpenAssertTrigger: () => void
  onOpenHandover: () => void
  onOpenTelemetry?: () => void
  onSimulateAnomaly?: () => void
  userRole?: string
}

export const CommandPalette: React.FC<CommandPaletteProps> = ({
  isOpen,
  onClose,
  onNavigateIncidents,
  onNavigateWallboard,
  onNavigateActivity,
  onNavigateDecisions,
  onNavigateFilings,
  onNavigateAdmin,
  onNavigateVerification,
  onOpenNewIncident,
  onOpenAssertTrigger,
  onOpenHandover,
  onOpenTelemetry,
  onSimulateAnomaly,
  userRole = "analyst",
}) => {
  const [query, setQuery] = useState("")

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement
      const inInput =
        target.tagName === "INPUT" ||
        target.tagName === "TEXTAREA" ||
        target.isContentEditable

      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault()
        if (isOpen) onClose()
        else setQuery("")
      }

      if (!inInput && !isOpen) {
        if (e.key === "n") {
          e.preventDefault()
          onOpenNewIncident()
        }
        if (e.key === "a") {
          e.preventDefault()
          onOpenAssertTrigger()
        }
      }

      if (e.key === "Escape" && isOpen) {
        onClose()
      }
    }

    window.addEventListener("keydown", handleKeyDown)
    return () => window.removeEventListener("keydown", handleKeyDown)
  }, [isOpen, onClose, onOpenNewIncident, onOpenAssertTrigger])

  if (!isOpen) return null

  const commands = [
    {
      id: "nav-incidents",
      title: "Go to active incidents",
      shortcut: "g i",
      icon: <LayoutGrid className="w-4 h-4 text-primary" />,
      action: () => {
        onNavigateIncidents()
        onClose()
      },
    },
    {
      id: "nav-wallboard",
      title: "Go to wallboard display",
      shortcut: "g w",
      icon: <Clock className="w-4 h-4 text-status-ok" />,
      action: () => {
        onNavigateWallboard()
        onClose()
      },
    },
    ...(onNavigateActivity
      ? [
          {
            id: "nav-activity",
            title: "Go to activity & audit chain",
            shortcut: "g a",
            icon: <Activity className="w-4 h-4 text-primary" />,
            action: () => {
              onNavigateActivity()
              onClose()
            },
          },
        ]
      : []),
    ...(onNavigateDecisions
      ? [
          {
            id: "nav-decisions",
            title: "Go to statutory decision ledger (M4)",
            shortcut: "g d",
            icon: <BookOpenCheck className="w-4 h-4 text-primary" />,
            action: () => {
              onNavigateDecisions()
              onClose()
            },
          },
        ]
      : []),
    ...(onNavigateFilings
      ? [
          {
            id: "nav-filings",
            title: "Go to regulatory filing packets (M3)",
            shortcut: "g f",
            icon: <FileCheck2 className="w-4 h-4 text-primary" />,
            action: () => {
              onNavigateFilings()
              onClose()
            },
          },
        ]
      : []),
    ...(onNavigateAdmin
      ? [
          {
            id: "nav-admin",
            title: "Go to system administration & telemetry",
            shortcut: "g m",
            icon: <Sliders className="w-4 h-4 text-primary" />,
            action: () => {
              onNavigateAdmin()
              onClose()
            },
          },
        ]
      : []),
    ...(onNavigateVerification
      ? [
          {
            id: "nav-verification",
            title: "Go to multi-agent verification & intake passports (M2)",
            shortcut: "g v",
            icon: <ShieldCheck className="w-4 h-4 text-primary" />,
            action: () => {
              onNavigateVerification()
              onClose()
            },
          },
        ]
      : []),
    ...(onOpenTelemetry
      ? [
          {
            id: "act-telemetry",
            title: "Open live cybersecurity telemetry monitor & simulator",
            shortcut: "g t",
            icon: <Radio className="w-4 h-4 text-status-ok" />,
            action: () => {
              onOpenTelemetry()
              onClose()
            },
          },
        ]
      : []),
    ...(onSimulateAnomaly
      ? [
          {
            id: "act-simulate-anomaly",
            title: "Simulate live cybersecurity threat anomaly (trigger alert)",
            shortcut: "s a",
            icon: <Flame className="w-4 h-4 text-status-critical" />,
            action: () => {
              onSimulateAnomaly()
              onClose()
            },
          },
        ]
      : []),
    {
      id: "nav-handover",
      title: "Go to shift handover briefing",
      shortcut: "g s",
      icon: <FileText className="w-4 h-4 text-status-due_soon" />,
      action: () => {
        onOpenHandover()
        onClose()
      },
    },
    {
      id: "act-new",
      title: "Create new incident",
      shortcut: "n",
      icon: <Plus className="w-4 h-4 text-primary" />,
      action: () => {
        onOpenNewIncident()
        onClose()
      },
    },
    {
      id: "act-assert",
      title: "Assert clock trigger on selected incident",
      shortcut: "a",
      icon: <Clock className="w-4 h-4 text-status-critical" />,
      action: () => {
        onOpenAssertTrigger()
        onClose()
      },
    },
  ]

  const filtered = commands.filter((c) =>
    c.title.toLowerCase().includes(query.toLowerCase())
  )

  return (
    <div className="fixed inset-0 z-50 bg-black/60 flex items-start justify-center pt-20 p-4">
      <div className="bg-surface border border-rule rounded-segment max-w-lg w-full shadow-2xl overflow-hidden flex flex-col">
        {/* Search Input */}
        <div className="p-3 border-b border-rule flex items-center gap-2.5">
          <Search className="w-4 h-4 text-muted" />
          <input
            autoFocus
            type="text"
            placeholder="Search commands, navigation, or shortcuts... (Esc to exit)"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Escape") {
                e.preventDefault()
                onClose()
              }
            }}
            className="flex-1 bg-transparent text-xs text-main focus:outline-none"
          />
          <button onClick={onClose} className="text-muted hover:text-main">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Command List */}
        <div className="p-2 max-h-80 overflow-y-auto divide-y divide-rule text-xs">
          {filtered.length === 0 ? (
            <div className="p-4 text-center text-muted">No commands found matching "{query}"</div>
          ) : (
            filtered.map((cmd) => (
              <button
                key={cmd.id}
                onClick={cmd.action}
                className="w-full p-2.5 flex items-center justify-between text-left hover:bg-app rounded-control group transition-colors"
              >
                <div className="flex items-center gap-2.5">
                  {cmd.icon}
                  <span className="font-medium text-main group-hover:text-primary">
                    {cmd.title}
                  </span>
                </div>
                <kbd className="px-1.5 py-0.5 rounded border border-rule text-[10px] text-muted font-mono bg-surface">
                  {cmd.shortcut}
                </kbd>
              </button>
            ))
          )}
        </div>

        {/* Footer with Role */}
        <div className="px-3 py-2 border-t border-rule bg-app/50 flex items-center justify-between text-[11px] text-muted">
          <span>Active role: <strong className="text-main font-mono capitalize">{userRole}</strong></span>
          <span>Press <kbd className="font-mono">Esc</kbd> to exit</span>
        </div>
      </div>
    </div>
  )
}
