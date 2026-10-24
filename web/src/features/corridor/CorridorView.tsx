import React, { useState, useEffect, lazy, Suspense } from "react"
import { FastForward } from "lucide-react"
import { ClockViewModel, ObligationItem, buildViewModels } from "./ClockViewModel"

const CorridorCanvas = lazy(() =>
  import("./CorridorCanvas").then((m) => ({ default: m.CorridorCanvas }))
)

interface CorridorViewProps {
  obligations: ObligationItem[]
  isDemo?: boolean
  theme?: "light" | "dark"
  onSelectObligation?: (obligationId: string) => void
}

export const CorridorView: React.FC<CorridorViewProps> = ({
  obligations,
  isDemo = true,
  theme = "dark",
  onSelectObligation,
}) => {
  // Check responsive & hardware defaults
  const shouldDefault2D = () => {
    if (typeof window === "undefined") return true
    if (window.innerWidth < 768) return true
    if (window.matchMedia("(pointer: coarse)").matches) return true
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return true
    return false
  }

  const [viewMode, setViewMode] = useState<"2d" | "3d">(() => {
    if (shouldDefault2D()) return "2d"
    return "3d"
  })

  const [cameraPreset, setCameraPreset] = useState<1 | 2 | 3>(1)
  const [selectedLane, setSelectedLane] = useState<number>(0)
  const [simSpeed, setSimSpeed] = useState<number>(1)
  const [viewModels, setViewModels] = useState<ClockViewModel[]>(() =>
    buildViewModels(obligations)
  )

  // Update viewModels once per second
  useEffect(() => {
    const timer = setInterval(() => {
      setViewModels(buildViewModels(obligations))
    }, 1000)
    return () => clearInterval(timer)
  }, [obligations])

  // View mode toggle
  const toggleViewMode = (mode: "2d" | "3d") => {
    setViewMode(mode)
  }

  // Keyboard shortcut listeners for camera presets (1, 2, 3) - inert when typing in inputs
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const target = e.target as HTMLElement
      if (
        target.tagName === "INPUT" ||
        target.tagName === "TEXTAREA" ||
        target.isContentEditable
      ) {
        return
      }
      if (e.key === "1") setCameraPreset(1)
      if (e.key === "2") setCameraPreset(2)
      if (e.key === "3") setCameraPreset(3)
    }
    window.addEventListener("keydown", handleKeyDown)
    return () => window.removeEventListener("keydown", handleKeyDown)
  }, [])

  return (
    <div className="flex flex-col border border-rule rounded-segment bg-surface overflow-hidden my-3">
      {/* Corridor Header and Controls Bar */}
      <div className="px-4 py-2.5 bg-app border-b border-rule flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <span className="text-xs font-semibold text-main tracking-tight">
            Situational runway
          </span>
          <div className="flex items-center rounded-control border border-rule bg-surface p-0.5 text-xs">
            <button
              onClick={() => toggleViewMode("2d")}
              className={`px-2 py-0.5 rounded-control transition-colors ${
                viewMode === "2d" ? "bg-primary text-primary-fg font-medium" : "text-muted hover:text-main"
              }`}
            >
              2D command view
            </button>
            <button
              onClick={() => toggleViewMode("3d")}
              className={`px-2 py-0.5 rounded-control transition-colors ${
                viewMode === "3d" ? "bg-primary text-primary-fg font-medium" : "text-muted hover:text-main"
              }`}
            >
              3D corridor
            </button>
          </div>
        </div>

        {/* 3D Camera Presets & Demo Speed Controls */}
        <div className="flex items-center gap-3 text-xs">
          {viewMode === "3d" && (
            <div className="flex items-center gap-1">
              <span className="text-[11px] text-muted mr-1">Camera:</span>
              <button
                onClick={() => setCameraPreset(1)}
                className={`px-2 py-0.5 rounded-control border text-[11px] ${
                  cameraPreset === 1 ? "border-primary text-primary bg-surface font-semibold" : "border-rule text-muted"
                }`}
                title="Preset 1: Observer perspective at Now looking down runway"
              >
                1: Now
              </button>
              <button
                onClick={() => setCameraPreset(2)}
                className={`px-2 py-0.5 rounded-control border text-[11px] ${
                  cameraPreset === 2 ? "border-primary text-primary bg-surface font-semibold" : "border-rule text-muted"
                }`}
                title="Preset 2: Isometric overview of all regulator lanes"
              >
                2: Overview
              </button>
              <button
                onClick={() => setCameraPreset(3)}
                className={`px-2 py-0.5 rounded-control border text-[11px] ${
                  cameraPreset === 3 ? "border-primary text-primary bg-surface font-semibold" : "border-rule text-muted"
                }`}
                title="Preset 3: Lane focus on active statutory gate"
              >
                3: Lane focus
              </button>
            </div>
          )}

          {isDemo && (
            <div className="flex items-center gap-1 border-l border-rule pl-3">
              <span className="text-[11px] text-muted flex items-center gap-1">
                <FastForward className="w-3 h-3 text-status-due_soon" />
                <span>Sim speed:</span>
              </span>
              {[1, 60, 600].map((speed) => (
                <button
                  key={speed}
                  onClick={() => setSimSpeed(speed)}
                  className={`px-1.5 py-0.5 rounded-control border text-[10px] font-mono ${
                    simSpeed === speed ? "border-status-due_soon text-status-due_soon bg-surface font-bold" : "border-rule text-muted"
                  }`}
                >
                  {speed}x
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Simulated Time Banner (Demo Mode Only) */}
      {isDemo && simSpeed > 1 && (
        <div className="bg-[#A65F00]/10 border-b border-status-due_soon px-4 py-1.5 text-xs text-status-due_soon font-medium flex items-center justify-between">
          <span>Simulated time active ({simSpeed}x acceleration) - demo mode only</span>
          <span className="text-[11px] opacity-80">Disabled in production deployment</span>
        </div>
      )}

      {/* 3D Canvas or 2D Companion */}
      {viewMode === "3d" ? (
        <Suspense
          fallback={
            <div className="w-full h-[460px] bg-[#0F1923] flex items-center justify-center text-muted text-xs">
              Initializing WebGL depth corridor...
            </div>
          }
        >
          <CorridorCanvas
            viewModels={viewModels}
            cameraPreset={cameraPreset}
            selectedLaneIndex={selectedLane}
            theme={theme}
            onFallback2D={() => toggleViewMode("2d")}
          />
        </Suspense>
      ) : (
        /* High-Density 2D Tabular Companion */
        <div className="p-4 grid grid-cols-1 md:grid-cols-3 gap-3 bg-app">
          {viewModels.map((vm) => {
            let borderClass = "border-rule"
            let badgeClass = "border-rule text-muted bg-surface"
            let statusText = "Pending trigger"

            if (vm.visualState === "running") {
              borderClass = "border-status-ok"
              badgeClass = "border-status-ok text-status-ok bg-surface"
              statusText = "Running"
            } else if (vm.visualState === "due_soon") {
              borderClass = "border-status-due_soon"
              badgeClass = "border-status-due_soon text-status-due_soon bg-surface"
              statusText = "Due soon"
            } else if (vm.visualState === "critical") {
              borderClass = "border-status-critical"
              badgeClass = "border-status-critical text-status-critical bg-surface font-bold"
              statusText = "Critical"
            } else if (vm.visualState === "breached") {
              borderClass = "border-status-critical"
              badgeClass = "border-status-critical text-status-critical bg-surface font-bold"
              statusText = "Breached"
            } else if (vm.visualState === "filed") {
              borderClass = "border-status-ok"
              badgeClass = "border-status-ok text-status-ok bg-surface"
              statusText = "Filed"
            } else if (vm.visualState === "not_in_force") {
              badgeClass = "border-rule text-muted bg-surface"
              statusText = "Not in force (13 May 2027)"
            }

            return (
              <div
                key={vm.id}
                tabIndex={0}
                onClick={() => {
                  setSelectedLane(vm.laneIndex)
                  onSelectObligation?.(vm.id)
                }}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    setSelectedLane(vm.laneIndex)
                    onSelectObligation?.(vm.id)
                  }
                }}
                className={`p-3 rounded-segment border ${borderClass} bg-surface cursor-pointer focus:outline-none focus:ring-2 focus:ring-primary`}
              >
                <div className="flex items-center justify-between pb-1 border-b border-rule">
                  <span className="text-xs font-semibold text-main">{vm.regulator}</span>
                  <span className={`px-2 py-0.5 rounded-segment text-[11px] border ${badgeClass}`}>
                    {statusText}
                  </span>
                </div>
                <div className="my-2">
                  <div className="font-mono text-lg font-bold text-main">{vm.formattedCountdown}</div>
                  <div className="text-xs text-muted mt-0.5">Deadline: {vm.formattedIst}</div>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* Accessible DOM Screen Reader Mirror (aria-live="polite") */}
      <div className="sr-only" aria-live="polite" aria-atomic="true">
        <h3>Active statutory deadlines</h3>
        <table aria-label="Statutory deadline depth sequence">
          <thead>
            <tr>
              <th>Regulator</th>
              <th>Status</th>
              <th>Countdown</th>
              <th>Deadline</th>
              <th>Depth Z</th>
            </tr>
          </thead>
          <tbody>
            {viewModels.map((vm) => (
              <tr key={vm.id}>
                <td>{vm.regulator}</td>
                <td>{vm.visualState}</td>
                <td>{vm.formattedCountdown}</td>
                <td>{vm.formattedIst}</td>
                <td>{vm.depthZ}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
