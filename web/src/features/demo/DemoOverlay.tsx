import React, { useEffect, useState } from "react"

export const DemoOverlay: React.FC = () => {
  const [isDemo, setIsDemo] = useState(false)
  const [caption, setCaption] = useState<string>("")

  useEffect(() => {
    if (typeof window === "undefined") return
    const params = new URLSearchParams(window.location.search)
    if (params.get("demo") === "1") {
      setIsDemo(true)
      const initialCaption = params.get("caption") || "CYBERQ Incident-to-Board Platform"
      setCaption(initialCaption)

      // Expose global setter for Playwright / scripts
      ;(window as any).__CYBERQ_SET_CAPTION__ = (text: string) => {
        setCaption(text)
      }

      // Click ripple handler
      const handlePointerDown = (e: MouseEvent) => {
        const ripple = document.createElement("div")
        ripple.style.position = "fixed"
        ripple.style.left = `${e.clientX}px`
        ripple.style.top = `${e.clientY}px`
        ripple.style.width = "40px"
        ripple.style.height = "40px"
        ripple.style.marginLeft = "-20px"
        ripple.style.marginTop = "-20px"
        ripple.style.borderRadius = "50%"
        ripple.style.pointerEvents = "none"
        ripple.style.border = "2px solid #3B82F6"
        ripple.style.background = "rgba(59, 130, 246, 0.25)"
        ripple.style.transform = "scale(0.2)"
        ripple.style.transition = "transform 400ms ease-out, opacity 400ms ease-out"
        ripple.style.zIndex = "99999"
        ripple.style.opacity = "1"
        document.body.appendChild(ripple)

        requestAnimationFrame(() => {
          ripple.style.transform = "scale(2.0)"
          ripple.style.opacity = "0"
        })

        setTimeout(() => {
          if (ripple.parentNode) {
            ripple.parentNode.removeChild(ripple)
          }
        }, 450)
      }

      window.addEventListener("pointerdown", handlePointerDown)
      return () => {
        window.removeEventListener("pointerdown", handlePointerDown)
      }
    }
  }, [])

  if (!isDemo || !caption) return null

  return (
    <div
      role="status"
      aria-live="polite"
      className="fixed bottom-6 left-1/2 -translate-x-1/2 z-[9999] pointer-events-none px-6 py-2.5 rounded-full bg-[#0B0F14]/90 border border-blue-500/50 text-[#E8EEF3] font-sans text-sm font-semibold tracking-wide shadow-2xl backdrop-blur-md flex items-center gap-3 transition-all duration-300"
    >
      <span className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-pulse flex-shrink-0" />
      <span>{caption}</span>
    </div>
  )
}
