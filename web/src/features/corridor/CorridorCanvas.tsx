import React, { useEffect, useRef, useState, useCallback } from "react"
import * as THREE from "three"
import { ClockViewModel } from "./ClockViewModel"

interface CorridorCanvasProps {
  viewModels: ClockViewModel[]
  cameraPreset: 1 | 2 | 3
  selectedLaneIndex?: number
  theme?: "light" | "dark"
  onFallback2D: () => void
}

interface ProjectedLabel {
  id: string
  x: number
  y: number
  yOffset: number
  text: string
  sub: string
  state: string
}

export const CorridorCanvas: React.FC<CorridorCanvasProps> = ({
  viewModels,
  cameraPreset,
  selectedLaneIndex = 0,
  theme = "dark",
  onFallback2D,
}) => {
  const mountRef = useRef<HTMLDivElement>(null)
  const rendererRef = useRef<THREE.WebGLRenderer | null>(null)
  const sceneRef = useRef<THREE.Scene | null>(null)
  const cameraRef = useRef<THREE.PerspectiveCamera | null>(null)
  const animationFrameRef = useRef<number | null>(null)
  const [labels, setLabels] = useState<ProjectedLabel[]>([])

  // Probe WebGL availability and context support
  useEffect(() => {
    try {
      const testCanvas = document.createElement("canvas")
      const gl = testCanvas.getContext("webgl2") || testCanvas.getContext("webgl")
      if (!gl) {
        onFallback2D()
        return
      }
    } catch {
      onFallback2D()
    }
  }, [onFallback2D])

  // Setup Three.js procedural scene with physical gate geometries
  useEffect(() => {
    const container = mountRef.current
    if (!container) return

    const width = container.clientWidth || 800
    const height = container.clientHeight || 450

    const isLight = theme === "light"
    const bgHex = isLight ? 0xf4f5f3 : 0x050508
    const floorHex = isLight ? 0xe2e6e9 : 0x0a0d14
    const lineHex = isLight ? 0xc2cad0 : 0x1a2332
    const nowHex = isLight ? 0x1b4f9c : 0x00e5ff

    // 1. Scene with bank palette background
    const scene = new THREE.Scene()
    scene.background = new THREE.Color(bgHex)
    sceneRef.current = scene

    // 2. Camera with clamped aspect ratio
    const camera = new THREE.PerspectiveCamera(55, width / height, 0.1, 200)
    camera.position.set(0, 2.5, -4)
    camera.lookAt(0, 1.5, 20)
    cameraRef.current = camera

    // 3. WebGL Renderer with performance clamping
    let renderer: THREE.WebGLRenderer
    try {
      renderer = new THREE.WebGLRenderer({
        antialias: true,
        powerPreference: "high-performance",
      })
    } catch {
      onFallback2D()
      return
    }

    renderer.setSize(width, height)
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.5))
    rendererRef.current = renderer
    ;(window as any).__CYBERQ_RENDERER_INFO__ = {
      geometries: renderer.info.memory.geometries,
      textures: renderer.info.memory.textures,
    }

    container.appendChild(renderer.domElement)
    renderer.domElement.setAttribute("aria-hidden", "true")

    // Handle context loss
    const handleContextLost = (e: Event) => {
      e.preventDefault()
      onFallback2D()
    }
    renderer.domElement.addEventListener("webglcontextlost", handleContextLost, false)

    // 4. Matte lighting (clean banking visibility, no specular bloom)
    const ambientLight = new THREE.AmbientLight(0xffffff, isLight ? 0.9 : 0.8)
    scene.add(ambientLight)

    const dirLight = new THREE.DirectionalLight(0xffffff, isLight ? 0.7 : 0.6)
    dirLight.position.set(5, 15, -10)
    scene.add(dirLight)

    // 5. Procedural runway floor with 3 distinct regulator lanes
    // Lane X coordinates: Lane 0 (CERT-In) = -4.2, Lane 1 (RBI) = 0.0, Lane 2 (DPDP) = 4.2
    const floorGeo = new THREE.PlaneGeometry(16, 140)
    const floorMat = new THREE.MeshLambertMaterial({ color: floorHex })
    const floorMesh = new THREE.Mesh(floorGeo, floorMat)
    floorMesh.rotation.x = -Math.PI / 2
    floorMesh.position.set(0, 0, 60)
    scene.add(floorMesh)

    // Lane division rules
    const lineMat = new THREE.LineBasicMaterial({ color: lineHex })
    for (const lx of [-6.3, -2.1, 2.1, 6.3]) {
      const lineGeo = new THREE.BufferGeometry().setFromPoints([
        new THREE.Vector3(lx, 0.02, -5),
        new THREE.Vector3(lx, 0.02, 135),
      ])
      const laneLine = new THREE.Line(lineGeo, lineMat)
      scene.add(laneLine)
    }

    // Now marker at observer position
    const nowGeo = new THREE.BoxGeometry(13, 0.08, 0.5)
    const nowMat = new THREE.MeshLambertMaterial({ color: nowHex })
    const nowMesh = new THREE.Mesh(nowGeo, nowMat)
    nowMesh.position.set(0, 0.04, 0)
    scene.add(nowMesh)

    // 6. Real 3D Physical Gate Geometries along the runway
    const laneX = [-4.2, 0.0, 4.2]

    const getGateColor = (state: string): number => {
      switch (state) {
        case "breached":
          return 0x7a0f0f
        case "critical":
          return 0xff1e42
        case "due_soon":
          return 0xffb74d
        case "filed":
          return 0x00ff66
        case "pending":
          return isLight ? 0x5a6d7d : 0x3d5060
        case "not_in_force":
          return isLight ? 0x8a99a8 : 0x16232f
        case "exempt":
          return 0x0088ff
        default:
          return isLight ? 0x1b4f9c : 0x00e5ff
      }
    }

    viewModels.forEach((vm) => {
      const x = laneX[vm.laneIndex] ?? 0
      const z = Math.max(1.0, vm.depthZ)
      const gateColor = getGateColor(vm.visualState)

      const gateMat = new THREE.MeshLambertMaterial({ color: gateColor })

      // Left vertical pylon
      const leftPylonGeo = new THREE.BoxGeometry(0.2, 3.0, 0.2)
      const leftPylon = new THREE.Mesh(leftPylonGeo, gateMat)
      leftPylon.position.set(x - 1.6, 1.5, z)
      scene.add(leftPylon)

      // Right vertical pylon
      const rightPylonGeo = new THREE.BoxGeometry(0.2, 3.0, 0.2)
      const rightPylon = new THREE.Mesh(rightPylonGeo, gateMat)
      rightPylon.position.set(x + 1.6, 1.5, z)
      scene.add(rightPylon)

      // Top lintel / arch crossbar
      const lintelGeo = new THREE.BoxGeometry(3.4, 0.24, 0.24)
      const lintel = new THREE.Mesh(lintelGeo, gateMat)
      lintel.position.set(x, 3.0, z)
      scene.add(lintel)

      // Additional visual cues per state (never color alone)
      if (vm.visualState === "breached") {
        // Barred gate crossbeam
        const barGeo = new THREE.BoxGeometry(3.2, 0.15, 0.15)
        const barMesh = new THREE.Mesh(barGeo, gateMat)
        barMesh.position.set(x, 1.5, z)
        scene.add(barMesh)
      } else if (vm.visualState === "critical") {
        // Double-frame beacon bar
        const secondBarGeo = new THREE.BoxGeometry(3.3, 0.18, 0.18)
        const secondBar = new THREE.Mesh(secondBarGeo, gateMat)
        secondBar.position.set(x, 2.7, z)
        scene.add(secondBar)
      }
    })

    // Render loop with collision-avoiding 2D label projection
    const animate = () => {
      animationFrameRef.current = requestAnimationFrame(animate)

      const projected: ProjectedLabel[] = []

      for (const vm of viewModels) {
        const x = laneX[vm.laneIndex] ?? 0
        const z = Math.max(1.0, vm.depthZ)
        const gatePos = new THREE.Vector3(x, 3.1, z)

        gatePos.project(camera)

        const sx = ((gatePos.x + 1) * width) / 2
        const sy = ((-gatePos.y + 1) * height) / 2

        if (gatePos.z > 0 && gatePos.z < 1) {
          projected.push({
            id: vm.id,
            x: sx,
            y: sy,
            yOffset: 0,
            text: vm.formattedCountdown,
            sub: `${vm.regulator} (${vm.formattedIst})`,
            state: vm.visualState,
          })
        }
      }

      // Lateral and vertical collision avoidance for coincident or close deadlines
      for (let i = 0; i < projected.length; i++) {
        for (let j = i + 1; j < projected.length; j++) {
          const dx = Math.abs(projected[i].x - projected[j].x)
          const dy = Math.abs(projected[i].y - projected[j].y)
          if (dx < 130 && dy < 48) {
            projected[i].yOffset = -20
            projected[j].yOffset = 20
          }
        }
      }

      setLabels(projected)
      renderer.render(scene, camera)
    }
    animate()

    // Resize handler
    const handleResize = () => {
      if (!container || !rendererRef.current || !cameraRef.current) return
      const w = container.clientWidth
      const h = container.clientHeight
      cameraRef.current.aspect = w / h
      cameraRef.current.updateProjectionMatrix()
      rendererRef.current.setSize(w, h)
    }
    window.addEventListener("resize", handleResize)

    // Clean disposal (strictly prevents memory leaks over 50 cycles)
    return () => {
      window.removeEventListener("resize", handleResize)
      if (animationFrameRef.current) {
        cancelAnimationFrame(animationFrameRef.current)
      }
      renderer.domElement.removeEventListener("webglcontextlost", handleContextLost)

      scene.traverse((obj) => {
        if (obj instanceof THREE.Mesh) {
          obj.geometry.dispose()
          if (Array.isArray(obj.material)) {
            obj.material.forEach((m) => m.dispose())
          } else {
            obj.material.dispose()
          }
        }
        if (obj instanceof THREE.Line) {
          obj.geometry.dispose()
          if (Array.isArray(obj.material)) {
            obj.material.forEach((m) => m.dispose())
          } else {
            obj.material.dispose()
          }
        }
      })
      renderer.dispose()
      if (container.contains(renderer.domElement)) {
        container.removeChild(renderer.domElement)
      }
    }
  }, [viewModels, theme, onFallback2D])

  // Camera presets controller
  const updateCameraPreset = useCallback(
    (preset: 1 | 2 | 3) => {
      const camera = cameraRef.current
      if (!camera) return

      const laneX = [-4.2, 0.0, 4.2]
      const targetLaneX = laneX[selectedLaneIndex] ?? 0

      if (preset === 1) {
        // Preset 1: Now (Default view looking down runway)
        camera.position.set(0, 2.5, -4)
        camera.lookAt(0, 1.5, 20)
      } else if (preset === 2) {
        // Preset 2: Overview (Isometric bird's-eye view)
        camera.position.set(0, 18, 25)
        camera.lookAt(0, 0, 45)
      } else if (preset === 3) {
        // Preset 3: Lane focus (Locks onto active regulator)
        camera.position.set(targetLaneX, 3.0, 5)
        camera.lookAt(targetLaneX, 1.5, 25)
      }
      camera.updateProjectionMatrix()
    },
    [selectedLaneIndex]
  )

  useEffect(() => {
    updateCameraPreset(cameraPreset)
  }, [cameraPreset, updateCameraPreset])

  const isLight = theme === "light"

  return (
    <div
      className={`relative w-full h-[460px] border border-rule overflow-hidden select-none ${
        isLight ? "bg-[#F4F5F3]" : "bg-[#0F1923]"
      }`}
    >
      <div ref={mountRef} className="w-full h-full" />

      {/* DOM Projected Tabular Labels with Collision Offsets */}
      <div className="absolute inset-0 pointer-events-none">
        {labels.map((lbl) => {
          let badgeStyle = isLight
            ? "border-rule text-main bg-surface/95 shadow-sm"
            : "border-rule text-[#E8EEF3] bg-[#16232F]/90 shadow-md"

          if (lbl.state === "critical") {
            badgeStyle = "border-[#B3261E] text-[#B3261E] bg-surface font-semibold"
          } else if (lbl.state === "due_soon") {
            badgeStyle = "border-[#A65F00] text-[#A65F00] bg-surface font-semibold"
          } else if (lbl.state === "breached") {
            badgeStyle = "border-[#7A0F0F] text-[#B3261E] bg-surface font-semibold"
          } else if (lbl.state === "filed") {
            badgeStyle = "border-[#1F7A4D] text-[#1F7A4D] bg-surface font-semibold"
          } else if (lbl.state === "pending") {
            badgeStyle = isLight
              ? "border-rule text-muted bg-surface/90"
              : "border-rule text-muted bg-[#16232F]/90"
          } else if (lbl.state === "not_in_force") {
            badgeStyle = isLight
              ? "border-rule text-muted/70 bg-surface/70"
              : "border-rule text-muted/70 bg-[#16232F]/70"
          } else if (lbl.state === "exempt") {
            badgeStyle = "border-[#41627A] text-[#1B4F9C] dark:text-[#7FB0FF] bg-surface"
          }

          return (
            <div
              key={lbl.id}
              style={{
                transform: `translate(${lbl.x}px, ${lbl.y + lbl.yOffset}px) translate(-50%, -100%)`,
              }}
              className="absolute transition-transform duration-100 ease-out flex flex-col items-center"
            >
              <div className={`px-2.5 py-1 rounded-segment border ${badgeStyle}`}>
                <div className="font-mono text-xs font-bold tracking-tight text-center">{lbl.text}</div>
                <div className="text-[10px] text-muted font-sans text-center whitespace-nowrap mt-0.5">
                  {lbl.sub}
                </div>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
