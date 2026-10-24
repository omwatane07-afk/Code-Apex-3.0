# ADR-0003: Three.js procedural depth visualization and progressive enhancement

Status: accepted.

## Context
Milestone M1 establishes the statutory deadline clock engine for CERT-In (6 hours), RBI DAKSH (6 hours), and DPDP (72 hours). SOC analysts and incident commanders operating at 2 a.m. face high cognitive load when tracking multiple concurrent regulatory timers.

To enhance situational awareness without adding decorative visual noise, we introduce a spatial depth dimension: "The Deadline Corridor". The observer is positioned at "Now" looking down an operational runway of time into upcoming regulatory milestones.

## Decision
1. **Pinned Standalone Three.js (`three@0.170.0`)**:
   - Pinned exact version `three@0.170.0` and `@types/three@0.170.0`.
   - Permissive MIT license (included in bank allowlist).
   - Provenance: `three@0.170.0` was released on 2024-10-31 (>14 days old), audited with `npm audit` (0 vulnerabilities).
   - Rejected React Three Fiber (`@react-three/fiber`) and `@react-three/drei`: they introduce dozens of transitive dependencies, increase bundle size, complicate WebGL context disposal, and violate the locked stack principle.

2. **Strict Air-Gapped Procedural Geometry**:
   - Zero external textures, zero remote 3D models (`.gltf` / `.obj`), zero remote font loaders.
   - All runway gates, lanes, and markers are generated procedurally using standard Three.js primitives (`BoxGeometry`, `CylinderGeometry`, `BufferGeometry`).
   - Materials are strictly matte banking-grade materials (`MeshLambertMaterial`, `MeshBasicMaterial`) adhering to the light and dark theme palettes in `tokens.css`. Glowing blooms and specular decorations are forbidden.
   - Content-Security-Policy (CSP) remains air-gapped: no external origins or blob loaders are introduced.

3. **CSS2DRenderer for DOM Typography**:
   - Tabular numerals and regulatory labels are rendered using Three.js `CSS2DRenderer` elements mapped to the DOM.
   - All text utilizes the self-hosted IBM Plex Sans fonts and active CSS variables (`var(--color-main)`, `var(--color-rule)`).

4. **Progressive Enhancement & Automatic 2D Fallback**:
   - The application defaults to 2D command center:
     - On mobile / tablet screens (< 768 px).
     - On devices with coarse pointers (`pointer: coarse`).
     - When `prefers-reduced-motion: reduce` is detected.
     - When WebGL2 is unsupported, context creation fails, or frame rate drops below 30 FPS.
   - Complete data parity is maintained: both 2D and 3D views consume the exact same `ClockViewModel[]` contract.

5. **Performance and Bundle Budgets**:
   - Code splitting: Three.js is bundled into a dedicated chunk loaded via `React.lazy()`.
   - Core bundle growth without 3D is <= 5%.
   - 3D chunk size is strictly capped at <= 250 KB gzip.
   - Render caps: max 150 draw calls, <100,000 triangles, device pixel ratio clamped to `Math.min(window.devicePixelRatio, 1.5)`.
