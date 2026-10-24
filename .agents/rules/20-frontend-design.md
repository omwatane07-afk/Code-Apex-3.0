# Frontend design rules

## Brief
Audience: SOC analysts and compliance officers working under a six-hour clock, often at night, plus a CISO who presents to the Board. Primary job: always know what is due, to whom, by when, and what to do next. Tone: a serious ledger and operations console. Calm, exact, dense where it helps, never decorative.

## The one memorable element: the clock strip
Every incident screen opens with a horizontal strip of obligation clocks (one segment per regulator). Each segment shows the regulator, the time remaining in large tabular figures (HH:MM:SS), the absolute deadline in IST (UTC on hover), the trigger that started it (noticed / detected / aware) and its state. Everything else on the page stays quiet so this strip reads in one second from across a room.
States and treatment (never colour alone; always icon plus text): `running` (neutral), `due_soon` (under 2 h; amber, "Due in 1h 42m"), `critical` (under 30 min; vermilion, filled segment), `filed` (green, shows acknowledgement ID), `breached` (dark red, shows overdue duration), `not_applicable`, `disputed` (shows both deadlines). Respect reduced motion; no flashing. A soft, non-looping pulse is allowed only on `critical`.
Time comes from the server with a drift indicator. If the browser clock differs by more than 2 s, show a banner and keep using server time.

## Layout
- App shell: narrow left rail (icons plus labels), top bar with environment label (`PRODUCTION` / `PILOT` / `DEMO`), search, user menu and the "next due" ticker. Content uses split panes and ruled tables, not stacks of identical rounded cards.
- Command Center: left, incident list sorted by earliest deadline; right, selected incident summary. Incident detail: clock strip, then tabs: Timeline, Obligations, Filing packets, Evidence, Decisions.
- Filing packet view: ordered fields as a two-column table (label, value) with a copy button per row and "copy all"; a sticky footer with the maker-checker state (Prepared by, Approved by), then "Record as filed" (portal, time, ack ID). Approval and filing use a confirmation sheet where the user types the incident ID. No auto-advance.
- Other screens: Sources (connector health and last event), Decision ledger, Board pack, Model governance (inventory entry, assumptions register, validation pack), Admin (users, roles, packs, audit verify).
- Desktop first (1280 px and up) with a wall-display mode (large type, read-only). Tablet and phone must remain usable for viewing clocks and approving, not for dense editing.

## Visual system
Tokens live in `web/src/styles/tokens.css` as CSS variables; Tailwind reads them. White-label slots: logo, product name, accent. Do not copy any bank's logo or brand colours.
- Light ("Day ledger"): background `#F4F5F3`, surface `#FFFFFF`, rule `#D3D8DB`, text `#15202B`, muted `#4F5D69`, primary `#1B4F9C`.
- Dark ("Night desk"): background `#0F1923`, surface `#16232F`, rule `#2A3A48`, text `#E8EEF3`, muted `#9FB0BF`, primary `#7FB0FF`.
- Status: ok `#1F7A4D`, due soon `#A65F00`, critical `#B3261E`, breached `#7A0F0F`, info `#41627A` (dark-mode equivalents chosen by the same contrast tests).
- Automated contrast tests are required: 4.5:1 for text, 3:1 for UI components and focus rings, in both themes. Theme follows system by default, user can override.
- Type: IBM Plex Sans (UI) with IBM Plex Sans Devanagari (Hindi), self-hosted woff2 under the OFL, subset, `font-display: swap`. Use tabular numerals for all times and counts. IBM Plex Mono only for hashes, IDs and code. Scale 12/13/14/16/20/28/40; body 14 px; line length under 80 characters in prose.
- Shape and depth: one 4 px radius for controls, 0 for table rows, 2 px for status segments. Use 1 px rules to separate regions. No drop-shadow stacks, no gradients, no glass effects, no illustration, no emoji. Elevation only for popovers and sheets.
- Copy: sentence case, plain verbs, specific labels ("Record as filed", not "Submit"). Errors say what failed and what to do. No tracked all-caps eyebrow labels, no decorative numbering, no "Welcome back" text.

## Interaction
- Keyboard first: command palette (Ctrl/Cmd+K), `g i` incidents, `g d` decisions, `j/k` move in lists, `/` search, visible focus on everything.
- Optimistic UI is forbidden for approvals, filings and role changes. Show pending and confirmed states explicitly.
- Every table: sortable, filterable, CSV export (audited), sticky header, empty state that says what to do.
- Offline-safe printing: print stylesheets for the filing worksheet and the manual-fallback checklist.
- Loading uses skeletons that match layout. Errors are inline, with request ID and a copy button.

## Accessibility and i18n
- WCAG 2.1 AA minimum. axe-core in CI with zero serious or critical violations. Screen-reader announcements for state changes in clocks (polite, throttled to threshold changes only).
- All strings go through the i18n layer from day one. English first, Hindi catalogue for navigation and status labels by M4. Dates, numbers and the Indian digit grouping (lakh, crore) use `Intl`.

## Depth and 3D
- Purpose: situational awareness and temporal depth, never decorative. Spatial depth represents the physical runway of statutory time remaining.
- Progressive enhancement: 2D command center is complete and keyboard/screen reader accessible. 3D Deadline Corridor adds depth when hardware permits.
- Automatic 2D defaults: view defaults to 2D on viewports < 768 px, on coarse pointer devices (pointer: coarse), on prefers-reduced-motion: reduce, or if the WebGL2 probe measures < 30 FPS or loses context.
- Materials and aesthetics: strictly matte banking materials (MeshLambertMaterial, MeshBasicMaterial). No glowing bloom, no specular reflections, no external textures or model files.
- Visual state cues (never color alone): standard portal for running, notched barrier with pylons for due_soon, double-frame beacon for critical, open gate for filed, barred gate for breached.
- Camera presets: Preset 1 ("Now", default view down the runway), Preset 2 ("Overview", isometric bird's-eye view), Preset 3 ("Lane focus", centers on selected regulator).
- Performance caps: maximum 150 draw calls, < 100,000 triangles, device pixel ratio clamped to min(devicePixelRatio, 1.5). Canvas marked aria-hidden="true"; accessible DOM list provides screen reader parity.
- Clock strip CSS 3D dials: depleting SVG progress arc updating once per second, preserve-3d perspective, translateZ(8px) forward for urgent states, flattened when reduced motion is preferred.

## Process
For each new screen: write a one-paragraph design plan and an ASCII wireframe in the plan artifact, build it, open it in the browser tool at 1440 and 390 px in both themes, capture screenshots, critique against this file, fix, then attach the screenshots to the walkthrough artifact. Remove one decorative element before you call a screen done.
