# CYBERQ 2 A.M. Operational Usability Task Script (Not Yet Measured)

## Protocol Specification
- **Evaluation Purpose**: Protocol for measuring whether a fatigued SOC lead or incident commander can triage an incoming cyber incident, inspect nearest statutory breaches, assert statutory clock triggers with consequence previews, and export a shift briefing in under 60 seconds with minimal clicks or keyboard alone.
- **Status**: Task script, not yet measured with human participants.
- **Environment**: Air-gapped bank SOC environment (`CYBERQ_ENV=pilot` / `DEMO`), high-contrast dark theme (Night Desk), 100% keyboard navigable.
- **Target Criteria**:
  1. Critical path steps minimized.
  2. All actions accessible via keyboard alone (`Tab`, `Enter`, `Space`, `Ctrl+K`, single-key shortcuts `n`, `a`, `1-3`).
  3. Total elapsed operational triage time target: < 60 seconds.

---

## Planned Execution Flow (Target: < 60 Seconds)

### Phase 1: Situational Awareness & Nearest Breach
1. **Action**: Analyst views active incidents list on the Command Center (`INC-2026-0001`).
2. **Visual Ergonomics**:
   - High-contrast clock dials immediately display statutory countdowns: CERT-In (6h statutory), RBI DAKSH (6h directions).
   - Alternatively, toggle to **3D Depth Runway** (`2` key or tab) to perceive spatial perspective of impending breaches down the depth Z-axis.
3. **Assessment**:
   - Urgent deadlines positioned closest to observer (`depthZ < 30`).
   - Monotonic continuous scale ensures clear visual separation.
- **Mouse Clicks**: 0 (Default view on load).
- **Keyboard**: 0 (Directly on screen) or 1 keypress (`2` for 3D view).

---

### Phase 2: Assert Statutory Trigger & Consequence Preview
1. **Action**: Open statutory trigger assertion modal.
   - **Keyboard**: Press `a` (global shortcut, inert while in input fields) or click `Assert clock trigger` (1 click).
2. **Dual-Trigger Default**:
   - Checkbox *"Simultaneous CERT-In & RBI DAKSH trigger (bank standard)"* checked by default.
   - Automatically provisions two independent legal assertions: `noticed` (CERT-In) and `detected` (RBI DAKSH).
3. **Timestamp Selection**:
   - Click relative quick picker: `10m ago` (1 click) or `Just now` (1 click) or `Tab` to timestamp input.
4. **Server Consequence Preview**:
   - Backend preview endpoint calculates exact statutory consequence:
     - `CERT-In`: 6h statutory clock, deadline calculated strictly server-side in UTC and rendered in IST.
     - `RBI`: 6h DAKSH platform clock, deadline calculated strictly server-side in UTC and rendered in IST.
- **Mouse Clicks**: 2 clicks (1 to open modal if mouse used + 1 quick picker).
- **Keyboard**: Shortcut `a` + Tab navigation (0 mouse clicks).

---

### Phase 3: Obligation Applicability Diagnostic Check
1. **Action**: Complete plain-language statutory diagnostic questions:
   - Question 1: *"Is personal data involved?"* -> Select `No` (1 click).
   - Question 2: *"Is this a reportable category?"* -> Select `Yes` (1 click).
2. **Precautionary Safeguard Verification**:
   - If an analyst selects `No` for reportable category, UI prominently displays precautionary notice:
     *"Precautionary rule: A 'No' answer keeps the clock running as 'pending approval' until a compliance approver confirms exemption with a mandatory reason. SOC analysts cannot stop statutory clocks."*
   - Enter evidence & rationale (`SIEM correlation alert ID #89201`).
   - PII Soft Guard scans input text: verifies zero unredacted Aadhaar numbers or provides audited override.
3. **Submit**: Press `Enter` or click `Assert trigger` (1 click).
- **Mouse Clicks**: 3 clicks (diagnostic Q1, diagnostic Q2, submit).
- **Keyboard**: Tab navigation + space to select radio + Enter to submit (0 mouse clicks).

---

### Phase 4: Shift Briefing & Wallboard Handoff
1. **Action**: Prepare handover briefing for incoming shift.
   - Press `Ctrl+K` -> select `Go to shift handover briefing` (or click `Shift handover` in header: 1 click).
   - Review sanitized briefing text (incident numbers, severities, running clocks; zero titles/PII if Admin).
   - Press `Copy to clipboard` (1 click).
2. **Optional SOC Wallboard Handoff**:
   - Press `Ctrl+K` -> `Go to wallboard display` (or navigate to `/wall`).
   - Ambient, high-visibility display running on wall display: zero incident titles, zero personal names, strictly incident numbers and large countdown clocks.
- **Mouse Clicks**: 2 clicks (open modal, copy).
- **Keyboard**: `Ctrl+K` + Enter + Tab + Enter (0 mouse clicks).

---

## Click Count Breakdown (Honest Accounting)
- **Total Mouse Clicks (Full Workflow via Mouse)**:
  - Phase 1: 0 clicks
  - Phase 2: 2 clicks (open modal + quick picker)
  - Phase 3: 3 clicks (applicability Q1 + applicability Q2 + submit assertion)
  - Phase 4: 2 clicks (open handover modal + copy to clipboard)
  - **Total**: 7 clicks (5 clicks on trigger assertion path, 2 clicks on handover path).
- **Total Mouse Clicks (Full Workflow via Keyboard)**: 0 mouse clicks.

---

## Task Protocol Checklist & Verification Method
| Requirement | Specification Target | Verification Method |
| :--- | :--- | :--- |
| Operational Triage Duration | < 60 seconds target | Human participant trial (not yet measured) |
| Trigger Assertion Clicks | Minimized (5 clicks mouse, 0 keyboard) | Measured via step-by-step click accounting |
| Keyboard Accessibility | 100% accessible via shortcuts & Tab | Automated E2E test (`tests/keyboard_flow.spec.ts`) |
| WCAG 2.1 AA Contrast | >= 4.5:1 text, >= 3.0:1 UI borders | Automated test `tests/contrast.test.ts` (Light: text 13.8:1, muted 5.1:1; Dark: text 10.5:1, muted 5.6:1) |
| Precautionary Principle Enforced | Analysts cannot stop statutory clocks | Backend policy tests (`test_incidents_api.py`) |
