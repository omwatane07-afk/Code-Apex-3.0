# ADR-0004: dedicated least-privilege wallboard role and sanitized endpoint

Status: accepted.

## Context
Commercial bank Security Operations Centers (SOCs) operate 24/7 with ambient wall-mounted displays visible from across the operations floor, visitor corridors, and physical inspection zones. 

Standard authenticated user sessions in CYBERQ:
1. Carry access to incident narrative summaries, evidence attachments, and potential bank customer identifiers.
2. Enforce a strict 15-minute idle session timeout (`SESSION_IDLE_TIMEOUT_MINUTES=15`).

Deploying an ambient wallboard under a standard analyst or commander user account would either:
- Expose confidential incident details and names to unauthorized bystanders across the room.
- Repeatedly disconnect every 15 minutes due to lack of mouse/keyboard input, creating an operational blind spot during active regulatory incidents.

## Decision
1. **Dedicated Role (`Role.WALLBOARD`)**:
   A dedicated system role `wallboard` is established. It operates under zero-trust, least-privilege constraints:
   - `wallboard` is granted exactly one permission: `Action.WALLBOARD_READ` (`wallboard:read`).
   - All other permissions (`incident:create`, `incident:read`, `incident:update`, `trigger:assert`, `packet:read`, `audit:read`, `admin:config`) are strictly denied (HTTP 403).

2. **Sanitized Endpoint (`GET /api/v1/incidents/wallboard`)**:
   A dedicated read-only endpoint returns exclusively sanitized operational telemetry:
   - Included: `incident_number`, `severity`, `status`, and obligation clocks (`regulator`, `status`, `deadline_at`, `active_deadline_at`, `is_disputed`, `applicability_status`).
   - Excluded: incident titles, descriptions, free-text summaries, investigator names, reporter phone numbers, and evidence links are entirely stripped from the database query and Pydantic serialization model.

3. **Authentication & Session Inactivity Exemption**:
   - The wallboard authenticates via standard session or rotating API bearer tokens assigned strictly to a service account with `Role.WALLBOARD`.
   - In `cyberq.iam.session.SessionManager`, sessions with `active_role == Role.WALLBOARD` are explicitly exempt from the 15-minute idle timeout, while still bounded by the maximum absolute session timeout (`SESSION_ABSOLUTE_TIMEOUT_HOURS=8`).

4. **Network Perimeter Restriction (IP Allow-List)**:
   - Access to `/api/v1/incidents/wallboard` is restricted to an explicit IP allow-list (`CYBERQ_WALLBOARD_ALLOWED_IPS`, default `["127.0.0.1", "::1"]`), enforcing that only whitelisted SOC display devices can query the endpoint.

## Consequences
- Physical security: Incident summaries and sensitive telemetry cannot leak onto ambient screens or to auditors/bystanders walking past the SOC.
- Operational resilience: Wall displays remain active during high-tempo incidents without manual re-authentication.
- Threat containment: If a wallboard display device or token is physically compromised, the adversary obtains only public incident identifiers and deadline timestamps, with zero access to bank narratives or regulatory filing packets.
