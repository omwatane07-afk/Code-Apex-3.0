# Regulatory content rules

Regulations change and secondary sources disagree. The product must never present guessed regulatory facts as verified.

## Data, not code
All obligations live in `packs/obligations/*.yaml`, loaded and validated at startup. Schema:
```
id, regulator, instrument, clause_ref, applies_to[], trigger_event
(noticed|detected|aware|custom), deadline_hours or deadline_rule, effective_from,
channel (portal|email|form|other), channel_notes, filing_fields[],
source_url, source_checked_on, verified_by, status (draft|verified), notes
```

## Production gate
- `status: verified` requires `verified_by` (a named human) and `source_checked_on`. Production mode (`CYBERQ_ENV=production`) refuses to load `draft` packs.
- Dev mode loads drafts but shows a persistent "Unverified regulatory data, for demonstration" banner on every screen that displays a deadline, clock or filing packet.

## Starter packs (all `draft` until a human verifies them against primary sources)
- CERT-In Directions (28 April 2022): report specified incidents within 6 hours of noticing or being notified. Trigger: `noticed`.
- RBI Cybersecurity, Technology: Risk, Resilience and Assurance Framework Directions, 2026 (issued 31 July 2026; commercial banks: RBI/DoS/2026-27/410): report cyber incidents on the DAKSH platform within 6 hours of detection. Trigger: `detected`. Secondary sources cite paragraph 182; confirm against the primary text at https://rbi.org.in/scripts/NotificationUser.aspx?Id=13643&Mode=0 and the equivalent Directions for other entity classes.
- DPDP Rules 2025, Rule 7: initial intimation to the Data Protection Board and affected individuals without delay; detailed report within 72 hours of becoming aware; enforcement from 13 May 2027 (`effective_from`). Trigger: `aware`.
- SEBI CSCRF: add only if the entity is SEBI-registered; leave as an empty draft stub.

## Filing fields
Do not invent filing form fields. Try to retrieve official forms or templates from primary sources. If you cannot, set `filing_fields: []`, write the gap to `docs/BLOCKERS.md`, and continue with a generic structured incident summary clearly labelled "not an official form".
The filing packet is a human aid: ordered, copy-friendly field values with a "filed" step that records portal, timestamp, filer and acknowledgement ID. It never submits anything.

## Entity applicability
The bank's entity class (commercial bank, small finance bank, payments bank, UCB, NBFC, etc.) is configuration. Seven parallel RBI Directions exist, one per class. Select packs by `applies_to`.

## Clock semantics
Clock start events differ by regulator (noticed, detected, aware). Record who asserted each trigger, when, and with what evidence. Never infer a trigger silently. If triggers are disputed, show both deadlines and keep the earlier one active until a compliance approver resolves it, with a mandatory reason.
