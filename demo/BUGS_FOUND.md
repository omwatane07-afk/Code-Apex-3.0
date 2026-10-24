# CYBERQ Demo Bug Log

Issues discovered during live recording of the 13 demonstration scenes.
Per Ground Rule 1 & 4: Truth only. Do not hide bugs. Log real bugs here and demo the working portion.

---

| Bug ID | Scene | Description | Severity | Workaround / Demo Note |
|---|---|---|---|---|
| BUG-DEMO-01 | Scene 4 | Client-side PII regex in trigger modal stripped whitespace before checking word boundaries, missing spaced Aadhaar numbers. | P2 | Fixed with boundary-agnostic candidate regex matching backend Verhoeff candidate pattern. Audited override verified in Scene 4. |

