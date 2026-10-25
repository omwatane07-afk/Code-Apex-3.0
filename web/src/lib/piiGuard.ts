/**
 * Client-Side Banking PII Guard.
 *
 * Scans and redacts sensitive Indian personal data (Aadhaar, PAN, Card, Phone, Email)
 * before any telemetry is sent to local models or APIs.
 */

export interface DetectedPII {
  type: "Aadhaar" | "PAN" | "Credit Card" | "Phone" | "Email"
  match: string
  maskedPreview: string
  index?: number
}

// Verhoeff multiplication table
const VERHOEFF_D = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
  [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
  [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]

// Verhoeff permutation table
const VERHOEFF_P = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
  [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
  [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
  [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
  [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]

function validateVerhoeff(numStr: string): boolean {
  const digits = numStr.replace(/\D/g, "").split("").map(Number)
  if (digits.length !== 12) return false
  if (digits[0] === 0 || digits[0] === 1) return false

  let c = 0
  const rev = digits.slice().reverse()
  for (let i = 0; i < rev.length; i++) {
    c = VERHOEFF_D[c][VERHOEFF_P[i % 8][rev[i]]]
  }
  return c === 0
}

function validateLuhn(numStr: string): boolean {
  const digits = numStr.replace(/\D/g, "").split("").map(Number)
  if (digits.length < 13 || digits.length > 19) return false

  let sum = 0
  let isEven = false
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits[i]
    if (isEven) {
      d *= 2
      if (d > 9) d -= 9
    }
    sum += d
    isEven = !isEven
  }
  return sum % 10 === 0
}


/**
 * Scans arbitrary text for banking PII:
 * 1. Aadhaar (12-digit numbers with Verhoeff validation)
 * 2. PAN (5 uppercase alpha, 4 digits, 1 uppercase alpha)
 * 3. Credit / Debit card (13-19 digits with Luhn validation)
 * 4. Indian Phone (+91 or 10-digit starting with 6-9)
 * 5. Email addresses
 */
export function scanForPII(text: string): DetectedPII[] {
  if (!text || typeof text !== "string") return []

  const findings: DetectedPII[] = []
  const seenMatches = new Set<string>()

  // 1. PAN cards: [A-Z]{5}[0-9]{4}[A-Z]{1}
  const panRegex = /\b([A-Z]{5}[0-9]{4}[A-Z]{1})\b/g
  let m: RegExpExecArray | null
  while ((m = panRegex.exec(text)) !== null) {
    const raw = m[1]
    if (!seenMatches.has(raw)) {
      seenMatches.add(raw)
      findings.push({
        type: "PAN",
        match: raw,
        maskedPreview: `${raw.slice(0, 2)}XXXXX${raw.slice(-2)}`,
        index: m.index,
      })
    }
  }

  // 2. Aadhaar cards: 12 digits (with optional spaces or dashes)
  const aadhaarRegex = /\b([2-9][0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4})\b/g
  while ((m = aadhaarRegex.exec(text)) !== null) {
    const raw = m[1]
    const cleanDigits = raw.replace(/\D/g, "")
    if (cleanDigits.length === 12 && validateVerhoeff(cleanDigits)) {
      if (!seenMatches.has(raw)) {
        seenMatches.add(raw)
        findings.push({
          type: "Aadhaar",
          match: raw,
          maskedPreview: `XXXX-XXXX-${cleanDigits.slice(-4)}`,
          index: m.index,
        })
      }
    }
  }

  // 3. Payment cards: 13-19 digits (with optional spaces or dashes)
  const cardRegex = /\b([3-6][0-9]{3}[\s-]?[0-9]{4}[\s-]?[0-9]{4}[\s-]?[0-9]{1,7})\b/g
  while ((m = cardRegex.exec(text)) !== null) {
    const raw = m[1]
    const cleanDigits = raw.replace(/\D/g, "")
    if (cleanDigits.length >= 13 && cleanDigits.length <= 19 && validateLuhn(cleanDigits)) {
      if (!seenMatches.has(raw) && !seenMatches.has(cleanDigits)) {
        seenMatches.add(raw)
        findings.push({
          type: "Credit Card",
          match: raw,
          maskedPreview: `${cleanDigits.slice(0, 4)}-XXXX-XXXX-${cleanDigits.slice(-4)}`,
          index: m.index,
        })
      }
    }
  }

  // 4. Indian Phone Numbers: +91 optional, followed by 10 digits starting with 6,7,8,9
  const phoneRegex = /(?:\+91[\s-]?)?\b([6-9][0-9]{9})\b/g
  while ((m = phoneRegex.exec(text)) !== null) {
    const raw = m[0].trim()
    const num = m[1]
    if (!seenMatches.has(raw)) {
      seenMatches.add(raw)
      findings.push({
        type: "Phone",
        match: raw,
        maskedPreview: `+91 ${num.slice(0, 2)}XXXXXX${num.slice(-2)}`,
        index: m.index,
      })
    }
  }

  // 5. Emails
  const emailRegex = /\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b/g
  while ((m = emailRegex.exec(text)) !== null) {
    const raw = m[1]
    if (!seenMatches.has(raw)) {
      seenMatches.add(raw)
      const parts = raw.split("@")
      findings.push({
        type: "Email",
        match: raw,
        maskedPreview: `${parts[0].slice(0, 2)}***@${parts[1]}`,
        index: m.index,
      })
    }
  }

  return findings
}

/**
 * Replaces all detected PII in text with standardized statutory redaction tokens.
 */
export function redactPII(text: string): string {
  if (!text || typeof text !== "string") return text

  let redacted = text
  const findings = scanForPII(text)

  // Sort longest matches first to avoid partial replacements
  findings.sort((a, b) => b.match.length - a.match.length)

  for (const f of findings) {
    const token = `[REDACTED_${f.type.toUpperCase().replace(/\s+/g, "_")}]`
    redacted = redacted.split(f.match).join(token)
  }

  return redacted
}
