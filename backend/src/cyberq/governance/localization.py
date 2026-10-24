"""Bilingual localization schema for Indian banking statutory tokens (English + Rajbhasha Hindi)."""

from typing import Any

STATUTORY_TOKENS: dict[str, dict[str, str]] = {
    # Regulators & Portals
    "REGULATOR_RBI": {
        "en": "Reserve Bank of India (RBI)",
        "hi": "भारतीय रिज़र्व बैंक (आरबीआई)",
    },
    "REGULATOR_CERT_IN": {
        "en": "Indian Computer Emergency Response Team (CERT-In)",
        "hi": "भारतीय कंप्यूटर आपातकालीन प्रतिक्रिया दल (सर्ट-इन)",
    },
    "REGULATOR_DPDP": {
        "en": "Data Protection Board of India (DPDP)",
        "hi": "भारतीय डेटा संरक्षण बोर्ड (डीपीडीपी)",
    },
    "PORTAL_DAKSH": {
        "en": "RBI DAKSH Supervisory Portal",
        "hi": "भारतीय रिज़र्व बैंक दक्ष पर्यवेक्षी पोर्टल",
    },
    # Filing Packet Types
    "FILING_CERT_IN_INITIAL": {
        "en": "CERT-In Statutory 6-Hour Initial Incident Notice",
        "hi": "सर्ट-इन वैधानिक 6-घंटे की प्रारंभिक घटना सूचना",
    },
    "FILING_RBI_DAKSH": {
        "en": "RBI DAKSH Cyber Security Incident Report (Para 182)",
        "hi": "आरबीआई दक्ष साइबर सुरक्षा घटना रिपोर्ट (पैरा 182)",
    },
    "FILING_DPDP_BREACH": {
        "en": "DPDP Data Protection Board Breach Notification (Rule 7)",
        "hi": "डीपीडीपी डेटा संरक्षण बोर्ड उल्लंघन अधिसूचना (नियम 7)",
    },
    # Risk Decision Ledger (CISO Actions)
    "DECISION_ACCEPT": {
        "en": "Risk Acceptance",
        "hi": "जोखिम स्वीकृति",
    },
    "DECISION_MITIGATE": {
        "en": "Risk Mitigation",
        "hi": "जोखिम शमन",
    },
    "DECISION_TRANSFER": {
        "en": "Risk Transfer",
        "hi": "जोखिम अंतरण",
    },
    "DECISION_AVOID": {
        "en": "Risk Avoidance",
        "hi": "जोखिम परिहार",
    },
    "DECISION_REGULATORY_DEFERRAL": {
        "en": "Regulatory Deferral",
        "hi": "नियामक स्थगन",
    },
    "DECISION_POLICY_EXCEPTION": {
        "en": "Policy Exception",
        "hi": "नीतिगत अपवाद",
    },
    # Exceptions Register
    "EXCEPTIONS_REGISTER_TITLE": {
        "en": "RBI Para 59 Technical Exceptions Register",
        "hi": "आरबीआई पैरा 59 तकनीकी अपवाद रजिस्टर",
    },
    "STATUS_ACTIVE": {
        "en": "Active",
        "hi": "सक्रिय",
    },
    "STATUS_EXPIRING_SOON": {
        "en": "Expiring Soon (<= 15 Days)",
        "hi": "शीघ्र समाप्त (15 दिन या उससे कम)",
    },
    "STATUS_EXPIRED": {
        "en": "Expired",
        "hi": "समाप्त",
    },
    "STATUS_REMEDIATED": {
        "en": "Remediated",
        "hi": "उपचारित",
    },
    "STATUS_REVOKED": {
        "en": "Revoked",
        "hi": "निरस्त",
    },
    "COMPENSATING_CONTROLS": {
        "en": "Compensating Controls",
        "hi": "क्षतिपूरक नियंत्रण",
    },
    # Board Pack Governance
    "BOARD_PACK_TITLE": {
        "en": "Quarterly Cyber Risk Board Pack (RBI Para 28(7))",
        "hi": "त्रैमासिक साइबर जोखिम बोर्ड पैक (आरबीआई पैरा 28(7))",
    },
    "EXECUTIVE_SUMMARY": {
        "en": "Executive Summary",
        "hi": "कार्यकारी सारांश",
    },
    "RUPEE_EXPOSURE": {
        "en": "Value at Risk (VaR) & Rupee Exposure",
        "hi": "जोखिम मूल्य (VaR) एवं रुपये में प्रभाव",
    },
    "MAKER_CHECKER_VERIFICATION": {
        "en": "Maker-Checker Dual Control Verification",
        "hi": "निर्माता-जांचकर्ता दोहरा नियंत्रण सत्यापन",
    },
    "CONFIDENTIAL_BANNER": {
        "en": "STRICTLY CONFIDENTIAL - BOARD OF DIRECTORS ONLY",
        "hi": "अत्यंत गोपनीय - केवल निदेशक मंडल के लिए",
    },
}

# Standard normalization lookup
KEY_ALIASES: dict[str, str] = {
    "accept": "DECISION_ACCEPT",
    "risk acceptance": "DECISION_ACCEPT",
    "mitigate": "DECISION_MITIGATE",
    "risk mitigation": "DECISION_MITIGATE",
    "transfer": "DECISION_TRANSFER",
    "risk transfer": "DECISION_TRANSFER",
    "avoid": "DECISION_AVOID",
    "risk avoidance": "DECISION_AVOID",
    "regulatory deferral": "DECISION_REGULATORY_DEFERRAL",
    "policy exception": "DECISION_POLICY_EXCEPTION",
    "active": "STATUS_ACTIVE",
    "expiring_soon": "STATUS_EXPIRING_SOON",
    "expired": "STATUS_EXPIRED",
    "remediated": "STATUS_REMEDIATED",
    "revoked": "STATUS_REVOKED",
    "cert-in": "REGULATOR_CERT_IN",
    "rbi": "REGULATOR_RBI",
    "dpdp": "REGULATOR_DPDP",
    "daksh": "PORTAL_DAKSH",
}


def get_token(key: str, lang: str = "en") -> str:
    """Retrieves statutory token in requested language ('en' or 'hi')."""
    normalized_key = KEY_ALIASES.get(key.strip().lower(), key.strip().upper())
    entry = STATUTORY_TOKENS.get(normalized_key)
    if entry:
        return entry.get(lang.lower(), entry.get("en", key))
    return key


def get_bilingual_label(key: str) -> str:
    """Returns bilingual representation: English / Hindi."""
    normalized_key = KEY_ALIASES.get(key.strip().lower(), key.strip().upper())
    entry = STATUTORY_TOKENS.get(normalized_key)
    if entry:
        return f"{entry['en']} / {entry['hi']}"
    return key


def localize_dict(data: dict[str, Any], lang: str = "en") -> dict[str, Any]:
    """Recursively replaces known string tokens in dictionary with localized text."""
    res: dict[str, Any] = {}
    for k, v in data.items():
        if isinstance(v, str):
            res[k] = get_token(v, lang)
        elif isinstance(v, dict):
            res[k] = localize_dict(v, lang)
        elif isinstance(v, list):
            res[k] = [
                localize_dict(item, lang) if isinstance(item, dict) else (get_token(item, lang) if isinstance(item, str) else item)
                for item in v
            ]
        else:
            res[k] = v
    return res
