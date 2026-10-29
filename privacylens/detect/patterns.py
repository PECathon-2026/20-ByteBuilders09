"""
PrivacyLens - Regular Expression Patterns & Matchers
Comprehensive compiled patterns for sensitive data across Indian and global contexts.
"""

import re
from typing import List, Dict, Any, Tuple
from .validators import luhn, verhoeff, pan_check, ifsc_check, upi_check, email_check, phone_check, ip_check

# Card regex: matches 13 to 19 digits formatted with spaces or dashes
CARD_PATTERN = re.compile(
    r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11}|(?:4\d{3}|5[1-5]\d{2}|60\d{2}|65\d{2})[- ]?\d{4}[- ]?\d{4}[- ]?\d{4})\b"
)

# Aadhaar regex: 12 digits, often formatted in 3 groups of 4 (e.g., 2341 5678 9012)
AADHAAR_PATTERN = re.compile(
    r"\b[2-9]\d{3}[ -]?\d{4}[ -]?\d{4}\b"
)

# Indian PAN regex
PAN_PATTERN = re.compile(
    r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
    re.IGNORECASE
)

# UPI pattern
UPI_PATTERN = re.compile(
    r"\b[a-zA-Z0-9.\-_]{2,256}@(okhdfcbank|okaxis|oksbi|okicici|paytm|apl|ybl|icici|sbi|axisbank|fbl|federal|indus|postbank|airtel|kotak|barodampay|upi)\b",
    re.IGNORECASE
)

# Indian IFSC pattern
IFSC_PATTERN = re.compile(
    r"\b[A-Z]{4}0[A-Z0-9]{6}\b"
)

# Email address
EMAIL_PATTERN = re.compile(
    r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
)

# Phone: Indian mobile & international E.164
PHONE_PATTERN = re.compile(
    r"(?:\+91[\-\s]?)?[6789]\d{4}[\-\s]?\d{5}\b|(?:\+?[1-9]\d{1,2}[\-\s]?)?\(?\d{3}\)?[\-\s]?\d{3}[\-\s]?\d{4}\b"
)

# API Keys & Secrets
API_KEY_PATTERNS = [
    ("OPENAI_KEY", re.compile(r"\bsk-(?:proj|mock|test)-[a-zA-Z0-9_\-]{20,}\b|\bsk-[a-zA-Z0-9]{32,}\b")),
    ("AWS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("STRIPE_KEY", re.compile(r"\b(?:sk|rk)_(?:live|test|mock)_[0-9a-zA-Z]{20,}\b")),
    ("GITHUB_TOKEN", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{36,}\b")),
    ("VAULT_TOKEN", re.compile(r"\bs\.[a-zA-Z0-9]{20,}\b")),
    ("BEARER_TOKEN", re.compile(r"Bearer\s+([A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_=]*)", re.IGNORECASE))
]

# IPv4 Pattern
IP_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)

# CVV Pattern (3-4 digits in context of cvv, cvc, security code, security number)
CVV_CONTEXT_PATTERN = re.compile(
    r"(?i)\b(?:cvv|cvc|cvn|security\s*code|csc)\b[^\d]{1,10}(\d{3,4})\b"
)


def scan_text_patterns(text: str) -> List[Dict[str, Any]]:
    """
    Scans a given text string for all regex patterns with mathematical checksum verification.
    Returns structured findings:
    {type, value, start, end, confidence, reason, source="regex"}
    """
    findings = []

    # 1. Credit / Debit Cards
    for m in CARD_PATTERN.finditer(text):
        val = m.group(0)
        clean = re.sub(r"[\s\-]+", "", val)
        if luhn(clean):
            findings.append({
                "type": "CARD",
                "value": val,
                "start": m.start(),
                "end": m.end(),
                "confidence": 0.99,
                "reason": f"Luhn-valid credit card number ({clean[:4]}****)",
                "source": "regex+luhn"
            })

    # 2. Aadhaar Numbers (12-digit Verhoeff)
    for m in AADHAAR_PATTERN.finditer(text):
        val = m.group(0)
        clean = re.sub(r"[\s\-]+", "", val)
        if verhoeff(clean):
            findings.append({
                "type": "AADHAAR",
                "value": val,
                "start": m.start(),
                "end": m.end(),
                "confidence": 0.98,
                "reason": "Verhoeff-valid 12-digit Indian Aadhaar number",
                "source": "regex+verhoeff"
            })

    # 3. PAN
    for m in PAN_PATTERN.finditer(text):
        val = m.group(0).upper()
        if pan_check(val):
            findings.append({
                "type": "PAN",
                "value": val,
                "start": m.start(),
                "end": m.end(),
                "confidence": 0.95,
                "reason": f"Indian PAN syntax valid (entity: {val[3]})",
                "source": "regex"
            })

    # 4. UPI ID
    for m in UPI_PATTERN.finditer(text):
        val = m.group(0)
        findings.append({
            "type": "UPI",
            "value": val,
            "start": m.start(),
            "end": m.end(),
            "confidence": 0.97,
            "reason": f"Valid UPI VPA handle ({val.split('@')[-1]})",
            "source": "regex"
        })

    # 5. IFSC Code
    for m in IFSC_PATTERN.finditer(text):
        val = m.group(0)
        if ifsc_check(val):
            findings.append({
                "type": "IFSC",
                "value": val,
                "start": m.start(),
                "end": m.end(),
                "confidence": 0.96,
                "reason": f"Indian Bank IFSC code ({val[:4]})",
                "source": "regex"
            })

    # 6. Emails
    for m in EMAIL_PATTERN.finditer(text):
        val = m.group(0)
        # Avoid clashing with UPI
        if not UPI_PATTERN.match(val):
            findings.append({
                "type": "EMAIL",
                "value": val,
                "start": m.start(),
                "end": m.end(),
                "confidence": 0.98,
                "reason": "Standard email address",
                "source": "regex"
            })

    # 7. Phone Numbers
    for m in PHONE_PATTERN.finditer(text):
        val = m.group(0).strip()
        if phone_check(val):
            # Avoid overlap with Aadhaar or Card
            clean = re.sub(r"\D", "", val)
            if len(clean) in (10, 11, 12, 13) and not luhn(clean):
                findings.append({
                    "type": "PHONE",
                    "value": val,
                    "start": m.start(),
                    "end": m.end(),
                    "confidence": 0.90,
                    "reason": "Telephone / mobile number format",
                    "source": "regex"
                })

    # 8. API Keys & Cloud Secrets
    for label, pattern in API_KEY_PATTERNS:
        for m in pattern.finditer(text):
            val = m.group(0)
            findings.append({
                "type": "API_KEY",
                "value": val,
                "start": m.start(),
                "end": m.end(),
                "confidence": 0.99,
                "reason": f"High entropy cloud secret pattern ({label})",
                "source": "regex"
            })

    # 9. IP Addresses
    for m in IP_PATTERN.finditer(text):
        val = m.group(0)
        if ip_check(val):
            findings.append({
                "type": "IP_ADDRESS",
                "value": val,
                "start": m.start(),
                "end": m.end(),
                "confidence": 0.88,
                "reason": "IPv4 network address",
                "source": "regex"
            })

    # 10. CVV from context
    for m in CVV_CONTEXT_PATTERN.finditer(text):
        val = m.group(1)
        findings.append({
            "type": "CVV",
            "value": val,
            "start": m.start(1),
            "end": m.end(1),
            "confidence": 0.94,
            "reason": "CVV / security code in field context",
            "source": "regex+context"
        })

    return findings
