"""
PrivacyLens - Structural DOM Detector
Detects sensitive fields by inspecting HTML tag attributes, autocomplete standards,
input types, accessibility semantics, form labels, and hidden elements.
"""

import re
from typing import List, Dict, Any, Optional

# Standard autocomplete mappings according to WHATWG HTML spec
AUTOCOMPLETE_MAP = {
    "cc-number": ("CARD", 0.99, "autocomplete='cc-number' attribute"),
    "cc-csc": ("CVV", 0.99, "autocomplete='cc-csc' attribute"),
    "cc-exp": ("CARD_EXP", 0.95, "autocomplete='cc-exp' attribute"),
    "current-password": ("PASSWORD", 0.99, "autocomplete='current-password' attribute"),
    "new-password": ("PASSWORD", 0.99, "autocomplete='new-password' attribute"),
    "one-time-code": ("OTP", 0.99, "autocomplete='one-time-code' attribute"),
    "tel": ("PHONE", 0.90, "autocomplete='tel' attribute"),
    "email": ("EMAIL", 0.95, "autocomplete='email' attribute"),
    "street-address": ("ADDRESS", 0.90, "autocomplete='street-address' attribute"),
    "name": ("PERSON", 0.85, "autocomplete='name' attribute")
}

LABEL_HINTS = [
    (re.compile(r"\b(card\s*number|credit\s*card|debit\s*card)\b", re.I), "CARD", 0.95),
    (re.compile(r"\b(cvv|cvc|security\s*code|csc)\b", re.I), "CVV", 0.96),
    (re.compile(r"\b(password|passcode|secret\s*pin)\b", re.I), "PASSWORD", 0.98),
    (re.compile(r"\b(otp|one[\s\-]*time[\s\-]*password|verification\s*code)\b", re.I), "OTP", 0.97),
    (re.compile(r"\b(aadhaar|uidai)\b", re.I), "AADHAAR", 0.95),
    (re.compile(r"\b(pan\s*card|pan\s*number)\b", re.I), "PAN", 0.95),
    (re.compile(r"\b(upi\s*id|vpa|upi\s*handle)\b", re.I), "UPI", 0.95),
    (re.compile(r"\b(delivery\s*address|billing\s*address|shipping\s*address)\b", re.I), "ADDRESS", 0.90)
]


def scan_dom_node(node: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Analyzes an individual DOM node dict (extracted via Playwright snapshot or DOM tree)
    Returns list of sensitive findings with explainable reason.
    """
    findings = []
    tag = node.get("tagName", "").lower()
    attributes = node.get("attributes", {})
    input_type = attributes.get("type", "").lower()
    autocomplete = attributes.get("autocomplete", "").lower()
    name_attr = attributes.get("name", "").lower()
    id_attr = attributes.get("id", "").lower()
    label_text = node.get("labelText", "").lower()
    placeholder = attributes.get("placeholder", "").lower()
    value = node.get("value", "") or node.get("textContent", "")
    is_hidden = node.get("isHidden", False) or attributes.get("aria-hidden") == "true" or "display: none" in attributes.get("style", "")
    selector = node.get("selector", f"#{id_attr}" if id_attr else tag)

    # 1. Direct input type = password
    if input_type == "password" and value:
        findings.append({
            "type": "PASSWORD",
            "value": value,
            "selector": selector,
            "confidence": 0.99,
            "reason": "DOM structure: input[type=password]",
            "source": "dom:structural",
            "is_hidden": is_hidden
        })

    # 2. Autocomplete attribute matching
    if autocomplete in AUTOCOMPLETE_MAP and value:
        sens_type, conf, desc = AUTOCOMPLETE_MAP[autocomplete]
        findings.append({
            "type": sens_type,
            "value": value,
            "selector": selector,
            "confidence": conf,
            "reason": f"DOM structure: {desc}",
            "source": "dom:autocomplete",
            "is_hidden": is_hidden
        })

    # 3. Label / placeholder hints
    combined_context = f"{label_text} {placeholder} {name_attr} {id_attr}"
    for pattern, sens_type, conf in LABEL_HINTS:
        if pattern.search(combined_context) and value:
            # Avoid duplicate if already caught by type or autocomplete
            if not any(f["type"] == sens_type for f in findings):
                findings.append({
                    "type": sens_type,
                    "value": value,
                    "selector": selector,
                    "confidence": conf,
                    "reason": f"DOM context: Associated label/attribute matches '{pattern.pattern}'",
                    "source": "dom:label",
                    "is_hidden": is_hidden
                })

    # 4. Hidden element traps (e.g. data attributes, aria-hidden backup cards)
    if is_hidden:
        for attr_k, attr_v in attributes.items():
            if any(term in attr_k.lower() for term in ["card", "secret", "token", "key", "password", "backup"]):
                findings.append({
                    "type": "CARD" if "card" in attr_k.lower() else "API_KEY",
                    "value": str(attr_v),
                    "selector": selector,
                    "confidence": 0.96,
                    "reason": f"DOM hidden trap: {attr_k} attribute on hidden element",
                    "source": "dom:hidden",
                    "is_hidden": True
                })

    return findings


def detect_split_otp(nodes: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """
    Detects split OTP inputs (e.g. 6 separate 1-char input boxes side by side).
    """
    otp_inputs = []
    parent_selector = None

    for node in nodes:
        attrs = node.get("attributes", {})
        classes = attrs.get("class", "")
        maxlength = attrs.get("maxlength", "")
        val = node.get("value", "")

        is_otp_candidate = (
            ("otp" in classes.lower() or "code" in classes.lower() or attrs.get("autocomplete") == "one-time-code")
            and maxlength in ("1", "2")
            and (val.isdigit() or val == "")
        )
        if is_otp_candidate:
            otp_inputs.append((node, val))

    if len(otp_inputs) in (4, 6, 8):
        combined_code = "".join([v for _, v in otp_inputs])
        selectors = [n.get("selector", "") for n, _ in otp_inputs]
        return {
            "type": "OTP",
            "value": combined_code,
            "selector": f"{selectors[0]}...{selectors[-1]}",
            "confidence": 0.98,
            "reason": f"DOM structure: Split OTP input sequence ({len(otp_inputs)} digits: '{combined_code}')",
            "source": "dom:split_otp",
            "sub_selectors": selectors
        }
    return None
