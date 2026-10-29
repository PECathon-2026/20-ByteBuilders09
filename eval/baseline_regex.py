"""
PrivacyLens Evaluation Suite - Baseline Redactor (Text-Only Regex)
Represents typical existing proxy gateways that only perform simple regex over visible text.
FLAWS / VULNERABILITIES DEMONSTRATED:
1. Ignores hidden DOM elements (leaks trap data in data attributes & display:none).
2. Does NOT redact screenshots (leaks sensitive credentials visually to multimodal LLMs).
3. Does NOT clean URL parameters or document metadata.
4. Does NOT support secret injection (forces LLM to either guess or drop data).
5. No fail-closed egress gateway.
"""

import re
from typing import Dict, Any, List

# Basic naive regex without Luhn or Verhoeff validation
NAIVE_CARD_REGEX = re.compile(r"\b\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4}\b")
NAIVE_EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")
NAIVE_PHONE_REGEX = re.compile(r"\b\d{10}\b")


class BaselineRegexRedactor:
    def __init__(self):
        self.name = "Baseline (Text-Only Regex)"

    def sanitize(self, snapshot: Dict[str, Any]) -> Dict[str, Any]:
        """
        Performs naive text substitution on visible text only.
        Leaves hidden DOM, screenshots, and URLs completely unprotected!
        """
        raw_text = snapshot.get("text", "")

        # Naive text replacement
        clean_text = NAIVE_CARD_REGEX.sub("[CARD_REDACTED]", raw_text)
        clean_text = NAIVE_EMAIL_REGEX.sub("[EMAIL_REDACTED]", clean_text)
        clean_text = NAIVE_PHONE_REGEX.sub("[PHONE_REDACTED]", clean_text)

        # Baseline flaw: Leaves screenshot 100% UNTOUCHED (raw credentials exposed)
        raw_image = snapshot.get("image")

        # Baseline flaw: Leaves hidden DOM elements intact
        # Baseline flaw: Leaves raw URL query parameters intact
        return {
            "title": snapshot.get("title", ""),
            "url": snapshot.get("url", ""),
            "text": clean_text,
            "nodes": snapshot.get("nodes", []),  # Hidden nodes NOT cleaned
            "image": raw_image,  # Raw screenshot leaked
            "storage_stripped": False
        }
