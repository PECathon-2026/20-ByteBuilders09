"""
PrivacyLens - Prompt Injection & Malicious Content Detector
Guards against indirect prompt injections, hidden adversarial instructions, and exfiltration attempts.
"""

import re
from typing import List, Dict, Any

INJECTION_SIGNATURES = [
    (re.compile(r"(?i)\bignore\s+(all\s+)?(previous|prior)\s+(instructions|directives|rules|constraints)\b"), "INDIRECT_PROMPT_INJECTION", "Attempt to override agent constraints"),
    (re.compile(r"(?i)\b(system\s*(override|alert|prompt)|emergency\s*debug\s*mode)\b"), "SYSTEM_PROMPT_MIMICRY", "Adversarial system prompt mimicry"),
    (re.compile(r"(?i)\b(exfiltrate|leak|steal|send\s+data\s+to|drop\s+all\s+user\s+security)\b"), "DATA_EXFILTRATION_INTENT", "Instruction to exfiltrate credentials or bypass security"),
    (re.compile(r"(?i)\b(?:https?://)?(?:[a-zA-Z0-9.\-]+\.)?(?:attacker|malicious|evil|exfil|pwned)\.[a-z]{2,}(?:/[^\s]*)?\b"), "MALICIOUS_DOMAIN", "Known adversarial exfiltration endpoint"),
    (re.compile(r"(?i)\b(navigate|fetch|curl|wget)\s+https?://[^\s]+\b"), "UNAUTHORIZED_NETWORK_CALL", "Attempt to force unapproved outbound request")
]


def detect_prompt_injections(text: str, nodes: List[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """
    Inspects page text and hidden DOM nodes for indirect prompt injection attack payloads.
    Returns: [{type, text_snippet, reason, severity, selector}]
    """
    alerts = []

    # 1. Full text pattern scanning
    for pat, attack_type, reason in INJECTION_SIGNATURES:
        for m in pat.finditer(text):
            alerts.append({
                "type": attack_type,
                "text_snippet": m.group(0),
                "reason": reason,
                "severity": "CRITICAL"
            })

    # 2. Hidden node inspection (off-screen or opacity 0)
    if nodes:
        for node in nodes:
            if node.get("isHidden"):
                node_text = (node.get("textContent") or "") + " " + str(node.get("attributes", {}))
                for pat, attack_type, reason in INJECTION_SIGNATURES:
                    if pat.search(node_text):
                        alerts.append({
                            "type": attack_type,
                            "text_snippet": node_text[:80],
                            "reason": f"Hidden DOM node vector ({reason})",
                            "severity": "CRITICAL",
                            "selector": node.get("selector")
                        })

    return alerts


def sanitize_injections(text: str) -> str:
    """Neutralizes detected adversarial prompt injection phrases from LLM input."""
    sanitized = text
    for pat, _, _ in INJECTION_SIGNATURES:
        sanitized = pat.sub("[FLAGGED_ADVERSARIAL_INJECTION_REMOVED]", sanitized)
    return sanitized
