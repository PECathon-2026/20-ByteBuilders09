"""
PrivacyLens - Text Sanitizer
Performs deterministic, consistent tokenization of text strings, replacing sensitive
values with vault tokens (e.g., [CARD_1], [PAN_1], [PERSON_1]).
"""

import re
from typing import List, Dict, Any, Tuple
from .vault import LocalSecretVault


def sanitize_text(
    text: str,
    findings: List[Dict[str, Any]],
    vault: LocalSecretVault
) -> str:
    """
    Substitutes detected sensitive values in text with consistent tokens stored in the vault.
    Sorts findings by value length descending to prevent partial token collision.
    """
    if not text:
        return ""

    sanitized = text

    # Sort by value length descending to ensure full strings replaced before subsets
    sorted_findings = sorted(
        findings,
        key=lambda f: len(str(f.get("value", ""))),
        reverse=True
    )

    for finding in sorted_findings:
        raw_val = str(finding.get("value", "")).strip()
        if not raw_val:
            continue

        sens_type = finding.get("type", "SECRET")
        prefix = sens_type.upper()

        # Allocate consistent token in RAM vault
        token = vault.allocate_token(
            token_prefix=prefix,
            real_value=raw_val,
            metadata={
                "type": sens_type,
                "confidence": finding.get("confidence", 1.0),
                "reason": finding.get("reason", "Text pattern match"),
                "source": finding.get("source", "text_sanitizer")
            }
        )

        # Replace exact literal match as well as variations without spaces/dashes
        clean_raw = re.sub(r"[\s\-]+", "", raw_val)
        if len(clean_raw) >= 6 and clean_raw != raw_val:
            # Also replace compact version if present
            sanitized = re.sub(re.escape(clean_raw), token, sanitized)

        # Replace raw value literally
        sanitized = sanitized.replace(raw_val, token)

    return sanitized
