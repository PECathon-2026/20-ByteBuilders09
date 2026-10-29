"""
PrivacyLens - Canary Leakage Benchmark Module
Generates trackable synthetic canary tokens and validates that ZERO canaries leak into cloud payloads.
"""

import re
import secrets
from typing import List, Dict, Any, Set


class CanaryManager:
    def __init__(self, prefix: str = "CANARY_PL"):
        self.prefix = prefix
        self._active_canaries: Set[str] = set()

    def generate_canary(self, label: str = "generic") -> str:
        """Generates a cryptographically random canary string."""
        entropy = secrets.token_hex(8).upper()
        canary = f"{self.prefix}_{label.upper()}_{entropy}"
        self._active_canaries.add(canary)
        return canary

    def scan_for_canaries(self, text: str) -> List[Dict[str, Any]]:
        """Scans arbitrary text or serialized payload for any active canary tokens."""
        leaks = []
        if not text:
            return leaks

        for canary in self._active_canaries:
            if canary in text:
                leaks.append({
                    "canary": canary,
                    "reason": f"Canary token '{canary}' detected in outgoing payload!",
                    "severity": "CRITICAL"
                })
        return leaks

    def get_active_count(self) -> int:
        return len(self._active_canaries)

    def clear(self):
        self._active_canaries.clear()
