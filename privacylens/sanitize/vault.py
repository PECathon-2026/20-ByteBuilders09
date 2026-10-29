"""
PrivacyLens - In-Memory Secret Vault
Securely stores tokens to real secrets in RAM only.
CRITICAL SECURITY GUARANTEES:
1. Secrets are NEVER serialized to disk, localStorage, or persistent databases.
2. Secrets are NEVER logged to console or log files.
3. Token mappings are consistent within a session (same secret gets same token).
"""

import threading
from typing import Dict, Optional, Any, List


class LocalSecretVault:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(LocalSecretVault, cls).__new__(cls)
                cls._instance._token_to_secret = {}
                cls._instance._secret_to_token = {}
                cls._instance._token_counters = {}
                cls._instance._metadata = {}
        return cls._instance

    def clear(self):
        """Purges all in-memory vault contents."""
        with self._lock:
            self._token_to_secret.clear()
            self._secret_to_token.clear()
            self._token_counters.clear()
            self._metadata.clear()

    def allocate_token(self, token_prefix: str, real_value: str, metadata: Optional[Dict[str, Any]] = None) -> str:
        """
        Retrieves existing token for real_value or allocates a new consistent token.
        E.g., allocate_token("CARD", "4532...") -> "[CARD_1]"
        """
        with self._lock:
            clean_secret = str(real_value).strip()
            # If already mapped, return identical token for consistency
            if clean_secret in self._secret_to_token:
                return self._secret_to_token[clean_secret]

            # Generate new sequential token for this prefix
            curr_count = self._token_counters.get(token_prefix, 0) + 1
            self._token_counters[token_prefix] = curr_count
            token = f"[{token_prefix}_{curr_count}]"

            self._token_to_secret[token] = clean_secret
            self._secret_to_token[clean_secret] = token
            self._metadata[token] = metadata or {}
            return token

    def get_real_value(self, token: str) -> Optional[str]:
        """Resolves token back to real secret for local executor injection."""
        with self._lock:
            return self._token_to_secret.get(token)

    def get_all_raw_secrets(self) -> List[str]:
        """Returns list of all current raw secrets for fail-closed egress scanning."""
        with self._lock:
            return list(self._secret_to_token.keys())

    def get_token_summary(self) -> List[Dict[str, Any]]:
        """
        Returns safe summary metadata (tokens, types, risk) WITHOUT raw values,
        safe for dashboard and audit logging.
        """
        with self._lock:
            summary = []
            for token, meta in self._metadata.items():
                summary.append({
                    "token": token,
                    "type": meta.get("type", "UNKNOWN"),
                    "mode": meta.get("mode", "inject"),
                    "confidence": meta.get("confidence", 1.0),
                    "reason": meta.get("reason", "Detected sensitive value")
                })
            return summary
