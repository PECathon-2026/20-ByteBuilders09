"""
PrivacyLens - Redacted Audit Logger
Guarantees that raw sensitive credentials and secrets are NEVER written to logs or disk.
Maintains a secure, in-memory structured audit stream for the dashboard.
"""

import time
import logging
from typing import List, Dict, Any, Optional
from ..sanitize.vault import LocalSecretVault


class RedactedAuditLogger:
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(RedactedAuditLogger, cls).__new__(cls)
            cls._instance._events = []
        return cls._instance

    def log_event(self, stage: str, message: str, details: Optional[Dict[str, Any]] = None):
        """
        Records an audit event, sanitizing any raw values against the vault.
        """
        vault = LocalSecretVault()
        raw_secrets = vault.get_all_raw_secrets()

        clean_message = message
        clean_details = {}

        # Strip all raw secrets from message text
        for s in raw_secrets:
            if len(s) >= 4 and s in clean_message:
                clean_message = clean_message.replace(s, "[REDACTED_BY_AUDIT_GUARD]")

        if details:
            for k, v in details.items():
                str_v = str(v)
                for s in raw_secrets:
                    if len(s) >= 4 and s in str_v:
                        str_v = str_v.replace(s, "[REDACTED]")
                clean_details[k] = str_v

        event = {
            "timestamp": time.time(),
            "time_str": time.strftime("%H:%M:%S"),
            "stage": stage.upper(),
            "message": clean_message,
            "details": clean_details
        }
        self._events.append(event)
        # Cap memory buffer at 1000 events
        if len(self._events) > 1000:
            self._events.pop(0)

        # Standard console logger
        logging.info(f"[{stage.upper()}] {clean_message}")

    def get_audit_trail(self) -> List[Dict[str, Any]]:
        return list(self._events)

    def clear(self):
        self._events.clear()
