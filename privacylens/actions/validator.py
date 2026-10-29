"""
PrivacyLens - Action Validator
Enforces action allowlists, ensures element_ids exist on the active page,
validates that input values do not leak raw sensitive data, and guards against unauthorized cross-domain navigation.
"""

import re
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse
from ..detect.patterns import scan_text_patterns

ALLOWED_ACTIONS = {"click", "type", "select", "scroll", "wait", "done"}


class ActionValidationError(Exception):
    pass


class ActionValidator:
    def __init__(self, allowed_domains: Optional[List[str]] = None):
        self.allowed_domains = allowed_domains or [
            "localhost", "127.0.0.1", "shoekart.test", "defense-systems.internal"
        ]

    def validate_action(
        self,
        action_dict: Dict[str, Any],
        element_map: Dict[str, Any],
        current_url: str
    ) -> Dict[str, Any]:
        """
        Validates LLM proposed action.
        Returns validated action dict or raises ActionValidationError.
        """
        if not isinstance(action_dict, dict):
            raise ActionValidationError(f"Invalid action payload format: expected JSON dict, got {type(action_dict)}")

        action_name = action_dict.get("action", "").lower()

        # 1. Action allowlist check
        if action_name not in ALLOWED_ACTIONS:
            raise ActionValidationError(
                f"Action '{action_name}' is not permitted. Allowed actions: {list(ALLOWED_ACTIONS)}"
            )

        if action_name == "done":
            return action_dict

        if action_name in ("scroll", "wait"):
            return action_dict

        # 2. Element existence check
        element_id = action_dict.get("element_id")
        if not element_id:
            raise ActionValidationError(f"Action '{action_name}' requires an 'element_id'")

        if element_id not in element_map:
            raise ActionValidationError(
                f"Element ID '{element_id}' does not exist in current sanitized DOM map!"
            )

        # 3. Value check for 'type' action:
        if action_name == "type":
            val = str(action_dict.get("value", ""))
            # If the LLM tries to type a raw card/Aadhaar/PAN without token
            raw_findings = scan_text_patterns(val)
            for f in raw_findings:
                if f["type"] in ("CARD", "AADHAAR", "PAN", "API_KEY", "PASSWORD", "CVV"):
                    raise ActionValidationError(
                        f"REJECTED: Unsanitized raw {f['type']} passed directly in action value! Must use token."
                    )

        # 4. Domain allowlist check for navigation
        if action_name == "navigate":
            target_url = action_dict.get("url", "")
            domain = urlparse(target_url).hostname or ""
            if domain and not any(allowed in domain for allowed in self.allowed_domains):
                raise ActionValidationError(
                    f"REJECTED: Navigation to untrusted external domain '{domain}' blocked!"
                )

        return action_dict
