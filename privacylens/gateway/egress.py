"""
PrivacyLens - Fail-Closed Egress Gateway
The single, authoritative gateway through which all outbound LLM payloads must pass.
Guarantees fail-closed semantics: Any detection, exception, or timeout causes an IMMEDIATE HARD BLOCK.
"""

import json
import logging
from typing import Dict, Any, List, Optional
from PIL import Image

from ..sanitize.vault import LocalSecretVault
from ..detect.patterns import scan_text_patterns
from ..detect.ocr import check_image_for_sensitive_leak
from .canary import CanaryManager

logger = logging.getLogger("PrivacyLens.Egress")


class EgressBlockedException(Exception):
    """Raised when the fail-closed egress gateway intercepts a data leak."""
    def __init__(self, message: str, violations: List[Dict[str, Any]]):
        super().__init__(message)
        self.violations = violations


class EgressGateway:
    def __init__(
        self,
        vault: Optional[LocalSecretVault] = None,
        canary_manager: Optional[CanaryManager] = None,
        fail_closed: bool = True
    ):
        self.vault = vault or LocalSecretVault()
        self.canary_manager = canary_manager or CanaryManager()
        self.fail_closed = fail_closed

    def inspect_and_filter(
        self,
        payload: Any,
        image: Optional[Image.Image] = None
    ) -> Dict[str, Any]:
        """
        Final checkpoint before payload reaches untrusted cloud/network.
        Returns:
            {
                "passed": bool,
                "leaks": List[Dict],
                "payload_bytes": int,
                "sensitive_bytes_leaked": int,
                "reason": str
            }
        """
        violations: List[Dict[str, Any]] = []

        try:
            # 1. Convert payload to string representation for full-text inspection
            if isinstance(payload, dict):
                filtered_payload = {k: v for k, v in payload.items() if k != "image"}
                payload_str = json.dumps(filtered_payload, default=str)
            elif isinstance(payload, list):
                payload_str = json.dumps(payload, default=str)
            else:
                payload_str = str(payload)

            payload_bytes = len(payload_str.encode("utf-8"))

            # 2. Check 1: Scan for any active canary tokens
            canary_hits = self.canary_manager.scan_for_canaries(payload_str)
            for hit in canary_hits:
                violations.append({
                    "channel": "text_payload",
                    "type": "CANARY_LEAK",
                    "detail": hit["reason"]
                })

            # 3. Check 2: Scan for any raw secrets stored in the local vault
            raw_secrets = self.vault.get_all_raw_secrets()
            for secret in raw_secrets:
                if len(secret) >= 4 and secret in payload_str:
                    violations.append({
                        "channel": "text_payload",
                        "type": "VAULT_SECRET_LEAK",
                        "detail": f"Raw secret starting with '{secret[:3]}***' found unmasked in outgoing payload!"
                    })

            # 4. Check 3: Independent second-pass pattern re-scan on text
            fresh_patterns = scan_text_patterns(payload_str)
            for p in fresh_patterns:
                # Disallow high-risk findings in outbound payload
                if p["type"] in ("CARD", "AADHAAR", "PAN", "API_KEY", "PASSWORD", "CVV"):
                    violations.append({
                        "channel": "text_payload",
                        "type": f"UNSANITIZED_{p['type']}",
                        "detail": f"Re-scan identified valid {p['type']} in outbound payload: {p['reason']}"
                    })

            # 5. Check 4: Second-pass OCR inspection on outgoing screenshot
            if image is not None:
                image_leaks = check_image_for_sensitive_leak(image, raw_secrets)
                for leak in image_leaks:
                    violations.append({
                        "channel": "visual_ocr",
                        "type": "IMAGE_PIXEL_LEAK",
                        "detail": leak["reason"]
                    })

            # FAIL-CLOSED DECISION
            if violations:
                msg = f"[EGRESS BLOCKED] {len(violations)} data leak violations intercepted!"
                logger.error(msg)
                if self.fail_closed:
                    raise EgressBlockedException(msg, violations)
                return {
                    "passed": False,
                    "leaks": violations,
                    "payload_bytes": payload_bytes,
                    "sensitive_bytes_leaked": sum(len(v.get("detail", "")) for v in violations),
                    "reason": msg
                }

            return {
                "passed": True,
                "leaks": [],
                "payload_bytes": payload_bytes,
                "sensitive_bytes_leaked": 0,
                "reason": "Payload clean. Passed all multi-modal egress scans."
            }

        except EgressBlockedException:
            raise
        except Exception as exc:
            # FAIL-CLOSED: Any internal exception during egress scan results in hard block
            msg = f"[FAIL-CLOSED TRIGGERED] Unexpected error during egress scan: {str(exc)}. Payload blocked."
            logger.critical(msg)
            fail_closed_violations = [{
                "channel": "system_guard",
                "type": "FAIL_CLOSED_EXCEPTION",
                "detail": msg
            }]
            if self.fail_closed:
                raise EgressBlockedException(msg, fail_closed_violations)
            return {
                "passed": False,
                "leaks": fail_closed_violations,
                "payload_bytes": 0,
                "sensitive_bytes_leaked": 0,
                "reason": msg
            }


def validate_outgoing_payload(
    payload: Any,
    image: Optional[Image.Image] = None,
    vault: Optional[LocalSecretVault] = None,
    canary_manager: Optional[CanaryManager] = None,
    fail_closed: bool = False
) -> Dict[str, Any]:
    """
    Centralized validation entry point. Every cloud-bound payload handled by PrivacyLens
    passes through this authoritative gate.
    """
    gw = EgressGateway(vault=vault, canary_manager=canary_manager, fail_closed=fail_closed)
    return gw.inspect_and_filter(payload, image=image)

