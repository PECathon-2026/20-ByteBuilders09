"""
PrivacyLens - Local Executor & Secret Injector
USP 1: Secret Injection Engine
The LLM plans actions using tokens (e.g., [CARD_1], [CVV_1]).
The Local Executor resolves the tokens against the in-memory RAM vault and injects
the real secrets directly into the local browser DOM. Secrets NEVER leave the trusted boundary.
"""

import re
import time
from typing import Dict, Any, List, Optional
from ..sanitize.vault import LocalSecretVault


class LocalExecutor:
    def __init__(self, vault: Optional[LocalSecretVault] = None):
        self.vault = vault or LocalSecretVault()

    def execute_action(
        self,
        action: Dict[str, Any],
        element_map: Dict[str, Any],
        page: Any
    ) -> Dict[str, Any]:
        """
        Executes an action in the browser.
        Performs local secret injection when tokens are present in input values.
        """
        action_name = action.get("action", "").lower()
        injected_tokens = []

        if action_name == "done":
            return {"status": "SUCCESS", "message": action.get("summary", "Complete")}

        if action_name == "wait":
            seconds = action.get("seconds", 1)
            time.sleep(min(seconds, 5))
            return {"status": "SUCCESS", "message": f"Waited {seconds}s"}

        element_id = action.get("element_id")
        elem_meta = element_map.get(element_id, {})
        selector = elem_meta.get("selector")

        if not selector and action_name not in ("scroll",):
            return {"status": "FAILED", "error": f"Selector not found for {element_id}"}

        try:
            if action_name == "click":
                # Scroll element into view and click
                page.locator(selector).first.scroll_into_view_if_needed()
                page.locator(selector).first.click(timeout=5000)
                page.wait_for_timeout(300)
                return {
                    "status": "SUCCESS",
                    "action": "click",
                    "element_id": element_id,
                    "selector": selector
                }

            elif action_name == "type":
                raw_input_value = str(action.get("value", ""))

                # SECRET INJECTION LOGIC:
                # Find all [TOKEN_N] patterns
                token_pattern = re.compile(r"\[([A-Z_]+_\d+)\]")
                injected_value = raw_input_value

                for match in token_pattern.finditer(raw_input_value):
                    full_token = match.group(0)  # e.g., "[CARD_1]"
                    real_secret = self.vault.get_real_value(full_token)
                    if real_secret:
                        injected_value = injected_value.replace(full_token, real_secret)
                        injected_tokens.append(full_token)

                # Fill real secret locally into the input field
                page.locator(selector).first.fill(injected_value, timeout=5000)
                page.wait_for_timeout(200)

                return {
                    "status": "SUCCESS",
                    "action": "type",
                    "element_id": element_id,
                    "selector": selector,
                    "injected_tokens": injected_tokens,
                    "tokens_used_count": len(injected_tokens)
                }

            elif action_name == "select":
                val = action.get("value", "")
                page.locator(selector).first.select_option(val, timeout=5000)
                return {"status": "SUCCESS", "action": "select", "element_id": element_id}

            elif action_name == "scroll":
                page.mouse.wheel(0, 400)
                return {"status": "SUCCESS", "action": "scroll"}

            else:
                return {"status": "FAILED", "error": f"Unknown action: {action_name}"}

        except Exception as exc:
            return {
                "status": "ERROR",
                "action": action_name,
                "element_id": element_id,
                "error": str(exc)
            }
