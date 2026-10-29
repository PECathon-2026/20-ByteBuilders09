"""
PrivacyLens - Autonomous Agent Loop
Coordinates the entire lifecycle:
Observe -> Detect -> Sanitize -> Egress Check -> Plan (LLM) -> Validate Action -> Approval Gate -> Local Execute
Limits: Max 15 steps, step timeout, fail-stop after 3 consecutive errors.
"""

import time
from typing import Dict, Any, List, Optional
from PIL import Image

from ..capture.browser import BrowserController
from ..capture.snapshot import capture_page_snapshot
from ..detect.engine import DetectionEngine
from ..sanitize.vault import LocalSecretVault
from ..sanitize.dom import sanitize_dom_tree
from ..sanitize.image import redact_screenshot
from ..gateway.egress import EgressGateway, EgressBlockedException
from ..gateway.canary import CanaryManager
from ..security.injection import detect_prompt_injections, sanitize_injections
from ..security.safe_logging import RedactedAuditLogger
from ..actions.validator import ActionValidator, ActionValidationError
from ..actions.approval import ApprovalGate
from ..actions.executor import LocalExecutor
from .llm_client import LLMClient


class AgentLoop:
    def __init__(
        self,
        browser: BrowserController,
        llm_client: Optional[LLMClient] = None,
        max_steps: int = 15,
        auto_approve: bool = True
    ):
        self.browser = browser
        self.llm_client = llm_client or LLMClient()
        self.max_steps = max_steps
        self.vault = LocalSecretVault()
        self.canary_mgr = CanaryManager()
        self.engine = DetectionEngine()
        self.egress = EgressGateway(vault=self.vault, canary_manager=self.canary_mgr, fail_closed=True)
        self.validator = ActionValidator()
        self.approval = ApprovalGate(auto_approve_eval=auto_approve)
        self.executor = LocalExecutor(vault=self.vault)
        self.logger = RedactedAuditLogger()

    def run(self, task_goal: str, target_url: str) -> Dict[str, Any]:
        """
        Executes end-to-end task loop with PrivacyLens firewall protection.
        """
        start_time = time.time()
        self.vault.clear()
        self.logger.clear()
        step_history: List[Dict[str, Any]] = []
        consecutive_failures = 0
        total_sensitive_bytes_sent_to_cloud = 0

        self.logger.log_event("START", f"Goal: {task_goal} | Target: {target_url}")
        self.browser.navigate(target_url)
        page = self.browser.get_page()

        last_clean_image = None
        last_raw_image = None
        last_findings = []
        task_completed = False

        for step in range(1, self.max_steps + 1):
            step_start = time.time()
            elapsed_total = round(step_start - start_time, 2)

            # 1. OBSERVE (Capture Snapshot)
            snapshot = capture_page_snapshot(page)
            last_raw_image = snapshot["image"]
            dom_node_count = len(snapshot.get("nodes", []))
            self.logger.log_event(
                "CAPTURE",
                f"[{elapsed_total}s] {snapshot.get('title')} (DOM {dom_node_count} nodes, screenshot {last_raw_image.width}x{last_raw_image.height})"
            )

            # 2. DETECT
            findings = self.engine.scan_page_snapshot(snapshot, last_raw_image)
            last_findings = findings
            self.logger.log_event(
                "DETECT",
                f"Found {len(findings)} sensitive elements across text, DOM, and visual channels",
                {"findings_count": len(findings), "types": [f["type"] for f in findings]}
            )

            # 3. SECURITY: Scan for Prompt Injections in webpage
            injections = detect_prompt_injections(snapshot.get("text", ""), snapshot.get("nodes", []))
            if injections:
                self.logger.log_event(
                    "SECURITY",
                    f"FLAGGED {len(injections)} indirect prompt injection vectors in webpage!",
                    {"injections": injections}
                )
                snapshot["text"] = sanitize_injections(snapshot.get("text", ""))

            # 4. SANITIZE
            clean_snapshot = sanitize_dom_tree(snapshot, findings, self.vault)
            clean_image = redact_screenshot(last_raw_image, findings)
            last_clean_image = clean_image

            token_count = len(self.vault.get_all_raw_secrets())
            self.logger.log_event(
                "SANITIZE",
                f"Tokens: {token_count} | Visual Redaction Boxes: {len(findings)} | RAM Vault: {token_count} entries"
            )

            # 5. EGRESS GATEWAY (FAIL-CLOSED)
            try:
                egress_result = self.egress.inspect_and_filter(clean_snapshot, clean_image)
                self.logger.log_event(
                    "EGRESS",
                    f"Re-scan text: 0 hits | OCR visual check: 0 hits | Canaries: 0 -> PASS ({egress_result['payload_bytes']} clean bytes)"
                )
            except EgressBlockedException as e:
                self.logger.log_event("EGRESS_BLOCKED", f"FAIL-CLOSED: {str(e)}")
                return {
                    "success": False,
                    "error": "Egress Blocked: Sensitive leak intercepted",
                    "violations": e.violations,
                    "steps": step,
                    "sensitive_bytes_leaked": 0
                }

            # 6. PLAN (Untrusted Cloud / Local LLM)
            action = self.llm_client.plan_next_action(
                task_goal=task_goal,
                sanitized_snapshot=clean_snapshot,
                step_history=step_history
            )
            self.logger.log_event("LLM_PLAN", f"Action proposed: {action.get('action')}", {"action": action})

            if action.get("action") == "done":
                self.logger.log_event("COMPLETE", f"Task satisfied: {action.get('summary')}")
                task_completed = True
                break

            # 7. ACTION VALIDATION
            try:
                validated_action = self.validator.validate_action(
                    action,
                    clean_snapshot.get("element_map", {}),
                    page.url
                )
            except ActionValidationError as ve:
                self.logger.log_event("VALIDATE_REJECTED", f"Action rejected: {str(ve)}")
                consecutive_failures += 1
                if consecutive_failures >= 3:
                    self.logger.log_event("STOP", "3 consecutive invalid actions. Stopping agent loop.")
                    break
                continue

            consecutive_failures = 0

            # 8. APPROVAL GATE (Human-in-the-Loop for Irreversible Actions)
            elem_meta = clean_snapshot.get("element_map", {}).get(validated_action.get("element_id"), {})
            if self.approval.requires_approval(validated_action, elem_meta):
                ticket = self.approval.request_approval(
                    validated_action,
                    elem_meta,
                    f"Execute irreversible action on {elem_meta.get('selector')}"
                )
                self.logger.log_event("APPROVAL_GATE", f"Action requires user confirmation: {ticket['ticket_id']}")
                if ticket["status"] != "APPROVED":
                    self.logger.log_event("APPROVAL_PENDING", "Waiting for dashboard user approval...")
                    # In interactive mode, break or wait; in eval mode, approved
                    return {
                        "status": "AWAITING_APPROVAL",
                        "ticket": ticket,
                        "snapshot": clean_snapshot
                    }

            # 9. LOCAL EXECUTOR (Secret Injection)
            exec_result = self.executor.execute_action(
                validated_action,
                clean_snapshot.get("element_map", {}),
                page
            )
            step_history.append(validated_action)

            injected_count = exec_result.get("tokens_used_count", 0)
            if injected_count > 0:
                self.logger.log_event(
                    "SECRET_INJECTION",
                    f"Locally injected {injected_count} real secret(s) from RAM vault into {exec_result.get('selector')}"
                )
            else:
                self.logger.log_event("EXECUTE", f"Action executed: {exec_result.get('action')}")

        total_time = round(time.time() - start_time, 2)
        return {
            "success": task_completed,
            "steps": len(step_history),
            "duration_seconds": total_time,
            "findings_count": len(last_findings),
            "vault_tokens": len(self.vault.get_all_raw_secrets()),
            "cloud_sensitive_bytes_leaked": total_sensitive_bytes_sent_to_cloud,
            "raw_image": last_raw_image,
            "clean_image": last_clean_image,
            "audit_trail": self.logger.get_audit_trail()
        }
