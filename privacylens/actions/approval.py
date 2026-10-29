"""
PrivacyLens - Human-in-the-Loop Approval Gate
Intercepts irreversible actions (e.g. Pay, Submit, Delete, Transfer) and requires explicit confirmation.
"""

import uuid
from typing import Dict, Any, Optional

IRREVERSIBLE_KEYWORDS = [
    "pay", "purchase", "place order", "checkout", "delete", "destroy",
    "submit order", "transfer", "send money", "emergency rotate"
]


class ApprovalGate:
    def __init__(self, auto_approve_eval: bool = False):
        self.auto_approve_eval = auto_approve_eval
        self.pending_approvals: Dict[str, Dict[str, Any]] = {}

    def requires_approval(self, action: Dict[str, Any], element_meta: Dict[str, Any]) -> bool:
        """Determines whether an action is high-risk / irreversible."""
        action_name = action.get("action", "").lower()
        if action_name not in ("click", "submit"):
            return False

        selector = element_meta.get("selector", "").lower()
        context_str = f"{selector} {element_meta.get('type', '')}"

        return any(kw in context_str for kw in IRREVERSIBLE_KEYWORDS)

    def request_approval(
        self,
        action: Dict[str, Any],
        element_meta: Dict[str, Any],
        context_description: str
    ) -> Dict[str, Any]:
        """
        Creates an approval ticket.
        If auto_approve_eval is True (for automated benchmarking), auto-approves.
        Otherwise queues ticket for dashboard confirmation.
        """
        ticket_id = f"appr-{str(uuid.uuid4())[:8]}"
        ticket = {
            "ticket_id": ticket_id,
            "action": action,
            "element": element_meta,
            "description": context_description,
            "status": "APPROVED" if self.auto_approve_eval else "PENDING"
        }

        self.pending_approvals[ticket_id] = ticket
        return ticket

    def approve(self, ticket_id: str) -> bool:
        if ticket_id in self.pending_approvals:
            self.pending_approvals[ticket_id]["status"] = "APPROVED"
            return True
        return False

    def reject(self, ticket_id: str) -> bool:
        if ticket_id in self.pending_approvals:
            self.pending_approvals[ticket_id]["status"] = "REJECTED"
            return True
        return False

    def get_pending(self) -> list:
        return [t for t in self.pending_approvals.values() if t["status"] == "PENDING"]
