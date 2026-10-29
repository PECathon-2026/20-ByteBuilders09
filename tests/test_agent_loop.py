"""
End-to-end integration test for PrivacyLens Agent Loop and Secret Injection.
Simulates checkout flow:
1. Agent plans actions using tokens [CARD_1], [CVV_1].
2. Local Executor resolves tokens from RAM vault.
3. Form is submitted with real values locally.
4. Outgoing cloud bytes contain 0 secrets.
"""

import os
import pytest
from privacylens.capture.browser import BrowserController
from privacylens.agent.loop import AgentLoop


def test_agent_checkout_secret_injection():
    checkout_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "testbed", "pages", "checkout.html"))
    file_url = f"file:///{checkout_path.replace(os.sep, '/')}"

    with BrowserController(headless=True) as browser:
        agent = AgentLoop(browser=browser, max_steps=8, auto_approve=True)
        result = agent.run(task_goal="Complete checkout and pay order", target_url=file_url)

        assert result["success"] is True
        assert result["steps"] >= 2
        assert result["cloud_sensitive_bytes_leaked"] == 0
        assert result["vault_tokens"] >= 5

        # Check audit trail logs
        stages = [e["stage"] for e in result["audit_trail"]]
        assert "CAPTURE" in stages
        assert "DETECT" in stages
        assert "SANITIZE" in stages
        assert "EGRESS" in stages
        assert "SECRET_INJECTION" in stages
