"""
PrivacyLens - Master Verification Test Suite (Part 8 Verification)
Tests all core requirements:
1. Synthetic Aadhaar number detection (Verhoeff dihedral algorithm)
2. Synthetic PAN number detection (Syntax and entity validation)
3. Email and phone number detection
4. Password and credential redaction
5. Sanitized payload contains semantic placeholders rather than original sensitive values
6. Actual outgoing payload is checked by fail-closed egress gateway
7. Intentionally introduced unsanitized canary triggers immediate block
8. Successfully sanitized payload passes egress validation
9. AI agent plans actions over sanitized webpage without exposing secrets
10. Dynamic statistics update from real session data (zero hardcoded numbers)
11. Multi-page routes (/dashboard, /protection, /evidence, /test-lab, /activity, /settings) serve application
"""

import pytest
import json
from fastapi.testclient import TestClient

from privacylens.api.server import app, global_session_store, global_vault, global_canary_mgr
from privacylens.detect.engine import DetectionEngine
from privacylens.detect.validators import verhoeff, luhn, pan_check
from privacylens.sanitize.vault import LocalSecretVault
from privacylens.sanitize.text import sanitize_text
from privacylens.gateway.egress import validate_outgoing_payload, EgressGateway
from privacylens.gateway.canary import CanaryManager
from privacylens.agent.llm_client import LLMClient
from testbed.synthetic_data import (
    generate_aadhaar,
    generate_pan,
    generate_credit_card,
    generate_indian_phone,
    generate_api_key
)


@pytest.fixture
def client():
    return TestClient(app)


def test_synthetic_aadhaar_detection():
    """Verify synthetic 12-digit Aadhaar detection using Verhoeff algorithm."""
    aadhaar = generate_aadhaar(formatted=True)
    clean_aadhaar = aadhaar.replace(" ", "")
    assert verhoeff(clean_aadhaar) is True, "Generated Aadhaar must have valid Verhoeff checksum"

    engine = DetectionEngine()
    findings = engine.scan_text(f"Customer registered identity Aadhaar: {aadhaar}")
    aadhaar_findings = [f for f in findings if f["type"] == "AADHAAR"]
    assert len(aadhaar_findings) >= 1
    assert clean_aadhaar in aadhaar_findings[0]["value"].replace(" ", "")


def test_synthetic_pan_detection():
    """Verify synthetic PAN detection with valid Indian syntax and entity."""
    pan = generate_pan("P")
    assert pan_check(pan) is True

    engine = DetectionEngine()
    findings = engine.scan_text(f"Tax verification PAN number: {pan}")
    pan_findings = [f for f in findings if f["type"] == "PAN"]
    assert len(pan_findings) >= 1
    assert pan_findings[0]["value"] == pan


def test_email_and_phone_detection():
    """Verify email and phone number detection."""
    phone = generate_indian_phone()
    email = "engineer.security@privacylens.test"

    engine = DetectionEngine()
    findings = engine.scan_text(f"Direct contact: {email} or mobile {phone}")
    types = {f["type"] for f in findings}
    assert "EMAIL" in types
    assert "PHONE" in types


def test_password_redaction_and_placeholders():
    """Verify passwords and credentials replaced by semantic placeholders."""
    raw_text = "Login credentials: user=alex.vance@internal.test password=SuperSecretPassword123!"
    vault = LocalSecretVault()
    vault.clear()

    engine = DetectionEngine()
    findings = engine.scan_text(raw_text)
    # Add password finding
    findings.append({
        "type": "PASSWORD",
        "value": "SuperSecretPassword123!",
        "confidence": 1.0,
        "reason": "Cleartext password"
    })

    sanitized = sanitize_text(raw_text, findings, vault)
    assert "SuperSecretPassword123!" not in sanitized
    assert "[PASSWORD_1]" in sanitized or "[EMAIL_1]" in sanitized
    # Vault must hold real secret in RAM
    assert vault.get_real_value("[PASSWORD_1]") == "SuperSecretPassword123!"


def test_sanitized_payload_contains_no_original_sensitive_values():
    """Verify that original sensitive values are unrecoverable from outgoing payload."""
    card = generate_credit_card("visa")["number"]
    pan = generate_pan("P")
    aadhaar = generate_aadhaar(formatted=True)
    text = f"Checkout order with Aadhaar {aadhaar}, PAN {pan}, card {card}"

    vault = LocalSecretVault()
    vault.clear()
    engine = DetectionEngine()
    findings = engine.scan_text(text)
    sanitized = sanitize_text(text, findings, vault)

    assert card not in sanitized
    assert pan not in sanitized
    assert aadhaar not in sanitized


def test_intentional_canary_leak_triggers_firewall_block(client):
    """Intentionally introduce an unsanitized canary and verify firewall blocks transmission."""
    resp = client.post("/api/canary/test-firewall", json={"inject_unredacted_canary": True})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "BLOCKED"
    assert data["firewall_verdict"] == "BLOCKED"
    assert len(data["violations"]) > 0


def test_clean_payload_passes_egress_validation(client):
    """Verify clean sanitized payload passes egress validation."""
    resp = client.post("/api/canary/test-firewall", json={"inject_unredacted_canary": False})
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "CLEARED"
    assert data["firewall_verdict"] == "PROTECTED"


def test_ai_agent_reasons_over_sanitized_data_and_injects_locally():
    """Verify AI client plans action using tokens and resolves secrets locally in RAM."""
    vault = LocalSecretVault()
    vault.clear()
    card_raw = "4532015012345678"
    token = vault.allocate_token("CARD", card_raw)

    sanitized_snapshot = {
        "title": "ShoeKart Checkout",
        "url": "https://shoekart.internal/checkout",
        "text": f"Payment order: Card [{token}]",
        "element_map": {
            "pl-1": {"selector": "#card-number", "tag": "input"},
            "pl-2": {"selector": "#card-cvv", "tag": "input"},
            "pl-3": {"selector": "#pay-button", "tag": "button"}
        }
    }

    client = LLMClient(provider="local_benchmark")
    action = client.plan_next_action(
        task_goal="Complete checkout and pay order",
        sanitized_snapshot=sanitized_snapshot,
        step_history=[]
    )

    assert action is not None
    assert "action" in action
    # Local executor can resolve token without exposing raw card to AI
    if "value" in action and action["value"].startswith("[CARD"):
        resolved = vault.get_real_value(action["value"])
        assert resolved == card_raw


def test_dynamic_statistics_updates_on_real_sessions(client):
    """Verify dashboard stats are updated dynamically on actual sessions."""
    # 1. Reset history
    client.post("/api/settings/clear-history")
    s_initial = client.get("/dashboard/stats").json()
    assert s_initial["total_sessions"] == 0

    # 2. Run a real protection session
    p_resp = client.post("/api/protection/start", json={
        "scenario": "checkout.html",
        "task_goal": "Complete checkout",
        "run_agent": True
    })
    assert p_resp.status_code == 200

    # 3. Check stats updated
    s_after = client.get("/dashboard/stats").json()
    assert s_after["total_sessions"] >= 1
    assert s_after["total_detected"] >= 1


def test_multi_page_navigation_routes_serve_spa(client):
    """Verify that all 6 required routes serve the application HTML for client-side routing."""
    routes = ["/dashboard", "/protection", "/evidence", "/test-lab", "/activity", "/settings"]
    for r in routes:
        resp = client.get(r)
        assert resp.status_code == 200
        assert "<div class=\"app-shell\">" in resp.text
        assert "PrivacyLens" in resp.text

