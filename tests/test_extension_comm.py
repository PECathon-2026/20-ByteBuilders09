"""
Chrome Extension Communication Integration Test.
Simulates exact HTTP JSON requests from extension popup/content scripts to:
- GET /health
- POST /scan
- POST /sanitize
Verifying fields expected by extension/popup/popup.js:
- data.status == "ok"
- scanData.findings (array with type, confidence, reason)
- sanitizeData.sanitized_content (string with stable tokens [EMAIL_1], [CARD_1])
- sanitizeData.tokens (array)
"""

from fastapi.testclient import TestClient
from privacylens.api.server import app
from testbed.synthetic_data import generate_credit_card, generate_pan, generate_upi

client = TestClient(app)


def test_extension_health_ping():
    resp = client.get("/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data.get("status") == "ok"
    assert "service" in data


def test_extension_scan_page_payload():
    # Simulates content extracted from a webpage by content.js
    card = generate_credit_card("visa")["number"]
    pan = generate_pan()
    upi = generate_upi()

    mock_page_text = (
        f"Billing Page\n"
        f"Customer Email: user.checkout@secure-shop.in\n"
        f"PAN Number: {pan}\n"
        f"Credit Card: {card}\n"
        f"UPI ID: {upi}\n"
    )

    payload = {
        "content": mock_page_text,
        "url": "https://secure-shop.in/checkout",
        "title": "Secure Checkout"
    }

    resp = client.post("/scan", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    assert data["status"] == "success"
    assert "findings" in data
    assert isinstance(data["findings"], list)
    assert len(data["findings"]) >= 3

    # Verify each finding contains the fields popup.js expects:
    for f in data["findings"]:
        assert "type" in f
        assert "confidence" in f
        assert "reason" in f


def test_extension_sanitize_page_payload():
    card = generate_credit_card("visa")["number"]
    mock_page_text = f"Checkout total: Rs 1,499. Payment method: Card {card}."

    payload = {
        "content": mock_page_text,
        "url": "https://secure-shop.in/checkout"
    }

    resp = client.post("/sanitize", json=payload)
    assert resp.status_code == 200
    data = resp.json()

    assert data["status"] == "success"
    assert "sanitized_content" in data
    assert "tokens" in data
    assert card not in data["sanitized_content"]
    assert "[CARD_1]" in data["sanitized_content"]
