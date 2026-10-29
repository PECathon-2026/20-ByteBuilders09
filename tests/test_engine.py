import pytest
from privacylens.detect.engine import DetectionEngine
from testbed.synthetic_data import generate_credit_card, generate_aadhaar


def test_engine_detects_multiple_sensitive_types():
    engine = DetectionEngine()
    valid_card = generate_credit_card("visa")["raw_number"]
    valid_aadhaar = generate_aadhaar(formatted=True)

    dummy_snapshot = {
        "title": "KYC Verification Portal",
        "url": f"https://shoekart.test/kyc?card={valid_card}",
        "text": f"User Aarav Sharma with PAN ABCPA1234D and Aadhaar {valid_aadhaar}. Refund UPI: user@okhdfcbank",
        "nodes": [
            {
                "tagName": "input",
                "selector": "#pwd",
                "attributes": {"type": "password", "id": "pwd"},
                "value": "MySuperSecret123!",
                "textContent": "",
                "bbox": [10, 20, 100, 30]
            }
        ]
    }

    findings = engine.scan_page_snapshot(dummy_snapshot)
    assert len(findings) >= 4

    types = {f["type"] for f in findings}
    assert "CARD" in types
    assert "PAN" in types
    assert "AADHAAR" in types
    assert "PASSWORD" in types

    # Verify explainable reason is attached to all findings
    for f in findings:
        assert "reason" in f
        assert len(f["reason"]) > 5
        assert "confidence" in f
        assert f["confidence"] > 0.7
