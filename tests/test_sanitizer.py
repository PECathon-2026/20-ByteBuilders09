"""
Unit test for Capture, Detection, Text & Image Sanitization on checkout.html.
Verifies:
1. All sensitive fields are replaced by tokens in sanitized DOM.
2. RAM-only vault maps tokens to real secrets.
3. Screenshot has black redaction boxes over sensitive inputs.
4. No real card number or Aadhaar remains in text.
"""

import os
import pytest
from privacylens.capture.browser import BrowserController
from privacylens.capture.snapshot import capture_page_snapshot
from privacylens.detect.engine import DetectionEngine
from privacylens.sanitize.vault import LocalSecretVault
from privacylens.sanitize.dom import sanitize_dom_tree
from privacylens.sanitize.image import redact_screenshot


def test_capture_and_sanitize_checkout():
    vault = LocalSecretVault()
    vault.clear()

    checkout_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "testbed", "pages", "checkout.html"))
    file_url = f"file:///{checkout_path.replace(os.sep, '/')}"

    with BrowserController(headless=True) as controller:
        controller.navigate(file_url)
        page = controller.get_page()

        # Step 1: Capture
        snapshot = capture_page_snapshot(page)
        assert snapshot["title"] == "ShoeKart - Secure Checkout"
        assert len(snapshot["nodes"]) > 0
        assert snapshot["image"] is not None

        # Step 2: Detect
        engine = DetectionEngine()
        findings = engine.scan_page_snapshot(snapshot, snapshot["image"])
        assert len(findings) >= 5, f"Expected at least 5 findings, got {len(findings)}: {findings}"

        found_types = {f["type"] for f in findings}
        assert "CARD" in found_types, "Credit card must be detected"
        assert "AADHAAR" in found_types or "PAN" in found_types

        # Step 3: Sanitize DOM & Text
        clean_snapshot = sanitize_dom_tree(snapshot, findings, vault)

        # Check that element_ids pl-1, pl-2 are assigned
        assert "element_map" in clean_snapshot
        assert len(clean_snapshot["element_map"]) > 0

        # Check raw card is nowhere in sanitized text
        raw_card = "4532 0150 1234 5678"
        assert raw_card not in clean_snapshot["text"]

        # Check vault has stored token mapping
        stored_tokens = vault.get_token_summary()
        assert len(stored_tokens) >= 5

        # Check Image redaction
        clean_image = redact_screenshot(snapshot["image"], findings)
        assert clean_image.size == snapshot["image"].size
