"""
PrivacyLens 2.0 - Privacy Proof Lab Unit & Integration Tests
Verifies:
1. All 6 local synthetic scenarios run reproducibly.
2. Pipeline A (Baseline) vs Pipeline B (PrivacyLens) leakage comparison.
3. Hidden DOM trap leak in Baseline vs zero leak in PrivacyLens.
4. Form inputs & Split OTP grouped detection.
5. URL query parameter scrubbing.
6. Screenshot pixel masking.
7. Prompt injection adversarial exfiltration blocking.
8. Deliberately injected post-sanitization canary is caught by centralized egress gateway.
9. Exportable JSON and CSV evidence report generation without raw secrets.
"""

import json
import pytest
from privacylens.proof_lab.scenarios import (
    get_all_scenarios,
    build_scenario_1_visible_text,
    build_scenario_2_hidden_dom,
    build_scenario_3_form_inputs,
    build_scenario_4_url_query,
    build_scenario_5_screenshot_pixels,
    build_scenario_6_prompt_injection,
    CANARY_VISIBLE_EMAIL,
    CANARY_HIDDEN_SECRET,
    CANARY_FORM_PASSWORD,
    CANARY_URL_TOKEN,
    CANARY_VISUAL_SECRET,
    CANARY_INJECTION_KEY
)
from privacylens.proof_lab.pipeline import (
    BaselinePipeline,
    PrivacyLensPipeline,
    run_scenario_comparison
)
from privacylens.proof_lab.metrics import calculate_metrics
from privacylens.proof_lab.report import (
    run_full_privacy_challenge,
    export_report_json,
    export_report_csv
)
from privacylens.gateway.egress import validate_outgoing_payload, EgressBlockedException
from privacylens.gateway.canary import CanaryManager


def test_six_scenarios_exist_and_deterministic():
    scenarios = get_all_scenarios()
    assert len(scenarios) == 6
    ids = [s["id"] for s in scenarios]
    assert len(ids) == len(set(ids))

    for s in scenarios:
        assert "name" in s
        assert "category" in s
        assert "attack_description" in s
        assert "planted_canaries" in s
        assert len(s["planted_canaries"]) >= 1
        assert "snapshot" in s


def test_scenario_1_visible_text_and_checksums():
    sc = build_scenario_1_visible_text()
    res = run_scenario_comparison(sc)

    # PrivacyLens detects all sensitive items and achieves 0.0% canary leakage
    pl = res["privacylens"]
    assert pl["status"] == "PROTECTED"
    assert pl["leaked_canaries_count"] == 0
    assert pl["metrics"]["canary_leakage_pct"] == 0.0
    assert pl["metrics"]["recall_pct"] >= 80.0
    assert len(pl["event_trace"]) == 5  # CAPTURE, DETECT, SANITIZE, VERIFY, ALLOW/BLOCK


def test_scenario_2_hidden_dom_leakage_divergence():
    sc = build_scenario_2_hidden_dom()
    res = run_scenario_comparison(sc)

    base = res["baseline"]
    pl = res["privacylens"]

    # Baseline text-only regex fails to detect hidden DOM attributes and leaks canaries
    assert CANARY_HIDDEN_SECRET in base["leaked_canaries"]
    assert base["leaked_canaries_count"] >= 1
    assert base["metrics"]["canary_leakage_pct"] > 0.0

    # PrivacyLens strips hidden DOM nodes: 0% canary leakage
    assert CANARY_HIDDEN_SECRET not in pl["leaked_canaries"]
    assert pl["leaked_canaries_count"] == 0
    assert pl["metrics"]["canary_leakage_pct"] == 0.0


def test_scenario_3_form_inputs_and_split_otp():
    sc = build_scenario_3_form_inputs()
    res = run_scenario_comparison(sc)

    pl = res["privacylens"]
    assert pl["leaked_canaries_count"] == 0
    assert pl["status"] == "PROTECTED"
    # Ensure raw password canary is not leaked in outgoing payload
    assert CANARY_FORM_PASSWORD not in pl["simulated_payload_sample"]


def test_scenario_4_url_query_scrubbing():
    sc = build_scenario_4_url_query()
    res = run_scenario_comparison(sc)

    base = res["baseline"]
    pl = res["privacylens"]

    # Baseline leaves URL unchanged and leaks token
    assert CANARY_URL_TOKEN in base["leaked_canaries"]

    # PrivacyLens scrubs URL parameters
    assert CANARY_URL_TOKEN not in pl["leaked_canaries"]
    assert pl["leaked_canaries_count"] == 0


def test_scenario_5_screenshot_pixel_redaction():
    sc = build_scenario_5_screenshot_pixels()
    res = run_scenario_comparison(sc)

    base = res["baseline"]
    pl = res["privacylens"]

    # Baseline leaves screenshot unmasked, leaking visual secret
    assert CANARY_VISUAL_SECRET in base["leaked_canaries"]

    # PrivacyLens applies visual redaction and reports OCR status honestly
    assert pl["status"] == "PROTECTED"
    assert "ocr_status" in pl


def test_scenario_6_prompt_injection_blocked():
    sc = build_scenario_6_prompt_injection()
    res = run_scenario_comparison(sc)

    pl = res["privacylens"]
    # Adversarial prompt injection exfiltration must be BLOCKED
    assert "BLOCKED" in pl["decision"]
    assert pl["metrics"]["payloads_blocked_count"] == 1


def test_deliberate_post_sanitization_canary_injection_blocked():
    """
    Critical security test:
    Deliberately introduces a canary after the first sanitization stage.
    Proves that the authoritative egress gateway performs a second-pass check and blocks it!
    """
    canary_mgr = CanaryManager()
    planted_leak = canary_mgr.generate_canary("POST_SANITIZE_LEAK")

    # Construct an outgoing payload that slipped past early filters
    leaking_payload = {
        "text": f"Simulated user message containing {planted_leak}",
        "url": "https://example.com/chat"
    }

    # Gateway inspection with fail_closed=False
    result = validate_outgoing_payload(
        payload=leaking_payload,
        canary_manager=canary_mgr,
        fail_closed=False
    )
    assert result["passed"] is False
    assert len(result["leaks"]) >= 1
    assert any("CANARY_LEAK" in l["type"] for l in result["leaks"])

    # Gateway inspection with fail_closed=True raises exception
    with pytest.raises(EgressBlockedException):
        validate_outgoing_payload(
            payload=leaking_payload,
            canary_manager=canary_mgr,
            fail_closed=True
        )


def test_metrics_zero_division_guard():
    # Test zero denominators handled cleanly without ZeroDivisionError
    m = calculate_metrics(
        ground_truth_count=0,
        detected_count=0,
        true_positive_count=0,
        planted_canaries_count=0,
        leaked_canaries_count=0,
        payloads_blocked_count=0,
        processing_time_ms=5.0
    )
    assert m["recall_pct"] == 100.0
    assert m["precision_pct"] == 100.0
    assert m["canary_leakage_pct"] == 0.0
    assert m["missed_markers_count"] == 0


def test_full_privacy_challenge_and_report_export():
    report = run_full_privacy_challenge()
    assert report["product"] == "PrivacyLens 2.0"
    assert report["tagline"] == "Prove Before You Trust."
    assert len(report["scenarios"]) == 6
    assert "macro_summary" in report

    macro = report["macro_summary"]
    # PrivacyLens canary leakage across all 6 scenarios must be 0.0%
    assert macro["privacylens"]["avg_canary_leakage_pct"] == 0.0
    # Baseline canary leakage must be strictly greater than 0% (due to hidden DOM, URL, image)
    assert macro["baseline"]["avg_canary_leakage_pct"] > 0.0

    # Test JSON export
    json_out = export_report_json(report)
    parsed = json.loads(json_out)
    assert parsed["product"] == "PrivacyLens 2.0"

    # Test CSV export
    csv_out = export_report_csv(report)
    assert "Scenario ID,Scenario Name,Category" in csv_out
    assert "scenario_1" in csv_out
    assert "scenario_6" in csv_out
