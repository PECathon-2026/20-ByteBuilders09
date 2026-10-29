"""
Unit and Integration tests for PrivacyLens Backend Endpoints.
Verifies:
- GET /health
- POST /scan
- POST /sanitize
- POST /validate-egress (clean vs blocked leaks)
- GET /dashboard/stats
- POST /approval/request & POST /approval/{id}/decision
- POST /vault/clear
"""

import pytest
from privacylens.api.server import (
    app,
    get_health,
    get_dashboard_stats,
    scan_content,
    sanitize_content,
    validate_egress,
    create_approval_request,
    get_pending_approvals,
    record_approval_decision,
    clear_vault,
    ContentPayloadRequest,
    EgressValidateRequest,
    ApprovalCreateRequest,
    ApprovalDecisionRequest,
    global_vault,
    global_approval_gate
)


def test_health_endpoint():
    data = get_health()
    assert data["status"] == "ok"
    assert data["service"] == "PrivacyLens Security Engine"
    assert data["egress_gateway"] == "active_fail_closed"


def test_scan_content_endpoint():
    sample_text = (
        "User contact: alex.vance@example.internal with registered phone +91-9876543210. "
        "Tax ID: ABCPA1234D and Visa card 4532 0150 1234 5678"
    )
    req = ContentPayloadRequest(content=sample_text, title="Account Settings")
    data = scan_content(req)
    assert data["status"] == "success"
    assert data["findings_count"] >= 3

    finding_types = {f["type"] for f in data["findings"]}
    assert "EMAIL" in finding_types
    assert "PHONE" in finding_types
    assert "PAN" in finding_types or "CARD" in finding_types


def test_sanitize_content_endpoint():
    from testbed.synthetic_data import generate_credit_card
    valid_card = generate_credit_card("visa")["number"]
    sample_text = f"Sending payment from card {valid_card} to user@okhdfcbank"
    req = ContentPayloadRequest(content=sample_text)
    data = sanitize_content(req)
    assert data["status"] == "success"

    clean_text = data["sanitized_content"]
    assert valid_card not in clean_text
    assert "[CARD_1]" in clean_text or "[UPI_1]" in clean_text
    assert len(data["tokens"]) >= 1


def test_validate_egress_endpoint_clean_and_blocked():
    from testbed.synthetic_data import generate_credit_card
    valid_card = generate_credit_card("visa")["number"]

    # 1. Clean payload
    clean_payload = {
        "action": "type",
        "element_id": "pl-2",
        "value": "[CARD_1]"
    }
    data_clean = validate_egress(EgressValidateRequest(payload=clean_payload))
    assert data_clean["passed"] is True
    assert data_clean["status"] == "CLEARED"

    # 2. Leaking payload with raw Luhn-valid credit card
    leaking_payload = {
        "action": "type",
        "element_id": "pl-2",
        "value": valid_card
    }
    data_leak = validate_egress(EgressValidateRequest(payload=leaking_payload))
    assert data_leak["passed"] is False
    assert data_leak["status"] == "BLOCKED"
    assert data_leak["violations_count"] > 0


def test_dashboard_stats_endpoint():
    data = get_dashboard_stats()
    assert "total_scans" in data
    assert "sensitive_findings_detected" in data
    assert "payloads_blocked" in data
    assert data["protection_status"] == "ACTIVE"


def test_approval_workflow_endpoints():
    # 1. Create approval request
    req_body = ApprovalCreateRequest(
        action={"action": "click", "element_id": "pl-9"},
        target="#btn-pay",
        description="Authorize purchase of Rs. 2,499 on ShoeKart",
        domain="shoekart.test"
    )
    ticket = create_approval_request(req_body)
    ticket_id = ticket["ticket_id"]
    assert ticket["status"] == "PENDING"

    # 2. Check pending list
    pending_list = get_pending_approvals()
    pending_ids = [t["ticket_id"] for t in pending_list]
    assert ticket_id in pending_ids

    # 3. Submit approval decision
    decision_data = record_approval_decision(
        ticket_id=ticket_id,
        req=ApprovalDecisionRequest(decision="approve", reason="User confirmed payment")
    )
    assert decision_data["status"] == "APPROVED"
    assert decision_data["success"] is True


def test_vault_clear_endpoint():
    data = clear_vault()
    assert data["status"] == "cleared"
    assert data["active_tokens"] == 0


def test_proof_lab_api_endpoints():
    from fastapi.testclient import TestClient
    client = TestClient(app)

    # 1. Scenarios list
    r_sc = client.get("/api/proof-lab/scenarios")
    assert r_sc.status_code == 200
    scenarios = r_sc.json()
    assert len(scenarios) == 6

    # 2. Run single scenario
    r_run = client.post("/api/proof-lab/run-scenario", json={"scenario_id": "scenario_2"})
    assert r_run.status_code == 200
    run_data = r_run.json()
    assert run_data["scenario_id"] == "scenario_2"
    assert "baseline" in run_data
    assert "privacylens" in run_data

    # 3. Export JSON & CSV
    r_json = client.get("/api/proof-lab/export/json")
    assert r_json.status_code == 200
    assert r_json.headers["content-type"] == "application/json"

    r_csv = client.get("/api/proof-lab/export/csv")
    assert r_csv.status_code == 200
    assert "text/csv" in r_csv.headers["content-type"]


def test_events_and_ocr_endpoints():
    from fastapi.testclient import TestClient
    client = TestClient(app)

    # Events history
    r_ev = client.get("/api/events/history")
    assert r_ev.status_code == 200
    ev_list = r_ev.json()
    assert isinstance(ev_list, list)
    assert len(ev_list) >= 1

    # OCR status
    r_ocr = client.get("/api/ocr/status")
    assert r_ocr.status_code == 200
    ocr_data = r_ocr.json()
    assert "available" in ocr_data
    assert "engine" in ocr_data


def test_egress_api_alias_endpoint():
    from fastapi.testclient import TestClient
    client = TestClient(app)

    clean_payload = {"action": "type", "value": "[CARD_1]"}
    r = client.post("/api/egress/validate", json={"payload": clean_payload})
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "CLEARED"
    assert data["passed"] is True

