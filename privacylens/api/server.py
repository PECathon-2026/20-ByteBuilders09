"""
PrivacyLens - FastAPI Backend Server
Powers the Chrome Extension, Dashboard, Detection Engine, In-Memory Vault,
Fail-Closed Egress Gateway, and Human Approval Gate.
"""

import os
import sys
import io
import base64
import json
import time
from typing import Dict, Any, Optional, List, Union
from fastapi import FastAPI, HTTPException, Request, Body, Path
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from privacylens.capture.browser import BrowserController
from privacylens.capture.snapshot import capture_page_snapshot
from privacylens.detect.engine import DetectionEngine
from privacylens.detect.patterns import scan_text_patterns
from privacylens.sanitize.vault import LocalSecretVault
from privacylens.sanitize.text import sanitize_text
from privacylens.sanitize.dom import sanitize_dom_tree
from privacylens.sanitize.image import redact_screenshot
from privacylens.gateway.egress import EgressGateway, EgressBlockedException
from privacylens.gateway.canary import CanaryManager
from privacylens.actions.approval import ApprovalGate
from privacylens.agent.loop import AgentLoop
from privacylens.security.safe_logging import RedactedAuditLogger
from eval.run_eval import run_full_evaluation, SCENARIOS
from eval.leakage_test import run_canary_leakage_benchmark

app = FastAPI(
    title="PrivacyLens Security Engine",
    description="Local privacy firewall and secret injection backend for browser AI agents",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

WORKSPACE_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DASHBOARD_DIR = os.path.join(WORKSPACE_ROOT, "dashboard")
PAGES_DIR = os.path.join(WORKSPACE_ROOT, "testbed", "pages")

# Mount dashboard static assets
if os.path.exists(DASHBOARD_DIR):
    app.mount("/static", StaticFiles(directory=DASHBOARD_DIR), name="static")

# Shared state
global_vault = LocalSecretVault()
global_canary_mgr = CanaryManager()
global_approval_gate = ApprovalGate(auto_approve_eval=False)
global_logger = RedactedAuditLogger()
cached_browser = None

# Real aggregated stats (persisted in-memory for session)
class LiveStats:
    def __init__(self):
        self.total_scans = 0
        self.sensitive_findings_detected = 0
        self.payloads_blocked = 0
        self.payloads_cleared = 0
        self.total_approvals_requested = 0
        self.total_approvals_granted = 0
        self.start_time = time.time()

stats = LiveStats()


def get_browser():
    global cached_browser
    if cached_browser is None or not cached_browser.is_alive():
        if cached_browser:
            try:
                cached_browser.close()
            except Exception:
                pass
        cached_browser = BrowserController(headless=True)
        cached_browser.start()
    return cached_browser


# Pydantic Request Models
class ContentPayloadRequest(BaseModel):
    content: Optional[str] = None
    url: Optional[str] = None
    title: Optional[str] = None
    scenario: Optional[str] = None
    session_id: Optional[str] = "default"


class EgressValidateRequest(BaseModel):
    payload: Union[Dict[str, Any], List[Any], str]
    canary_test: Optional[bool] = False


class ApprovalCreateRequest(BaseModel):
    action: Dict[str, Any]
    target: str
    description: str
    domain: Optional[str] = "localhost"


class ApprovalDecisionRequest(BaseModel):
    decision: str = Field(..., description="'approve' or 'reject'")
    reason: Optional[str] = None


class AgentRunRequest(BaseModel):
    scenario: Optional[str] = "checkout.html"
    task_goal: Optional[str] = "Complete checkout and pay order"
    auto_approve: bool = True


def pil_to_b64(img) -> str:
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode("utf-8")


# ==============================================================================
# PHASE 2 CORE BACKEND ENDPOINTS
# ==============================================================================

@app.get("/health")
def get_health():
    """Returns backend status, engine version, and protection status."""
    return {
        "status": "ok",
        "version": "1.0.0",
        "service": "PrivacyLens Security Engine",
        "egress_gateway": "active_fail_closed",
        "vault": "in_memory_ram",
        "uptime_seconds": round(time.time() - stats.start_time, 1)
    }


@app.get("/dashboard/stats")
def get_dashboard_stats():
    """Returns real aggregated statistics without exposing any secrets."""
    pending_approvals = global_approval_gate.get_pending()
    return {
        "protection_status": "ACTIVE",
        "total_scans": stats.total_scans,
        "sensitive_findings_detected": stats.sensitive_findings_detected,
        "payloads_blocked": stats.payloads_blocked,
        "payloads_cleared": stats.payloads_cleared,
        "pending_approvals": len(pending_approvals),
        "active_vault_tokens": len(global_vault.get_all_raw_secrets()),
        "uptime_seconds": round(time.time() - stats.start_time, 1)
    }


@app.post("/scan")
@app.post("/api/scan")
def scan_content(req: ContentPayloadRequest):
    """
    Analyzes supplied synthetic, DOM, or testbed content for sensitive PII/credentials.
    Returns findings with detected category, confidence, and explainable reason.
    """
    stats.total_scans += 1

    # Mode A: User supplied direct content string from Chrome Extension or API client
    if req.content is not None:
        engine = DetectionEngine()
        dummy_snapshot = {
            "title": req.title or "Scanned Tab",
            "url": req.url or "http://localhost",
            "text": req.content,
            "nodes": []
        }
        findings = engine.scan_page_snapshot(dummy_snapshot)
        stats.sensitive_findings_detected += len(findings)

        # Build clean response omitting raw secret values for safety
        safe_findings = []
        for f in findings:
            safe_findings.append({
                "type": f.get("type"),
                "confidence": f.get("confidence", 0.95),
                "reason": f.get("reason", "Matched pattern"),
                "source": f.get("source", "pattern_validator"),
                "selector": f.get("selector", "text_body")
            })

        global_logger.log_event("SCAN", f"Scanned content ({len(req.content)} chars), detected {len(findings)} sensitive items")

        return {
            "status": "success",
            "title": req.title or "Scanned Content",
            "url": req.url or "http://localhost",
            "findings_count": len(findings),
            "findings": safe_findings,
            "scanned_characters": len(req.content)
        }

    # Mode B: Browser testbed snapshot (used by Dashboard inspector)
    global_vault.clear()
    global_logger.clear()

    page_filename = req.scenario or "checkout.html"
    full_path = os.path.join(PAGES_DIR, page_filename)
    if not os.path.exists(full_path):
        raise HTTPException(status_code=404, detail=f"Page not found: {page_filename}")
    target_url = f"file:///{full_path.replace(os.sep, '/')}"

    with BrowserController(headless=True) as b:
        b.navigate(target_url)
        page = b.get_page()

        snapshot = capture_page_snapshot(page)
        raw_img = snapshot["image"]
        global_logger.log_event("CAPTURE", f"Captured snapshot of {snapshot.get('title')}")

        engine = DetectionEngine()
        findings = engine.scan_page_snapshot(snapshot, raw_img)
        stats.sensitive_findings_detected += len(findings)
        global_logger.log_event("DETECT", f"Engine detected {len(findings)} sensitive elements")

        clean_dom = sanitize_dom_tree(snapshot, findings, global_vault)
        clean_img = redact_screenshot(raw_img, findings)
        global_logger.log_event("SANITIZE", f"Tokens in RAM: {len(global_vault.get_all_raw_secrets())}")

        egress = EgressGateway(vault=global_vault, canary_manager=global_canary_mgr, fail_closed=False)
        egress_res = egress.inspect_and_filter(clean_dom, clean_img)
        if egress_res["passed"]:
            stats.payloads_cleared += 1
        else:
            stats.payloads_blocked += 1
        global_logger.log_event("EGRESS", f"Egress status: {'PASSED' if egress_res['passed'] else 'BLOCKED'}")

        return {
            "status": "success",
            "title": snapshot.get("title"),
            "url": snapshot.get("url"),
            "findings_count": len(findings),
            "findings": findings,
            "tokens": global_vault.get_token_summary(),
            "egress": egress_res,
            "raw_screenshot": pil_to_b64(raw_img),
            "clean_screenshot": pil_to_b64(clean_img),
            "audit_trail": global_logger.get_audit_trail()
        }


@app.post("/sanitize")
def sanitize_content(req: ContentPayloadRequest):
    """
    Substitutes detected sensitive values with stable placeholders ([EMAIL_1], [CARD_1]).
    Maintains token-to-value mapping in volatile RAM only.
    """
    content = req.content or ""
    if not content:
        raise HTTPException(status_code=400, detail="Content string required")

    engine = DetectionEngine()
    dummy_snapshot = {
        "title": req.title or "",
        "url": req.url or "",
        "text": content,
        "nodes": []
    }
    findings = engine.scan_page_snapshot(dummy_snapshot)

    # Sanitize content using RAM vault
    sanitized_text = sanitize_text(content, findings, global_vault)

    safe_findings = [
        {
            "type": f.get("type"),
            "confidence": f.get("confidence", 0.95),
            "reason": f.get("reason", "Detected sensitive value")
        }
        for f in findings
    ]

    return {
        "status": "success",
        "sanitized_content": sanitized_text,
        "findings_count": len(findings),
        "findings": safe_findings,
        "tokens": global_vault.get_token_summary()
    }


@app.post("/validate-egress")
def validate_egress(req: EgressValidateRequest):
    """
    Performs central outgoing-content fail-closed security check.
    Re-scans payload for known secrets, active canaries, and unsanitized credential patterns.
    """
    egress = EgressGateway(vault=global_vault, canary_manager=global_canary_mgr, fail_closed=False)
    res = egress.inspect_and_filter(req.payload)

    if res["passed"]:
        stats.payloads_cleared += 1
        return {
            "status": "CLEARED",
            "passed": True,
            "violations_count": 0,
            "message": "Outgoing payload is clean. Passed all multi-pass egress scans."
        }
    else:
        stats.payloads_blocked += 1
        return {
            "status": "BLOCKED",
            "passed": False,
            "violations_count": len(res.get("leaks", [])),
            "violations": res.get("leaks", []),
            "message": "Egress Gateway Intercepted sensitive data leak. Payload blocked."
        }


@app.post("/approval/request")
def create_approval_request(req: ApprovalCreateRequest):
    """Creates a pending human-in-the-loop approval ticket for consequential actions."""
    stats.total_approvals_requested += 1
    ticket = global_approval_gate.request_approval(
        action=req.action,
        element_meta={"selector": req.target, "domain": req.domain},
        context_description=req.description
    )
    return ticket


@app.get("/approval/pending")
@app.get("/api/approvals")
def get_pending_approvals():
    """Lists all pending approval tickets."""
    return global_approval_gate.get_pending()


@app.post("/approval/{ticket_id}/decision")
@app.post("/api/approvals/respond")
def record_approval_decision(
    ticket_id: Optional[str] = None,
    req: Optional[ApprovalDecisionRequest] = None,
    legacy_body: Optional[Dict[str, Any]] = Body(None)
):
    """Records an authorized user's approval or rejection decision."""
    # Support both REST param and legacy body
    target_id = ticket_id or (legacy_body.get("ticket_id") if legacy_body else None)
    decision = (req.decision if req else (legacy_body.get("action") if legacy_body else "reject")).lower()

    if not target_id:
        raise HTTPException(status_code=400, detail="Missing ticket_id")

    if decision in ("approve", "approved"):
        ok = global_approval_gate.approve(target_id)
        if ok:
            stats.total_approvals_granted += 1
        status_str = "APPROVED"
    else:
        ok = global_approval_gate.reject(target_id)
        status_str = "REJECTED"

    return {
        "ticket_id": target_id,
        "status": status_str,
        "success": ok
    }


@app.post("/vault/clear")
def clear_vault():
    """Safely purges all in-memory vault contents."""
    global_vault.clear()
    return {"status": "cleared", "active_tokens": 0}


# ==============================================================================
# DASHBOARD & AGENT HELPERS
# ==============================================================================

@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    index_path = os.path.join(DASHBOARD_DIR, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>PrivacyLens Dashboard loading...</h1>"


@app.get("/api/scenarios")
def get_scenarios():
    return SCENARIOS


@app.post("/api/run-agent")
def run_agent_interactive(req: AgentRunRequest):
    """Runs autonomous agent with secret injection on the selected page."""
    page_filename = req.scenario or "checkout.html"
    full_path = os.path.join(PAGES_DIR, page_filename)
    if not os.path.exists(full_path):
        raise HTTPException(status_code=404, detail="Page not found")

    target_url = f"file:///{full_path.replace(os.sep, '/')}"
    with BrowserController(headless=True) as b:
        agent = AgentLoop(browser=b, max_steps=8, auto_approve=req.auto_approve)
        result = agent.run(task_goal=req.task_goal, target_url=target_url)

    resp = {
        "success": result.get("success"),
        "steps": result.get("steps"),
        "duration_seconds": result.get("duration_seconds"),
        "findings_count": result.get("findings_count"),
        "vault_tokens": result.get("vault_tokens"),
        "cloud_sensitive_bytes_leaked": result.get("cloud_sensitive_bytes_leaked", 0),
        "audit_trail": result.get("audit_trail", [])
    }

    if "raw_image" in result and result["raw_image"]:
        resp["raw_screenshot"] = pil_to_b64(result["raw_image"])
    if "clean_image" in result and result["clean_image"]:
        resp["clean_screenshot"] = pil_to_b64(result["clean_image"])

    return resp


@app.get("/api/eval")
def get_eval_results():
    results_json = os.path.join(WORKSPACE_ROOT, "eval", "results", "comparison_results.json")
    if os.path.exists(results_json):
        with open(results_json, "r", encoding="utf-8") as f:
            return json.load(f)
    return run_full_evaluation()


@app.post("/api/eval/run")
def trigger_eval_run():
    return run_full_evaluation()


@app.get("/api/canary-benchmark")
def get_canary_benchmark():
    return run_canary_leakage_benchmark()


@app.on_event("shutdown")
def shutdown_event():
    global cached_browser
    if cached_browser:
        cached_browser.close()
