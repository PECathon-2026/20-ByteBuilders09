"""
PrivacyLens 2.0 - Evidence-Based Privacy Proof Report Generator
Generates exportable JSON and CSV evidence reports for judges and auditors.
Secrets are strictly purged: only scenario metadata, canary IDs, and measured metrics are included.
"""

import io
import csv
import json
import time
from typing import Dict, Any, List

from .scenarios import get_all_scenarios
from .pipeline import run_scenario_comparison


def run_full_privacy_challenge() -> Dict[str, Any]:
    """
    Executes the one-click Full Privacy Challenge across all 6 local synthetic scenarios.
    Returns side-by-side evidence, event traces, and macro comparative averages.
    """
    scenarios = get_all_scenarios()
    scenario_results: List[Dict[str, Any]] = []

    # Aggregators for macro metrics
    total_scenarios = len(scenarios)

    base_recall_sum = 0.0
    base_precision_sum = 0.0
    base_leak_sum = 0.0
    base_latency_sum = 0.0

    pl_recall_sum = 0.0
    pl_precision_sum = 0.0
    pl_leak_sum = 0.0
    pl_latency_sum = 0.0
    pl_blocked_total = 0

    for sc in scenarios:
        res = run_scenario_comparison(sc)
        scenario_results.append(res)

        b_m = res["baseline"]["metrics"]
        base_recall_sum += b_m["recall_pct"]
        base_precision_sum += b_m["precision_pct"]
        base_leak_sum += b_m["canary_leakage_pct"]
        base_latency_sum += b_m["processing_time_ms"]

        p_m = res["privacylens"]["metrics"]
        pl_recall_sum += p_m["recall_pct"]
        pl_precision_sum += p_m["precision_pct"]
        pl_leak_sum += p_m["canary_leakage_pct"]
        pl_latency_sum += p_m["processing_time_ms"]
        pl_blocked_total += p_m["payloads_blocked_count"]

    macro_summary = {
        "total_scenarios_evaluated": total_scenarios,
        "baseline": {
            "avg_recall_pct": round(base_recall_sum / total_scenarios, 1) if total_scenarios > 0 else 0.0,
            "avg_precision_pct": round(base_precision_sum / total_scenarios, 1) if total_scenarios > 0 else 0.0,
            "avg_canary_leakage_pct": round(base_leak_sum / total_scenarios, 1) if total_scenarios > 0 else 0.0,
            "avg_latency_ms": round(base_latency_sum / total_scenarios, 2) if total_scenarios > 0 else 0.0,
            "total_payloads_blocked": 0
        },
        "privacylens": {
            "avg_recall_pct": round(pl_recall_sum / total_scenarios, 1) if total_scenarios > 0 else 0.0,
            "avg_precision_pct": round(pl_precision_sum / total_scenarios, 1) if total_scenarios > 0 else 0.0,
            "avg_canary_leakage_pct": round(pl_leak_sum / total_scenarios, 1) if total_scenarios > 0 else 0.0,
            "avg_latency_ms": round(pl_latency_sum / total_scenarios, 2) if total_scenarios > 0 else 0.0,
            "total_payloads_blocked": pl_blocked_total
        }
    }

    return {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "product": "PrivacyLens 2.0",
        "tagline": "Prove Before You Trust.",
        "defining_feature": "Privacy Proof Lab",
        "macro_summary": macro_summary,
        "scenarios": scenario_results
    }


def export_report_json(report_data: Dict[str, Any]) -> str:
    """Exports the Privacy Proof Report as formatted JSON."""
    return json.dumps(report_data, indent=2)


def export_report_csv(report_data: Dict[str, Any]) -> str:
    """Exports scenario comparison rows as CSV."""
    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        "Scenario ID",
        "Scenario Name",
        "Category",
        "Ground Truth Items",
        "Baseline Status",
        "Baseline Leaked Canaries",
        "Baseline Recall (%)",
        "Baseline Leakage (%)",
        "PrivacyLens Status",
        "PrivacyLens Decision",
        "PrivacyLens Leaked Canaries",
        "PrivacyLens Recall (%)",
        "PrivacyLens Leakage (%)",
        "PrivacyLens Latency (ms)",
        "Payload Blocked"
    ])

    for sc in report_data.get("scenarios", []):
        b = sc["baseline"]
        p = sc["privacylens"]
        bm = b["metrics"]
        pm = p["metrics"]

        writer.writerow([
            sc["scenario_id"],
            sc["scenario_name"],
            sc["category"],
            sc["ground_truth_count"],
            b["status"],
            b["leaked_canaries_count"],
            bm["recall_pct"],
            bm["canary_leakage_pct"],
            p["status"],
            p["decision"],
            p["leaked_canaries_count"],
            pm["recall_pct"],
            pm["canary_leakage_pct"],
            pm["processing_time_ms"],
            "YES" if pm["payloads_blocked_count"] > 0 else "NO"
        ])

    return output.getvalue()
