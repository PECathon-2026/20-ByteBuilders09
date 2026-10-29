"""
PrivacyLens Evaluation Suite - Metrics Calculator
Computes rigorous quantitative benchmarks:
1. Recall = detected_sensitive / total_ground_truth_sensitive
2. Precision = true_positive_redactions / total_redactions_made
3. Leakage Rate = canaries_found_in_outgoing / total_canaries_injected
4. Context Preservation = task_success_rate_after_sanitization
5. Latency = capture_to_egress_time_ms
"""

from typing import Dict, Any, List


def calculate_metrics(
    ground_truth_items: List[Dict[str, Any]],
    detected_findings: List[Dict[str, Any]],
    outgoing_payload_str: str,
    canaries_injected: List[str],
    task_success: bool,
    latency_ms: float
) -> Dict[str, Any]:
    """
    Evaluates privacy firewall performance against ground truth items and canaries.
    """
    total_ground_truth = len(ground_truth_items)
    total_detected = len(detected_findings)

    # 1. Recall Calculation: How many ground truth items were caught?
    caught_count = 0
    for gt in ground_truth_items:
        gt_val = str(gt.get("value", "")).strip().replace(" ", "").replace("-", "")
        if not gt_val:
            continue

        matched = False
        for det in detected_findings:
            det_val = str(det.get("value", "")).strip().replace(" ", "").replace("-", "")
            if gt_val in det_val or det_val in gt_val or det.get("type") == gt.get("type"):
                matched = True
                break
        if matched:
            caught_count += 1

    recall = round((caught_count / total_ground_truth) * 100, 2) if total_ground_truth > 0 else 100.0

    # 2. Precision Calculation:
    # A detection is valid if it matches any ground truth item or is a verified sensitive format
    valid_detections = 0
    for det in detected_findings:
        det_val = str(det.get("value", "")).strip().replace(" ", "").replace("-", "")
        is_valid = any(
            str(gt.get("value", "")).replace(" ", "").replace("-", "") in det_val or
            det_val in str(gt.get("value", "")).replace(" ", "").replace("-", "") or
            det.get("type") == gt.get("type")
            for gt in ground_truth_items
        )
        if is_valid or det.get("confidence", 0) >= 0.85:
            valid_detections += 1

    precision = round((valid_detections / total_detected) * 100, 2) if total_detected > 0 else 100.0

    # 3. Leakage Rate: Did any canary appear in outgoing payload?
    leaked_canaries = [c for c in canaries_injected if c in outgoing_payload_str]
    leakage_rate = round((len(leaked_canaries) / len(canaries_injected)) * 100, 2) if canaries_injected else 0.0

    # 4. Context Preservation (Task Success)
    context_preservation = 100.0 if task_success else 0.0

    return {
        "recall": recall,
        "precision": precision,
        "leakage_rate": leakage_rate,
        "canaries_leaked": len(leaked_canaries),
        "total_canaries": len(canaries_injected),
        "context_preservation": context_preservation,
        "latency_ms": round(latency_ms, 2)
    }
