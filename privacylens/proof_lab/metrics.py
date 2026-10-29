"""
PrivacyLens 2.0 - Privacy Proof Lab Metrics Calculator
Provides explicit, mathematically rigorous formulas with robust zero-denominator handling.
"""

from typing import Dict, Any, List


def calculate_metrics(
    ground_truth_count: int,
    detected_count: int,
    true_positive_count: int,
    planted_canaries_count: int,
    leaked_canaries_count: int,
    payloads_blocked_count: int,
    processing_time_ms: float,
    context_preserved: bool = True
) -> Dict[str, Any]:
    """
    Calculates security and performance metrics with explicit zero-division guards.
    """
    # 1. Detection Recall: TP / GroundTruth
    if ground_truth_count > 0:
        recall = (true_positive_count / ground_truth_count) * 100.0
    else:
        recall = 100.0 if detected_count == 0 else 0.0

    # 2. Detection Precision: TP / TotalDetected
    if detected_count > 0:
        precision = (true_positive_count / detected_count) * 100.0
    else:
        precision = 100.0 if ground_truth_count == 0 else 0.0

    # 3. Canary Leakage Rate: Leaked / TotalPlanted
    if planted_canaries_count > 0:
        canary_leakage_rate = (leaked_canaries_count / planted_canaries_count) * 100.0
    else:
        canary_leakage_rate = 0.0

    # 4. Missed Sensitive Markers
    missed_markers = max(0, ground_truth_count - true_positive_count)

    # 5. Context Preservation Score (0 - 100%)
    context_score = 100.0 if context_preserved else 0.0

    return {
        "recall_pct": round(min(100.0, max(0.0, recall)), 1),
        "precision_pct": round(min(100.0, max(0.0, precision)), 1),
        "canary_leakage_pct": round(min(100.0, max(0.0, canary_leakage_rate)), 1),
        "missed_markers_count": missed_markers,
        "payloads_blocked_count": payloads_blocked_count,
        "processing_time_ms": round(processing_time_ms, 2),
        "context_preservation_pct": context_score
    }
