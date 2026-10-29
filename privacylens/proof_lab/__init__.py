"""
PrivacyLens Proof Lab Package
"""

from .scenarios import (
    get_all_scenarios,
    get_all_planted_canaries,
    build_scenario_1_visible_text,
    build_scenario_2_hidden_dom,
    build_scenario_3_form_inputs,
    build_scenario_4_url_query,
    build_scenario_5_screenshot_pixels,
    build_scenario_6_prompt_injection
)
from .pipeline import (
    BaselinePipeline,
    PrivacyLensPipeline,
    run_scenario_comparison,
    run_live_text_evaluation
)
from .metrics import calculate_metrics
from .report import (
    run_full_privacy_challenge,
    export_report_json,
    export_report_csv
)

__all__ = [
    "get_all_scenarios",
    "get_all_planted_canaries",
    "BaselinePipeline",
    "PrivacyLensPipeline",
    "run_scenario_comparison",
    "run_live_text_evaluation",
    "calculate_metrics",
    "run_full_privacy_challenge",
    "export_report_json",
    "export_report_csv"
]
