"""
PrivacyLens - Unified Detection Engine
Orchestrates regex pattern matchers, algorithmic validators, DOM structure rules,
NER, OCR, and face detectors into an explainable, deduplicated findings record.
"""

import uuid
from typing import List, Dict, Any, Optional
from PIL import Image

from .patterns import scan_text_patterns
from .structural import scan_dom_node, detect_split_otp
from .ner import extract_entities_from_text
from .faces import detect_faces_in_image, detect_faces_from_dom_elements
from .ocr import extract_text_with_boxes


class DetectionEngine:
    def __init__(self, policy: Optional[Dict[str, Any]] = None):
        self.policy = policy or {}

    def scan_text(self, text: str, url: str = "http://localhost") -> List[Dict[str, Any]]:
        """Scans arbitrary raw text with regex patterns, NER, and deduplication."""
        return self.scan_page_snapshot({"text": text, "url": url, "title": "", "nodes": []})

    def scan_page_snapshot(
        self,
        snapshot: Dict[str, Any],
        image: Optional[Image.Image] = None
    ) -> List[Dict[str, Any]]:
        """
        Scans a complete page snapshot (DOM, text, screenshot, inputs, URL, title)
        Returns unified, explainable findings:
        [{id, type, value, source, selector, bbox, confidence, reason, mode}]
        """
        raw_findings: List[Dict[str, Any]] = []

        # 1. Text & Regex analysis on page title, URL query params, and text content
        page_text = snapshot.get("text", "")
        title = snapshot.get("title", "")
        url = snapshot.get("url", "")
        combined_text = f"{title}\n{url}\n{page_text}"

        text_findings = scan_text_patterns(combined_text)
        for f in text_findings:
            f["channel"] = "text_pattern"
            raw_findings.append(f)

        # 2. NER for person names & addresses
        ner_findings = extract_entities_from_text(page_text)
        for f in ner_findings:
            f["channel"] = "ner"
            raw_findings.append(f)

        # 3. Structural DOM inspection across all elements
        dom_nodes = snapshot.get("nodes", [])
        for node in dom_nodes:
            # Check inputs, textareas, and hidden elements
            structural_findings = scan_dom_node(node)
            for f in structural_findings:
                f["channel"] = "dom_structure"
                if "bbox" in node:
                    f["bbox"] = node["bbox"]
                raw_findings.append(f)

            # Also scan node value/text specifically with regex
            val = node.get("value", "") or node.get("textContent", "")
            if val and len(val) >= 3:
                val_findings = scan_text_patterns(val)
                for vf in val_findings:
                    vf["selector"] = node.get("selector", "")
                    if "bbox" in node:
                        vf["bbox"] = node["bbox"]
                    vf["channel"] = "dom_input_regex"
                    raw_findings.append(vf)

        # 4. Split OTP boxes detector
        split_otp = detect_split_otp(dom_nodes)
        if split_otp:
            raw_findings.append(split_otp)

        # 5. Visual face detection in screenshot or DOM video tiles
        if image:
            visual_faces = detect_faces_in_image(image)
            for f in visual_faces:
                raw_findings.append(f)

        dom_faces = detect_faces_from_dom_elements(dom_nodes)
        for f in dom_faces:
            raw_findings.append(f)

        # Deduplicate and consolidate findings
        consolidated = self._deduplicate_findings(raw_findings, dom_nodes)
        return consolidated

    def _deduplicate_findings(
        self,
        findings: List[Dict[str, Any]],
        dom_nodes: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Deduplicates findings based on value and type.
        Preserves highest confidence and richer diagnostic reason.
        """
        seen_keys = {}
        unique_list = []

        # Sort by confidence descending so highest confidence wins
        sorted_findings = sorted(findings, key=lambda x: x.get("confidence", 0), reverse=True)

        for item in sorted_findings:
            sens_type = item.get("type")
            value = str(item.get("value", "")).strip()

            # Disambiguate Card vs Phone (Luhn cards take absolute precedence)
            if sens_type == "PHONE" and item.get("source") == "regex":
                clean_num = value.replace(" ", "").replace("-", "")
                if any(f.get("type") == "CARD" and clean_num in f.get("value", "").replace(" ", "") for f in unique_list):
                    continue

            key = (sens_type, value)
            if key not in seen_keys:
                finding_id = f"fnd-{str(uuid.uuid4())[:8]}"
                item["id"] = finding_id

                # Match bounding box from selector if bbox missing
                if not item.get("bbox") and item.get("selector"):
                    for n in dom_nodes:
                        if n.get("selector") == item.get("selector") and n.get("bbox"):
                            item["bbox"] = n.get("bbox")
                            break

                seen_keys[key] = item
                unique_list.append(item)
            else:
                # Merge selector or bbox if existing entry didn't have one
                existing = seen_keys[key]
                if not existing.get("selector") and item.get("selector"):
                    existing["selector"] = item.get("selector")
                if not existing.get("bbox") and item.get("bbox"):
                    existing["bbox"] = item.get("bbox")

        return unique_list
