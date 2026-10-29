"""
PrivacyLens - DOM Sanitizer
Cleanses hidden elements, URL parameters, document title, alt-text, and accessibility labels.
Assigns deterministic element IDs (pl-1, pl-2, ...) so the LLM operates with guaranteed safe references.
"""

import re
import copy
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import Dict, Any, List, Tuple
from .vault import LocalSecretVault
from .text import sanitize_text


def sanitize_url(raw_url: str, findings: List[Dict[str, Any]], vault: LocalSecretVault) -> str:
    """
    Sanitizes query parameters and path segments in a URL, replacing sensitive keys/values with tokens.
    """
    if not raw_url:
        return ""
    parsed = urlparse(raw_url)
    if not parsed.query:
        return sanitize_text(raw_url, findings, vault)

    qs = parse_qs(parsed.query, keep_blank_values=True)
    sanitized_qs = {}
    for k, v_list in qs.items():
        clean_k = sanitize_text(k, findings, vault)
        sanitized_qs[clean_k] = [sanitize_text(v, findings, vault) for v in v_list]

    clean_query = urlencode(sanitized_qs, doseq=True)
    clean_parts = list(parsed)
    clean_parts[4] = clean_query
    return urlunparse(clean_parts)


def sanitize_dom_tree(
    snapshot: Dict[str, Any],
    findings: List[Dict[str, Any]],
    vault: LocalSecretVault
) -> Dict[str, Any]:
    """
    Produces a safe, thoroughly sanitized snapshot ready for untrusted cloud LLM consumption.
    1. Assigns sequential element IDs: 'pl-1', 'pl-2', ... to interactive nodes.
    2. Redacts title, URL query params, hidden elements, input values, aria labels, and text.
    3. Purges all cookies, sessionStorage, and localStorage.
    """
    clean_snapshot = copy.deepcopy(snapshot)

    # 1. Clean Title and URL
    clean_snapshot["title"] = sanitize_text(clean_snapshot.get("title", ""), findings, vault)
    clean_snapshot["url"] = sanitize_url(clean_snapshot.get("url", ""), findings, vault)

    # 2. Assign deterministic pl-X IDs to elements and build element_map
    nodes = clean_snapshot.get("nodes", [])
    element_map: Dict[str, Dict[str, Any]] = {}
    counter = 1

    for node in nodes:
        elem_id = f"pl-{counter}"
        counter += 1
        node["element_id"] = elem_id
        element_map[elem_id] = {
            "selector": node.get("selector", ""),
            "tagName": node.get("tagName", ""),
            "type": node.get("attributes", {}).get("type", ""),
            "bbox": node.get("bbox")
        }

        # Sanitize attributes (alt, aria-label, placeholder, value, title, data-*)
        attrs = node.get("attributes", {})
        for attr_k, attr_v in list(attrs.items()):
            # Completely strip cookies or storage data attributes
            if "cookie" in attr_k.lower() or "storage" in attr_k.lower() or "session" in attr_k.lower():
                attrs[attr_k] = "[STRIPPED_STORAGE]"
            else:
                attrs[attr_k] = sanitize_text(str(attr_v), findings, vault)

        # Sanitize value and textContent
        if "value" in node and node["value"]:
            node["value"] = sanitize_text(str(node["value"]), findings, vault)

        if "textContent" in node and node["textContent"]:
            node["textContent"] = sanitize_text(str(node["textContent"]), findings, vault)

        # If element is hidden, explicitly purge sensitive content
        if node.get("isHidden", False) or attrs.get("aria-hidden") == "true":
            node["textContent"] = "[HIDDEN_NODE_REDACTED]"
            if "value" in node:
                node["value"] = "[HIDDEN_VALUE_REDACTED]"

    # 3. Purge sensitive browser storage channels
    clean_snapshot.pop("cookies", None)
    clean_snapshot.pop("localStorage", None)
    clean_snapshot.pop("sessionStorage", None)

    # 4. Clean root text dump
    if "text" in clean_snapshot:
        clean_snapshot["text"] = sanitize_text(clean_snapshot["text"], findings, vault)

    clean_snapshot["element_map"] = element_map
    return clean_snapshot
