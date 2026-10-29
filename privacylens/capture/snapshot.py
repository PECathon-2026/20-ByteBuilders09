"""
PrivacyLens - DOM & Visual Snapshot Collector
Captures DOM element tree, accessibility attributes, text content, bounding boxes, and visual screenshot.
"""

import io
from typing import Dict, Any, List, Optional
from PIL import Image

DOM_EXTRACTION_SCRIPT = """
() => {
    function getSelector(el) {
        if (el.id) return '#' + el.id;
        let path = [];
        while (el && el.nodeType === Node.ELEMENT_NODE) {
            let selector = el.nodeName.toLowerCase();
            if (el.id) {
                selector += '#' + el.id;
                path.unshift(selector);
                break;
            } else {
                let sibling = el, nth = 1;
                while (sibling = sibling.previousElementSibling) {
                    if (sibling.nodeName.toLowerCase() === selector) nth++;
                }
                if (nth !== 1) selector += ":nth-of-type(" + nth + ")";
            }
            path.unshift(selector);
            el = el.parentNode;
        }
        return path.join(" > ");
    }

    function isElementHidden(el) {
        const style = window.getComputedStyle(el);
        if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return true;
        const rect = el.getBoundingClientRect();
        if (rect.width === 0 || rect.height === 0) return true;
        if (rect.left < -500 || rect.top < -500) return true;
        return false;
    }

    const interactiveTags = ['input', 'select', 'textarea', 'button', 'a', 'code', 'div', 'span', 'p', 'h1', 'h2', 'h3', 'form'];
    const elements = Array.from(document.querySelectorAll(interactiveTags.join(',')));
    const nodes = [];

    for (const el of elements) {
        const rect = el.getBoundingClientRect();
        const attrs = {};
        for (const attr of el.attributes) {
            attrs[attr.name] = attr.value;
        }

        // Determine associated label
        let labelText = '';
        if (el.id) {
            const labelEl = document.querySelector(`label[for="${el.id}"]`);
            if (labelEl) labelText = labelEl.innerText;
        }

        // Only include non-empty or interactive nodes to keep snapshot clean
        const isInput = ['input', 'select', 'textarea', 'button'].includes(el.tagName.toLowerCase());
        const hasText = (el.innerText || '').trim().length > 0;
        const hasValue = !!el.value;
        const isHidden = isElementHidden(el);

        if (isInput || hasText || hasValue || isHidden || attrs['id']) {
            nodes.push({
                tagName: el.tagName.toLowerCase(),
                selector: getSelector(el),
                attributes: attrs,
                value: el.value !== undefined ? String(el.value) : null,
                textContent: (el.innerText || el.textContent || '').trim(),
                labelText: labelText,
                isHidden: isHidden,
                bbox: [Math.round(rect.left), Math.round(rect.top), Math.round(rect.width), Math.round(rect.height)]
            });
        }
    }

    return {
        title: document.title,
        url: window.location.href,
        text: document.body.innerText || '',
        nodes: nodes
    };
}
"""


def capture_page_snapshot(page) -> Dict[str, Any]:
    """
    Executes DOM extraction on the Playwright page and captures a high-resolution screenshot.
    Returns: {title, url, text, nodes, image: PIL.Image}
    """
    dom_data = page.evaluate(DOM_EXTRACTION_SCRIPT)
    screenshot_bytes = page.screenshot(full_page=False)
    image = Image.open(io.BytesIO(screenshot_bytes)).convert("RGB")

    dom_data["image"] = image
    return dom_data
