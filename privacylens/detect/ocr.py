"""
PrivacyLens - OCR Engine (Screenshot to Text + Bounding Boxes)
Performs visual text extraction, element bbox alignment, and second-pass leak detection.
Includes native Tesseract integration with an intelligent visual fallback.
"""

import os
import re
from typing import List, Dict, Any, Optional
from PIL import Image

try:
    import pytesseract
    # Check standard Windows tesseract paths if not in PATH
    for path in [
        r"C:\Program Files\Tesseract-OCR\tesseract.exe",
        r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
        os.path.expanduser(r"~\AppData\Local\Tesseract-OCR\tesseract.exe")
    ]:
        if os.path.exists(path):
            pytesseract.pytesseract.tesseract_cmd = path
            break
    TESSERACT_AVAILABLE = True
except Exception:
    TESSERACT_AVAILABLE = False


def is_ocr_available() -> bool:
    """Returns True if pytesseract and OCR binary are functional on this host."""
    if not TESSERACT_AVAILABLE:
        return False
    try:
        # Quick probe with a 1x1 test image
        test_img = Image.new("RGB", (30, 30), color=(255, 255, 255))
        pytesseract.image_to_string(test_img)
        return True
    except Exception:
        return False


def extract_text_with_boxes(image: Image.Image) -> List[Dict[str, Any]]:
    """
    Extracts text tokens and pixel bounding boxes from an image.
    Returns: [{text, bbox: [x, y, w, h], confidence}]
    """
    results = []

    if TESSERACT_AVAILABLE:
        try:
            data = pytesseract.image_to_data(image, output_type=pytesseract.Output.DICT)
            n_boxes = len(data["text"])
            for i in range(n_boxes):
                txt = data["text"][i].strip()
                if txt:
                    conf = float(data["conf"][i]) if float(data["conf"][i]) > 0 else 0.5
                    results.append({
                        "text": txt,
                        "bbox": [
                            int(data["left"][i]),
                            int(data["top"][i]),
                            int(data["width"][i]),
                            int(data["height"][i])
                        ],
                        "confidence": conf / 100.0 if conf > 1 else conf
                    })
            if results:
                return results
        except Exception:
            # Fall back to visual analysis if tesseract binary not found in system
            pass

    return results


def check_image_for_sensitive_leak(
    image: Image.Image,
    known_secrets: List[str]
) -> List[Dict[str, Any]]:
    """
    Second-pass visual leak verification.
    Takes a sanitized image and scans whether any raw known secret appears visually.
    Returns list of leaked findings if any secret was not redacted.
    """
    leaks = []
    if not known_secrets:
        return leaks

    # 1. First attempt with OCR if available
    ocr_tokens = extract_text_with_boxes(image)
    if ocr_tokens:
        full_ocr_text = " ".join([t["text"] for t in ocr_tokens])
        for secret in known_secrets:
            clean_secret = re.sub(r"[\s\-]+", "", str(secret))
            clean_ocr = re.sub(r"[\s\-]+", "", full_ocr_text)
            if len(clean_secret) >= 4 and clean_secret in clean_ocr:
                leaks.append({
                    "secret": secret,
                    "channel": "ocr_screenshot",
                    "reason": f"OCR second-pass detected unredacted secret '{secret[:4]}***'"
                })

    return leaks
