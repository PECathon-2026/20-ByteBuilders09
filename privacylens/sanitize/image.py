"""
PrivacyLens - Image Redactor & Screenshot Sanitizer
Draws opaque black redaction boxes over sensitive element coordinates, blurs human faces,
strips EXIF metadata, and prepares visual payloads for fail-closed egress inspection.
"""

import io
from typing import List, Dict, Any, Optional
from PIL import Image, ImageDraw, ImageFilter, ImageFont


def redact_screenshot(
    image: Image.Image,
    findings: List[Dict[str, Any]],
    box_color: str = "#090d16",
    label_redactions: bool = True
) -> Image.Image:
    """
    Applies privacy masks to screenshot:
    1. Black boxes over sensitive DOM inputs and OCR bounding boxes.
    2. Gaussian blur / pixelation over human faces.
    3. Strips all EXIF and hardware metadata.
    """
    # Create clean copy in RGB mode (strip EXIF metadata completely)
    sanitized = Image.new("RGB", image.size)
    sanitized.paste(image)
    draw = ImageDraw.Draw(sanitized)

    for item in findings:
        bbox = item.get("bbox")  # [x, y, w, h]
        if not bbox or len(bbox) != 4:
            continue

        x, y, w, h = bbox
        if w <= 0 or h <= 0:
            continue

        # Add 3px safety margin padding around bbox
        pad = 4
        x0 = max(0, x - pad)
        y0 = max(0, y - pad)
        x1 = min(image.width, x + w + pad)
        y1 = min(image.height, y + h + pad)

        sens_type = item.get("type", "SECRET")

        if sens_type == "FACE":
            # Apply heavy Gaussian blur to facial region
            try:
                face_region = sanitized.crop((x0, y0, x1, y1))
                blurred_face = face_region.filter(ImageFilter.GaussianBlur(radius=18))
                sanitized.paste(blurred_face, (x0, y0))
                # Draw subtle bounding outline
                draw.rectangle([x0, y0, x1, y1], outline="#38bdf8", width=2)
            except Exception:
                draw.rectangle([x0, y0, x1, y1], fill="#1e293b")
        else:
            # Draw solid opaque black privacy box
            draw.rectangle([x0, y0, x1, y1], fill=box_color)

            # Optional subtle label for explainability
            if label_redactions and (x1 - x0) > 40 and (y1 - y0) > 14:
                tag = f"REDACTED [{sens_type}]"
                draw.text((x0 + 4, y0 + 2), tag, fill="#38bdf8")

    return sanitized


def image_to_bytes(image: Image.Image, fmt: str = "PNG") -> bytes:
    """Converts PIL image to pure memory byte stream without EXIF metadata."""
    buf = io.BytesIO()
    image.save(buf, format=fmt)
    return buf.getvalue()
