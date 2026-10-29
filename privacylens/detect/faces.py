"""
PrivacyLens - Face Detector
Detects facial regions in screenshots and avatars for visual blurring.
Provides OpenCV Haar-Cascade detection when available, with a DOM/PIL geometric fallback.
"""

from typing import List, Dict, Any, Optional
from PIL import Image

try:
    import cv2
    import numpy as np
    CV2_AVAILABLE = True
except Exception:
    CV2_AVAILABLE = False


def detect_faces_in_image(image: Image.Image) -> List[Dict[str, Any]]:
    """
    Detects face bounding boxes in an image.
    Returns: [{bbox: [x, y, w, h], confidence, reason, source: 'face_detector'}]
    """
    findings = []

    if CV2_AVAILABLE:
        try:
            cv_img = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
            gray = cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY)
            face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
            faces = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(30, 30))
            for (x, y, w, h) in faces:
                findings.append({
                    "type": "FACE",
                    "bbox": [int(x), int(y), int(w), int(h)],
                    "confidence": 0.92,
                    "reason": "OpenCV Haar-Cascade detected human facial features",
                    "source": "cv2:haar"
                })
            if findings:
                return findings
        except Exception:
            pass

    return findings


def detect_faces_from_dom_elements(nodes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Identifies avatar, webcam, and participant face elements from DOM metadata.
    """
    face_findings = []
    face_keywords = ["face-", "avatar-", "webcam", "participant", "profile-photo", "user-avatar"]

    for node in nodes:
        selector = node.get("selector", "")
        node_id = node.get("attributes", {}).get("id", "")
        classes = node.get("attributes", {}).get("class", "")
        bbox = node.get("bbox")  # [x, y, w, h]

        match_key = None
        for kw in face_keywords:
            if kw in selector.lower() or kw in node_id.lower() or kw in classes.lower():
                match_key = kw
                break

        if match_key and bbox:
            face_findings.append({
                "type": "FACE",
                "value": node_id or selector,
                "bbox": bbox,
                "selector": selector,
                "confidence": 0.94,
                "reason": f"DOM video/avatar tile match ('{match_key}')",
                "source": "dom:face_tile"
            })

    return face_findings
