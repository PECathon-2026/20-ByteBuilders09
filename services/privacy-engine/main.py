from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import re, cv2, numpy as np, base64
from validators import luhn_checksum, verhoeff_checksum, shannon_entropy

app = FastAPI(title="PrivacyLens Engine")

class BoundingBox(BaseModel): 
    x: float; y: float; w: float; h: float
class DOMElement(BaseModel):
    id: int; tag: str; type: Optional[str] = None; value: str; attributes: List[Dict[str, str]] = []; bbox: BoundingBox
class ScanPayload(BaseModel): 
    elements: List[DOMElement]; screenshot: str

def analyze_elements(elements: List[DOMElement]) -> List[Dict[str, Any]]:
    detections = []
    pan_regex = re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b')
    aadhaar_regex = re.compile(r'\b\d{4}\s?\d{4}\s?\d{4}\b')
    card_regex = re.compile(r'\b(?:\d[ -]*?){13,19}\b')
    
    for el in elements:
        val = str(el.value).strip()
        if not val or el.bbox.w == 0: continue
        
        flagged, det_type = False, None
        
        if el.type in ['password', 'hidden'] or any(a['name'] == 'autocomplete' and 'cc-' in a.get('value', '').lower() for a in el.attributes):
            flagged, det_type = True, "AUTH_CREDENTIAL"
        elif pan_regex.search(val):
            flagged, det_type = True, "PAN_CARD"
        elif aadhaar_match := aadhaar_regex.search(val):
            if verhoeff_checksum(aadhaar_match.group().replace(' ', '')): flagged, det_type = True, "AADHAAR"
        elif card_match := card_regex.search(val):
            if luhn_checksum(re.sub(r'[\s-]', '', card_match.group())): flagged, det_type = True, "CREDIT_CARD"
        elif any(val.startswith(p) for p in ['sk-', 'ghp_', 'AIza']) and shannon_entropy(val) > 3.8:
            flagged, det_type = True, "API_SECRET"

        if flagged:
            detections.append({"element_id": el.id, "type": det_type, "raw_value": val, "bbox": el.bbox.dict()})
    return detections

def apply_redaction(base64_img: str, detections: List[Dict[str, Any]]) -> str:
    if not detections: return base64_img
    
    img_data = base64.b64decode(base64_img.split(',')[1] if ',' in base64_img else base64_img)
    img = cv2.imdecode(np.frombuffer(img_data, np.uint8), cv2.IMREAD_COLOR)
    
    for det in detections:
        x, y, w, h = int(det["bbox"]["x"]), int(det["bbox"]["y"]), int(det["bbox"]["w"]), int(det["bbox"]["h"])
        cv2.rectangle(img, (x, y), (x + w, y + h), (0, 0, 0), -1)
        cv2.putText(img, f"[REDACTED:{det['type']}]", (x + 2, y + 15), cv2.FONT_HERSHEY_SIMPLEX, 0.4, (0, 0, 255), 1)

    return base64.b64encode(cv2.imencode('.png', img)[1]).decode('utf-8')

@app.post("/api/detect")
async def detect_pii(payload: ScanPayload):
    try:
        detections = analyze_elements(payload.elements)
        sanitized_img = apply_redaction(payload.screenshot, detections)
        return {"status": "success", "detections": detections, "sanitized_screenshot": f"data:image/png;base64,{sanitized_img}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))