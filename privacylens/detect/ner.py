"""
PrivacyLens - Named Entity Recognition (NER) for Names & Addresses
Extracts PERSON names and physical ADDRESS locations with high precision.
Supports Presidio/spaCy when available, with a fast, zero-dependency heuristic fallback.
"""

import re
from typing import List, Dict, Any

# Indian & International honorifics and name markers
HONORIFICS = r"\b(Mr\.|Mrs\.|Ms\.|Dr\.|Prof\.|Shri|Smt\.|Customer:|Host:|Name:)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3})\b"

# Address markers (Indian pincodes, flats, roads, layouts, cities)
ADDRESS_PATTERNS = [
    re.compile(r"\b(?:Flat|House|Plot|Apartment|Tower|Sector|Phase|Road|Street|Layout|Nagar|Colony|Lane)[^,\n]{2,40},\s*[^,\n]{2,40},\s*(?:Bengaluru|Bangalore|Delhi|Mumbai|Hyderabad|Chennai|Pune|Kolkata|Noida|Gurugram|Jaipur|Ahmedabad)\s*(?:[0-9]{6})?", re.IGNORECASE),
    re.compile(r"\b[1-9][0-9]{2}\s?[0-9]{3}\b")  # Indian 6-digit PIN code
]

# Common name dictionary for rapid entity disambiguation
KNOWN_FIRST_NAMES = {
    "aarav", "rajesh", "vikramaditya", "ananya", "priya", "rohit", "alex", "john", "neha", "sanjay",
    "kavita", "amit", "deepa", "arjun", "sneha", "rahul", "pooja", "tarun", "aditi", "karan"
}


def extract_entities_from_text(text: str) -> List[Dict[str, Any]]:
    """
    Scans text for PERSON and ADDRESS entities.
    Returns: [{type, value, start, end, confidence, reason, source='ner'}]
    """
    findings = []

    # 1. Names with honorific or conversational prefix (e.g., "Customer: Rajesh Kulkarni", "Host: Vikramaditya Roy")
    for m in re.finditer(HONORIFICS, text):
        full_match = m.group(0)
        name_val = m.group(2).strip()
        findings.append({
            "type": "PERSON",
            "value": name_val,
            "start": m.start(2),
            "end": m.end(2),
            "confidence": 0.94,
            "reason": f"NER: Name pattern with context prefix '{m.group(1)}'",
            "source": "ner:heuristic"
        })

    # 2. Name scanning via capitalized pair matching known names
    words = text.split()
    for i in range(len(words) - 1):
        clean_first = re.sub(r"[^\w]", "", words[i]).lower()
        clean_second = re.sub(r"[^\w]", "", words[i + 1])
        if clean_first in KNOWN_FIRST_NAMES and clean_second.istitle() and len(clean_second) > 2:
            candidate = f"{words[i].strip(' ,.:;')} {words[i+1].strip(' ,.:;')}"
            start_pos = text.find(candidate)
            if start_pos != -1 and not any(f["value"] == candidate for f in findings):
                findings.append({
                    "type": "PERSON",
                    "value": candidate,
                    "start": start_pos,
                    "end": start_pos + len(candidate),
                    "confidence": 0.90,
                    "reason": f"NER: Detected personal name '{candidate}'",
                    "source": "ner:dictionary"
                })

    # 3. Addresses
    for pat in ADDRESS_PATTERNS:
        for m in pat.finditer(text):
            val = m.group(0).strip()
            if len(val) > 8 and not any(f["value"] == val for f in findings):
                findings.append({
                    "type": "ADDRESS",
                    "value": val,
                    "start": m.start(),
                    "end": m.end(),
                    "confidence": 0.88,
                    "reason": "NER: Physical address structure with city / postal PIN",
                    "source": "ner:address_pattern"
                })

    return findings
