"""
PrivacyLens - Algorithmic and Checksum Validators
Provides mathematical verification for cards (Luhn), Aadhaar (Verhoeff), PAN, IFSC, etc.
"""

import re
from typing import Tuple

# Verhoeff tables
VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
]

VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8]
]

VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def luhn(card_number: str) -> bool:
    """Validates credit / debit card number using Luhn mod-10 algorithm."""
    clean = re.sub(r"[\s\-]+", "", str(card_number))
    if not clean.isdigit() or len(clean) < 13 or len(clean) > 19:
        return False
    digits = [int(d) for d in clean]
    sum_digits = 0
    alt = False
    for d in reversed(digits):
        if alt:
            val = d * 2
            if val > 9:
                val -= 9
            sum_digits += val
        else:
            sum_digits += d
        alt = not alt
    return sum_digits % 10 == 0


def verhoeff(aadhaar_number: str) -> bool:
    """Validates Indian 12-digit Aadhaar number with the Verhoeff dihedral group algorithm."""
    clean = re.sub(r"[\s\-]+", "", str(aadhaar_number))
    if not clean.isdigit() or len(clean) != 12:
        return False
    # First digit of real Aadhaar cannot be 0 or 1
    if clean[0] in ("0", "1"):
        return False
    c = 0
    reversed_digits = [int(x) for x in reversed(clean)]
    for i, digit in enumerate(reversed_digits):
        p_val = VERHOEFF_P[i % 8][digit]
        c = VERHOEFF_D[c][p_val]
    return c == 0


def pan_check(pan: str) -> bool:
    """
    Validates Indian Income Tax Permanent Account Number (PAN).
    Format: 5 letters, 4 numbers, 1 letter.
    4th character denotes entity: P, C, H, F, A, T, B, L, J, G.
    """
    clean = pan.strip().upper()
    if len(clean) != 10:
        return False
    pattern = r"^[A-Z]{3}[ABCFGHLJPT][A-Z][0-9]{4}[A-Z]$"
    return bool(re.match(pattern, clean))


def ifsc_check(ifsc: str) -> bool:
    """Validates Indian Financial System Code (IFSC): 4 letters, 0, 6 alphanumeric."""
    clean = ifsc.strip().upper()
    if len(clean) != 11:
        return False
    pattern = r"^[A-Z]{4}0[A-Z0-9]{6}$"
    return bool(re.match(pattern, clean))


def upi_check(upi: str) -> bool:
    """Validates Unified Payments Interface (UPI) VPA identifier."""
    clean = upi.strip().lower()
    pattern = r"^[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}$"
    if not re.match(pattern, clean):
        return False
    # Exclude common email domains that are not UPI providers unless explicitly flagged
    known_upi_handles = {
        "okaxis", "okhdfcbank", "oksbi", "okicici", "paytm", "apl", "ybl",
        "icici", "sbi", "axisbank", "fbl", "federal", "indus", "postbank",
        "airtel", "kotak", "barodampay", "upi"
    }
    handle = clean.split("@")[-1]
    return handle in known_upi_handles or bool(re.search(r"upi|pay|bank|okh", handle))


def email_check(email: str) -> bool:
    """Validates standard email address."""
    clean = email.strip()
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, clean))


def phone_check(phone: str) -> bool:
    """Validates telephone or Indian mobile number."""
    clean = re.sub(r"[\s\-\(\)\.]+", "", phone)
    # Check Indian 10-digit (+91 optional) or international E.164
    if re.match(r"^(\+91|91)?[6789]\d{9}$", clean):
        return True
    if re.match(r"^\+[1-9]\d{8,14}$", clean):
        return True
    return False


def ip_check(ip: str) -> bool:
    """Validates IPv4 address, filtering out version strings like 1.0.0 or 2.1.4."""
    parts = ip.strip().split(".")
    if len(parts) != 4:
        return False
    try:
        nums = [int(p) for p in parts]
        return all(0 <= n <= 255 for n in nums)
    except ValueError:
        return False
