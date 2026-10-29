"""
PrivacyLens - Synthetic Data Generator
Generates cryptographically valid test credentials and PII for testing:
- Luhn-valid Credit Cards (Visa, Mastercard, Amex)
- Verhoeff-valid Indian Aadhaar numbers (12-digit)
- Valid Indian Permanent Account Numbers (PAN)
- Indian UPI IDs & IFSC codes
- Realistic names, addresses, emails, phone numbers, and cloud API keys
"""

import random
import re
from typing import Dict, List, Any

# ==============================================================================
# VERHOEFF ALGORITHM (Used for Indian Aadhaar 12-digit validation)
# ==============================================================================

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


def generate_verhoeff_checksum(number_str: str) -> int:
    """Computes the Verhoeff checksum digit for a numerical string."""
    c = 0
    reversed_digits = [int(x) for x in reversed(number_str)]
    for i, digit in enumerate(reversed_digits):
        p_val = VERHOEFF_P[(i + 1) % 8][digit]
        c = VERHOEFF_D[c][p_val]
    return VERHOEFF_INV[c]


def validate_verhoeff(number_str: str) -> bool:
    """Validates an Aadhaar number using the Verhoeff algorithm."""
    clean = re.sub(r"\s+", "", str(number_str))
    if not clean.isdigit() or len(clean) != 12:
        return False
    c = 0
    reversed_digits = [int(x) for x in reversed(clean)]
    for i, digit in enumerate(reversed_digits):
        p_val = VERHOEFF_P[i % 8][digit]
        c = VERHOEFF_D[c][p_val]
    return c == 0


def generate_aadhaar(formatted: bool = True) -> str:
    """Generates a valid 12-digit Aadhaar number with valid Verhoeff checksum."""
    # Aadhaar cannot start with 0 or 1
    first_digit = str(random.randint(2, 9))
    remaining_10 = "".join([str(random.randint(0, 9)) for _ in range(10)])
    partial = first_digit + remaining_10
    checksum = generate_verhoeff_checksum(partial)
    full = partial + str(checksum)
    if formatted:
        return f"{full[0:4]} {full[4:8]} {full[8:12]}"
    return full


# ==============================================================================
# LUHN ALGORITHM (Credit/Debit Card generator)
# ==============================================================================

def generate_luhn_checksum(number_str: str) -> int:
    """Generates the check digit for a card number prefix using Luhn algorithm."""
    digits = [int(d) for d in number_str]
    # Double every second digit from right to left
    sum_digits = 0
    alt = True
    for d in reversed(digits):
        if alt:
            val = d * 2
            if val > 9:
                val -= 9
            sum_digits += val
        else:
            sum_digits += d
        alt = not alt
    return (10 - (sum_digits % 10)) % 10


def validate_luhn(card_number: str) -> bool:
    """Validates credit card number with Luhn algorithm."""
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


def generate_credit_card(card_type: str = "visa", formatted: bool = True) -> Dict[str, str]:
    """Generates a valid credit card with CVV and expiry."""
    if card_type.lower() == "visa":
        prefix = "4" + "".join([str(random.randint(0, 9)) for _ in range(14)])
        length = 16
    elif card_type.lower() == "mastercard":
        prefix = "5" + str(random.choice([1, 2, 3, 4, 5])) + "".join([str(random.randint(0, 9)) for _ in range(13)])
        length = 16
    elif card_type.lower() == "amex":
        prefix = "3" + str(random.choice([4, 7])) + "".join([str(random.randint(0, 9)) for _ in range(12)])
        length = 15
    else:  # RuPay
        prefix = "60" + "".join([str(random.randint(0, 9)) for _ in range(13)])
        length = 16

    checksum = generate_luhn_checksum(prefix)
    number = prefix + str(checksum)

    cvv_length = 4 if card_type.lower() == "amex" else 3
    cvv = "".join([str(random.randint(0, 9)) for _ in range(cvv_length)])
    exp_month = f"{random.randint(1, 12):02d}"
    exp_year = f"{random.randint(26, 31)}"

    formatted_num = " ".join([number[i:i + 4] for i in range(0, len(number), 4)]) if formatted else number

    return {
        "type": card_type,
        "number": formatted_num,
        "raw_number": number,
        "cvv": cvv,
        "expiry": f"{exp_month}/{exp_year}",
        "cardholder": "Aarav Sharma"
    }


# ==============================================================================
# INDIAN PAN (Permanent Account Number)
# ==============================================================================

def validate_pan(pan: str) -> bool:
    """Validates Indian PAN: 5 uppercase letters, 4 digits, 1 uppercase letter."""
    pattern = r"^[A-Z]{3}[ABCFGHLJPT][A-Z][0-9]{4}[A-Z]$"
    return bool(re.match(pattern, pan.strip().upper()))


def generate_pan(entity_type: str = "P") -> str:
    """
    Generates a valid Indian PAN string.
    4th char represents entity (P = Person, C = Company, H = HUF, F = Firm)
    """
    letters = "ABCDEFGHJKLMNPQRSTUVWXYZ"
    first3 = "".join(random.choices(letters, k=3))
    fourth = entity_type.upper()
    fifth = random.choice(letters)  # Surname initial
    digits = "".join([str(random.randint(0, 9)) for _ in range(4)])
    last = random.choice(letters)
    return f"{first3}{fourth}{fifth}{digits}{last}"


# ==============================================================================
# UPI ID & IFSC CODES
# ==============================================================================

UPI_HANDLES = ["okhdfcbank", "okaxis", "oksbi", "paytm", "apl", "ybl", "icici"]
IFSC_BANKS = ["HDFC", "SBIN", "ICIC", "PUNB", "KKBK", "UTIB"]


def validate_upi(upi: str) -> bool:
    pattern = r"^[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}$"
    return bool(re.match(pattern, upi.strip()))


def generate_upi(username: str = None) -> str:
    if not username:
        username = random.choice(["aarav.sharma", "priya_patel", "rohit.verma99", "pay_tech2026"])
    handle = random.choice(UPI_HANDLES)
    return f"{username}@{handle}"


def validate_ifsc(ifsc: str) -> bool:
    pattern = r"^[A-Z]{4}0[A-Z0-9]{6}$"
    return bool(re.match(pattern, ifsc.strip().upper()))


def generate_ifsc() -> str:
    bank = random.choice(IFSC_BANKS)
    suffix = "".join(random.choices("0123456789ABCDEFGHJKLMNPQRSTUVWXYZ", k=6))
    return f"{bank}0{suffix}"


# ==============================================================================
# PHONE, EMAIL, API KEYS, CANARY TOKENS
# ==============================================================================

def generate_indian_phone() -> str:
    first = str(random.choice([6, 7, 8, 9]))
    rest = "".join([str(random.randint(0, 9)) for _ in range(9)])
    return f"+91-{first}{rest[0:4]}-{rest[4:9]}"


def generate_api_key(service: str = "openai") -> str:
    if service == "openai":
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        return "sk-mock-" + "".join(random.choices(chars, k=40))
    elif service == "aws":
        chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        return "AKIA" + "".join(random.choices(chars, k=16))
    elif service == "stripe":
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        return "sk_test_" + "".join(random.choices(chars, k=24))
    return "secret_token_" + "".join(random.choices("0123456789abcdef", k=32))


def generate_canary(prefix: str = "CANARY") -> str:
    """Generates unique canary token for leak benchmarking."""
    unique = "".join(random.choices("ABCDEF0123456789", k=16))
    return f"{prefix}_{unique}"


if __name__ == "__main__":
    print("--- Synthetic Data Smoke Test ---")
    card = generate_credit_card("visa")
    print(f"Visa: {card['number']} (Luhn valid: {validate_luhn(card['number'])})")
    aadhaar = generate_aadhaar()
    print(f"Aadhaar: {aadhaar} (Verhoeff valid: {validate_verhoeff(aadhaar)})")
    pan = generate_pan("P")
    print(f"PAN: {pan} (Valid: {validate_pan(pan)})")
    upi = generate_upi()
    print(f"UPI: {upi} (Valid: {validate_upi(upi)})")
    ifsc = generate_ifsc()
    print(f"IFSC: {ifsc} (Valid: {validate_ifsc(ifsc)})")
    print(f"API Key: {generate_api_key('openai')}")
