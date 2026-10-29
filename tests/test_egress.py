"""
Unit test for PrivacyLens Fail-Closed Egress Gateway.
Tests:
1. Clean sanitized payloads pass seamlessly.
2. Raw secrets trigger immediate block.
3. Canaries trigger immediate block.
4. Fail-closed behavior on exceptions.
"""

import pytest
from privacylens.gateway.egress import EgressGateway, EgressBlockedException
from privacylens.gateway.canary import CanaryManager
from privacylens.sanitize.vault import LocalSecretVault


def test_egress_clean_payload():
    vault = LocalSecretVault()
    vault.clear()
    canary_mgr = CanaryManager()

    # Register token in vault
    card_token = vault.allocate_token("CARD", "4532015012345678")

    gateway = EgressGateway(vault=vault, canary_manager=canary_mgr, fail_closed=True)

    # Outgoing payload containing ONLY safe tokens
    clean_payload = {
        "action": "type",
        "element_id": "pl-3",
        "value": card_token
    }

    result = gateway.inspect_and_filter(clean_payload)
    assert result["passed"] is True
    assert len(result["leaks"]) == 0


def test_egress_blocks_raw_secret():
    vault = LocalSecretVault()
    vault.clear()
    canary_mgr = CanaryManager()

    # Raw secret stored in vault
    raw_card = "4532015012345678"
    vault.allocate_token("CARD", raw_card)

    gateway = EgressGateway(vault=vault, canary_manager=canary_mgr, fail_closed=True)

    # Leak simulated: raw secret included in outgoing message
    leaking_payload = {
        "action": "type",
        "element_id": "pl-3",
        "value": raw_card
    }

    with pytest.raises(EgressBlockedException) as excinfo:
        gateway.inspect_and_filter(leaking_payload)

    assert "data leak violations" in str(excinfo.value)
    assert len(excinfo.value.violations) > 0


def test_egress_blocks_canary():
    vault = LocalSecretVault()
    vault.clear()
    canary_mgr = CanaryManager()

    canary = canary_mgr.generate_canary("TEST")
    gateway = EgressGateway(vault=vault, canary_manager=canary_mgr, fail_closed=True)

    payload_with_canary = {
        "action": "report",
        "data": f"Exfiltrated payload with {canary}"
    }

    with pytest.raises(EgressBlockedException):
        gateway.inspect_and_filter(payload_with_canary)
