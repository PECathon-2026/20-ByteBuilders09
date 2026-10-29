"""
Unit tests for PrivacyLens In-Memory Vault.
Verifies:
1. Tokens are consistent across calls for the same secret.
2. Distinct secrets receive unique tokens.
3. Vault resolves tokens back to real secrets.
4. Vault purge/clear functions properly.
"""

import pytest
from privacylens.sanitize.vault import LocalSecretVault


def test_vault_allocation_and_consistency():
    vault = LocalSecretVault()
    vault.clear()

    raw_card = "4532015012345678"
    token1 = vault.allocate_token("CARD", raw_card)
    assert token1 == "[CARD_1]"

    # Requesting token for identical secret returns the same token
    token2 = vault.allocate_token("CARD", raw_card)
    assert token2 == "[CARD_1]"

    # Different secret gets sequential token
    raw_card2 = "4000123456789010"
    token3 = vault.allocate_token("CARD", raw_card2)
    assert token3 == "[CARD_2]"

    # Resolve token back to real secret
    assert vault.get_real_value("[CARD_1]") == raw_card
    assert vault.get_real_value("[CARD_2]") == raw_card2
    assert vault.get_real_value("[CARD_999]") is None


def test_vault_clear():
    vault = LocalSecretVault()
    vault.allocate_token("PASSWORD", "Secret123!")
    assert len(vault.get_all_raw_secrets()) > 0

    vault.clear()
    assert len(vault.get_all_raw_secrets()) == 0
    assert vault.get_real_value("[PASSWORD_1]") is None
