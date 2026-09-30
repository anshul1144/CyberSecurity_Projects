"""
Test Suite for SecureStego Cryptographic Module (core/crypto.py)
Covers TC05, TC06, and cryptographic integrity tests.
"""

import pytest
from core.crypto import (
    derive_key,
    encrypt_data,
    decrypt_data,
    CryptoError,
    DecryptionError,
    KeyDerivationError,
)


def test_tc05_correct_password_decryption():
    """TC05: Correct password successfully decrypts ciphertext."""
    plaintext = b"Classified Cyber Security Mission Intel"
    password = "SuperSecretPassword123!"

    ciphertext, salt, nonce = encrypt_data(plaintext, password)
    assert len(ciphertext) > len(plaintext)  # Ciphertext + 16-byte GCM tag
    assert len(salt) == 16
    assert len(nonce) == 12

    decrypted = decrypt_data(ciphertext, password, salt, nonce)
    assert decrypted == plaintext


def test_tc06_wrong_password_failure():
    """TC06: Wrong password must fail securely with DecryptionError."""
    plaintext = b"Top Secret Payload"
    correct_pass = "CorrectPass123!"
    wrong_pass = "WrongPass999!"

    ciphertext, salt, nonce = encrypt_data(plaintext, correct_pass)

    with pytest.raises(DecryptionError) as exc_info:
        decrypt_data(ciphertext, wrong_pass, salt, nonce)

    assert "Decryption failed" in str(exc_info.value)


def test_tampered_ciphertext_rejection():
    """TC10-crypto: Tampering with ciphertext bits triggers authentication failure."""
    plaintext = b"Sensitive Data"
    password = "SecurePassword"

    ciphertext, salt, nonce = encrypt_data(plaintext, password)

    # Corrupt one byte of ciphertext
    tampered = bytearray(ciphertext)
    tampered[5] ^= 0xFF

    with pytest.raises(DecryptionError):
        decrypt_data(bytes(tampered), password, salt, nonce)


def test_empty_password_rejection():
    """Empty password should raise an error during key derivation."""
    with pytest.raises(CryptoError):
        derive_key("", salt=b"0" * 16)
