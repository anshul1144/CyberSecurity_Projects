"""
SecureStego Cryptographic Module

Implements industry-standard cryptography adhering to OWASP recommendations:
- Key Derivation: PBKDF2-HMAC-SHA256 with 200,000 iterations and 16-byte random salt.
- Authenticated Encryption: AES-256-GCM with 12-byte random nonce and 16-byte authentication tag.
- Integrity verification: Automatic authentication tag validation to detect wrong passwords or tampering.
"""

import os
from typing import Tuple, Optional
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


class CryptoError(Exception):
    """Base exception for cryptographic operations."""
    pass


class DecryptionError(CryptoError):
    """Raised when decryption fails due to invalid password or tampered ciphertext."""
    pass


class KeyDerivationError(CryptoError):
    """Raised when key derivation parameters are invalid."""
    pass


PBKDF2_ITERATIONS = 200_000
SALT_SIZE_BYTES = 16
NONCE_SIZE_BYTES = 12
KEY_SIZE_BYTES = 32  # 256 bits for AES-256


def derive_key(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    """
    Derives a 256-bit AES key from a passphrase and salt using PBKDF2-HMAC-SHA256.

    Args:
        password: User-provided secret passphrase.
        salt: Cryptographically random 16-byte salt.
        iterations: Number of PBKDF2 iterations (default 200,000).

    Returns:
        32-byte derived cryptographic key.
    """
    if not password:
        raise KeyDerivationError("Password cannot be empty.")
    if len(salt) != SALT_SIZE_BYTES:
        raise KeyDerivationError(f"Salt must be exactly {SALT_SIZE_BYTES} bytes, got {len(salt)}.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE_BYTES,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_data(
    plaintext: bytes,
    password: str,
    associated_data: Optional[bytes] = None,
    salt: Optional[bytes] = None,
    nonce: Optional[bytes] = None,
) -> Tuple[bytes, bytes, bytes]:
    """
    Encrypts plaintext bytes using AES-256-GCM authenticated encryption.

    Args:
        plaintext: Raw data bytes to encrypt.
        password: Secret passphrase.
        associated_data: Optional authenticated data (AEAD).
        salt: Optional pre-generated 16-byte salt (generated randomly if None).
        nonce: Optional pre-generated 12-byte nonce (generated randomly if None).

    Returns:
        Tuple of (ciphertext_with_tag, salt, nonce).
        Note: AESGCM in cryptography package appends the 16-byte authentication tag to ciphertext.
    """
    if salt is None:
        salt = os.urandom(SALT_SIZE_BYTES)
    if nonce is None:
        nonce = os.urandom(NONCE_SIZE_BYTES)

    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data)

    return ciphertext_with_tag, salt, nonce


def decrypt_data(
    ciphertext_with_tag: bytes,
    password: str,
    salt: bytes,
    nonce: bytes,
    associated_data: Optional[bytes] = None,
) -> bytes:
    """
    Decrypts AES-256-GCM ciphertext and validates authentication tag.

    Args:
        ciphertext_with_tag: Encrypted payload containing ciphertext and 16-byte tag.
        password: User passphrase used for decryption.
        salt: 16-byte salt used during encryption.
        nonce: 12-byte nonce used during encryption.
        associated_data: Optional authenticated data verified against tag.

    Returns:
        Decrypted original plaintext bytes.

    Raises:
        DecryptionError: If the password is incorrect or data was modified/tampered.
    """
    if not password:
        raise DecryptionError("Password cannot be empty.")
    if len(salt) != SALT_SIZE_BYTES or len(nonce) != NONCE_SIZE_BYTES:
        raise DecryptionError("Invalid salt or nonce length.")

    try:
        key = derive_key(password, salt)
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)
        return plaintext
    except InvalidTag:
        raise DecryptionError("Decryption failed: Incorrect password or corrupted/tampered payload.")
    except Exception as e:
        raise DecryptionError(f"Decryption error: {str(e)}")
