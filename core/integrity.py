"""
SecureStego Integrity & Protocol Packaging Module

Defines the binary payload structure, header validation, and serialization.
Binary Payload Specification:
  [4 Bytes: MAGIC 'SSTG']
  [1 Byte:  VERSION (0x01)]
  [1 Byte:  FILE_FLAG (0x00: Text, 0x01: File)]
  [16 Bytes: SALT (PBKDF2)]
  [12 Bytes: NONCE (AES-GCM)]
  [2 Bytes: METADATA_LEN (unsigned short, big-endian)]
  [N Bytes: METADATA (JSON encoded UTF-8)]
  [4 Bytes: CIPHERTEXT_LEN (unsigned int, big-endian)]
  [M Bytes: CIPHERTEXT_WITH_TAG (AES-GCM encrypted payload)]
"""

import json
import struct
from typing import Dict, Any, Tuple

MAGIC_BYTES = b"SSTG"
CURRENT_VERSION = 1
FLAG_TEXT = 0
FLAG_FILE = 1

# Header fixed prefix size: 4 (magic) + 1 (version) + 1 (flag) + 16 (salt) + 12 (nonce) + 2 (meta_len) = 36 bytes
FIXED_HEADER_SIZE = 4 + 1 + 1 + 16 + 12 + 2


class PacketIntegrityError(Exception):
    """Raised when payload structure or magic header validation fails."""
    pass


def create_payload_packet(
    ciphertext: bytes,
    salt: bytes,
    nonce: bytes,
    is_file: bool = False,
    metadata: Dict[str, Any] = None,
) -> bytes:
    """
    Serializes encrypted payload and cryptographic parameters into a standard SecureStego packet.

    Args:
        ciphertext: Encrypted data including AES-GCM 16-byte authentication tag.
        salt: 16-byte PBKDF2 salt.
        nonce: 12-byte AES-GCM nonce.
        is_file: True if embedding a binary file, False if plain text message.
        metadata: Dictionary containing file name, size, type, etc.

    Returns:
        Structured binary bytes packet.
    """
    if metadata is None:
        metadata = {}

    meta_bytes = json.dumps(metadata).encode("utf-8")
    meta_len = len(meta_bytes)
    if meta_len > 65535:
        raise PacketIntegrityError("Metadata exceeds maximum allowed size (64KB).")

    file_flag = FLAG_FILE if is_file else FLAG_TEXT
    ciphertext_len = len(ciphertext)

    # Format: 4s (magic), B (version), B (flag), 16s (salt), 12s (nonce), H (meta_len)
    header = struct.pack(
        ">4sBB16s12sH",
        MAGIC_BYTES,
        CURRENT_VERSION,
        file_flag,
        salt,
        nonce,
        meta_len,
    )

    packet = header + meta_bytes + struct.pack(">I", ciphertext_len) + ciphertext
    return packet


def parse_payload_packet(raw_bytes: bytes) -> Dict[str, Any]:
    """
    Parses and validates a raw byte stream into structured packet components.

    Args:
        raw_bytes: Byte buffer extracted from stego image.

    Returns:
        Dict containing version, is_file, salt, nonce, metadata, ciphertext.

    Raises:
        PacketIntegrityError: If magic bytes do not match or stream is corrupted.
    """
    if len(raw_bytes) < FIXED_HEADER_SIZE + 4:
        raise PacketIntegrityError("Incomplete payload: data is smaller than minimum header size.")

    magic, version, flag, salt, nonce, meta_len = struct.unpack_from(
        ">4sBB16s12sH", raw_bytes, 0
    )

    if magic != MAGIC_BYTES:
        raise PacketIntegrityError(
            f"Invalid Magic Header: Expected {MAGIC_BYTES!r}, found {magic!r}. No SecureStego payload detected."
        )

    if version != CURRENT_VERSION:
        raise PacketIntegrityError(
            f"Unsupported payload version: {version}. Expected version {CURRENT_VERSION}."
        )

    offset = FIXED_HEADER_SIZE
    if len(raw_bytes) < offset + meta_len + 4:
        raise PacketIntegrityError("Malformed payload: metadata truncated.")

    meta_bytes = raw_bytes[offset : offset + meta_len]
    offset += meta_len

    try:
        metadata = json.loads(meta_bytes.decode("utf-8")) if meta_len > 0 else {}
    except Exception as e:
        raise PacketIntegrityError(f"Failed to parse payload metadata JSON: {str(e)}")

    (ciphertext_len,) = struct.unpack_from(">I", raw_bytes, offset)
    offset += 4

    ciphertext = raw_bytes[offset : offset + ciphertext_len]
    if len(ciphertext) != ciphertext_len:
        raise PacketIntegrityError(
            f"Corrupt payload: expected {ciphertext_len} ciphertext bytes, got {len(ciphertext)}."
        )

    return {
        "version": version,
        "is_file": (flag == FLAG_FILE),
        "salt": salt,
        "nonce": nonce,
        "metadata": metadata,
        "ciphertext": ciphertext,
    }
