"""
SecureStego Decoder Module

Extracts LSB bitstream, parses protocol packet, and decrypts secret information.
"""

import os
import struct
from typing import Dict, Any, Tuple, Union, Optional
import numpy as np
from PIL import Image

from core.crypto import decrypt_data, DecryptionError
from core.integrity import parse_payload_packet, PacketIntegrityError


class DecodingError(Exception):
    """Base exception for decoding failures."""
    pass


class InvalidStegoImageError(DecodingError):
    """Raised when an image does not contain a valid SecureStego payload."""
    pass


class AuthenticationFailureError(DecodingError):
    """Raised when the password is incorrect or payload integrity check fails."""
    pass


def decode_data_from_image(
    stego_image: Union[str, Image.Image],
    password: str,
) -> Dict[str, Any]:
    """
    Extracts, validates, and decrypts hidden data from a stego image.

    Args:
        stego_image: File path or PIL Image object.
        password: User passphrase for AES-GCM decryption.

    Returns:
        Dictionary containing:
            - is_file (bool): True if data is a file, False if text.
            - data (str or bytes): Decrypted text string or binary file bytes.
            - metadata (dict): Metadata (e.g. original filename, extension, mime).
            - payload_size (int): Size of decrypted content in bytes.

    Raises:
        InvalidStegoImageError: If the image has no SecureStego header or corrupted length.
        AuthenticationFailureError: If password is wrong or ciphertext modified.
        DecodingError: Other processing errors.
    """
    if not password:
        raise AuthenticationFailureError("Password cannot be empty.")

    # 1. Load image
    try:
        if isinstance(stego_image, str):
            if not os.path.exists(stego_image):
                raise DecodingError(f"Stego image file not found: {stego_image}")
            img = Image.open(stego_image)
        elif isinstance(stego_image, Image.Image):
            img = stego_image
        else:
            raise DecodingError("Stego image must be a valid file path or PIL Image.")

        img_rgb = img.convert("RGB")
    except Exception as e:
        if isinstance(e, DecodingError):
            raise
        raise DecodingError(f"Failed to load stego image: {str(e)}")

    # 2. Extract LSB stream
    pixels = np.array(img_rgb, dtype=np.uint8)
    flat_pixels = pixels.reshape(-1)
    extracted_lsbs = flat_pixels & 1

    total_available_bits = len(extracted_lsbs)
    if total_available_bits < 32:
        raise InvalidStegoImageError("Image is too small to contain any embedded payload header.")

    # 3. Read 32-bit payload bit-length prefix
    prefix_bits = extracted_lsbs[:32]
    prefix_bytes = np.packbits(prefix_bits).tobytes()
    (payload_bits_count,) = struct.unpack(">I", prefix_bytes)

    # Sanity check bit bounds
    if payload_bits_count <= 0 or (payload_bits_count % 8 != 0):
        raise InvalidStegoImageError("No valid SecureStego payload detected (invalid bit length header).")

    if 32 + payload_bits_count > total_available_bits:
        raise InvalidStegoImageError(
            f"Corrupted or invalid payload length ({payload_bits_count} bits) exceeds total image bits ({total_available_bits})."
        )

    # 4. Extract exact payload bytes
    payload_bits = extracted_lsbs[32 : 32 + payload_bits_count]
    raw_packet_bytes = np.packbits(payload_bits).tobytes()

    # 5. Parse and validate protocol header & magic bytes
    try:
        packet = parse_payload_packet(raw_packet_bytes)
    except PacketIntegrityError as e:
        raise InvalidStegoImageError(f"Payload validation failed: {str(e)}")

    # 6. Decrypt ciphertext using derived key and verify authentication tag
    try:
        decrypted_bytes = decrypt_data(
            ciphertext_with_tag=packet["ciphertext"],
            password=password,
            salt=packet["salt"],
            nonce=packet["nonce"],
        )
    except DecryptionError as e:
        raise AuthenticationFailureError(str(e))

    # 7. Format return output
    is_file = packet["is_file"]
    metadata = packet.get("metadata", {})

    if is_file:
        result_data = decrypted_bytes
    else:
        try:
            result_data = decrypted_bytes.decode("utf-8")
        except UnicodeDecodeError:
            result_data = decrypted_bytes.decode("utf-8", errors="replace")

    return {
        "is_file": is_file,
        "data": result_data,
        "metadata": metadata,
        "payload_size": len(decrypted_bytes),
    }
