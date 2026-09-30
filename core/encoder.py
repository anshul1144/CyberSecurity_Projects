"""
SecureStego Encoder Module

Handles cryptographic encryption and LSB-based bit embedding into cover images.
"""

import os
import struct
from typing import Dict, Any, Optional, Union
import numpy as np
from PIL import Image

from core.crypto import encrypt_data, CryptoError
from core.integrity import create_payload_packet, PacketIntegrityError
from core.capacity import calculate_image_capacity


class EncodingError(Exception):
    """Base exception for encoding failures."""
    pass


class CapacityExceededError(EncodingError):
    """Raised when the payload exceeds cover image capacity."""
    pass


def encode_data_into_image(
    cover_image: Union[str, Image.Image],
    secret_data: Union[str, bytes],
    password: str,
    is_file: bool = False,
    metadata: Optional[Dict[str, Any]] = None,
) -> Image.Image:
    """
    Encrypts secret text/file and embeds it into the cover image using LSB steganography.

    Args:
        cover_image: File path or PIL Image instance.
        secret_data: String text message or binary file bytes.
        password: User passphrase for encryption.
        is_file: True if embedding a file, False if text.
        metadata: Optional dictionary with file attributes (e.g. filename, mime).

    Returns:
        PIL.Image containing the stego image in lossless RGB format.

    Raises:
        EncodingError: If image loading, encryption, or embedding fails.
        CapacityExceededError: If payload is larger than image capacity.
    """
    if metadata is None:
        metadata = {}

    # 1. Validate inputs
    if not password:
        raise EncodingError("Password cannot be empty.")

    if isinstance(secret_data, str):
        if not secret_data:
            raise EncodingError("Secret message cannot be empty.")
        raw_plaintext = secret_data.encode("utf-8")
    elif isinstance(secret_data, bytes):
        if len(secret_data) == 0:
            raise EncodingError("Secret file content cannot be empty.")
        raw_plaintext = secret_data
    else:
        raise EncodingError("Secret data must be either string or bytes.")

    # 2. Load and validate image
    try:
        if isinstance(cover_image, str):
            if not os.path.exists(cover_image):
                raise EncodingError(f"Cover image file not found: {cover_image}")
            img = Image.open(cover_image)
        elif isinstance(cover_image, Image.Image):
            img = cover_image
        else:
            raise EncodingError("Cover image must be a valid file path or PIL Image.")

        # Ensure image is in RGB mode
        img_rgb = img.convert("RGB")
    except Exception as e:
        if isinstance(e, EncodingError):
            raise
        raise EncodingError(f"Failed to load cover image: {str(e)}")

    width, height = img_rgb.size
    pixels = np.array(img_rgb, dtype=np.uint8)

    # 3. Encrypt payload
    try:
        ciphertext, salt, nonce = encrypt_data(raw_plaintext, password)
    except CryptoError as e:
        raise EncodingError(f"Encryption failed: {str(e)}")

    # 4. Create structured packet
    try:
        packet = create_payload_packet(
            ciphertext=ciphertext,
            salt=salt,
            nonce=nonce,
            is_file=is_file,
            metadata=metadata,
        )
    except PacketIntegrityError as e:
        raise EncodingError(f"Packet assembly failed: {str(e)}")

    # 5. Convert packet to bitstream with a 32-bit total length prefix
    payload_bits_count = len(packet) * 8
    length_prefix_bytes = struct.pack(">I", payload_bits_count)
    full_payload = length_prefix_bytes + packet

    # Total bits: 32 bits length prefix + payload bits
    bits_to_embed = np.unpackbits(np.frombuffer(full_payload, dtype=np.uint8))
    total_bits_needed = len(bits_to_embed)

    # 6. Check capacity
    flat_pixels = pixels.reshape(-1)
    available_bits = len(flat_pixels)

    if total_bits_needed > available_bits:
        raise CapacityExceededError(
            f"Image capacity exceeded. Needs {total_bits_needed // 8:,} bytes, "
            f"but image can only hold {available_bits // 8:,} bytes."
        )

    # 7. Perform Vectorized LSB embedding
    # Clear LSB with & 0xFE (254), then bitwise OR with target bit
    target_bits = bits_to_embed.astype(np.uint8)
    flat_pixels[:total_bits_needed] = (flat_pixels[:total_bits_needed] & np.uint8(0xFE)) | target_bits

    # 8. Reconstruct PIL Image
    stego_array = flat_pixels.reshape(pixels.shape)
    stego_image = Image.fromarray(stego_array, mode="RGB")

    return stego_image


def save_stego_image(stego_image: Image.Image, output_path: str) -> str:
    """
    Saves the stego image as a lossless PNG to preserve LSB data.

    Args:
        stego_image: PIL Image instance.
        output_path: Target path for output PNG.

    Returns:
        Absolute path to saved stego image.
    """
    base, ext = os.path.splitext(output_path)
    if ext.lower() != ".png":
        output_path = f"{base}.png"

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    stego_image.save(output_path, format="PNG")
    return os.path.abspath(output_path)
