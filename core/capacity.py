"""
SecureStego Capacity Calculation Module

Calculates theoretical and usable data capacity for cover images,
accounting for cryptographic and packaging overheads.
"""

from typing import Dict, Any, Tuple
from core.integrity import FIXED_HEADER_SIZE

# Prefix bits to encode the total payload bit-length: 32 bits (4 bytes)
BITSTREAM_PREFIX_BYTES = 4
AES_GCM_TAG_BYTES = 16
CIPHERTEXT_LEN_PREFIX_BYTES = 4
MINIMUM_PROTOCOL_OVERHEAD = (
    BITSTREAM_PREFIX_BYTES + FIXED_HEADER_SIZE + CIPHERTEXT_LEN_PREFIX_BYTES + AES_GCM_TAG_BYTES
)


def calculate_image_capacity(width: int, height: int, channels: int = 3) -> Dict[str, Any]:
    """
    Computes theoretical and usable payload capacities for given image dimensions.

    Args:
        width: Image width in pixels.
        height: Image height in pixels.
        channels: Number of color channels (default 3 for RGB).

    Returns:
        Dictionary containing:
            - total_pixels: Total pixel count.
            - total_bits: Theoretical bit capacity.
            - theoretical_capacity_bytes: Raw byte capacity.
            - protocol_overhead_bytes: Base protocol overhead.
            - usable_capacity_bytes: Maximum secret payload bytes that can be safely embedded.
    """
    total_pixels = width * height
    total_bits = total_pixels * channels
    raw_capacity_bytes = total_bits // 8

    usable_capacity_bytes = max(0, raw_capacity_bytes - MINIMUM_PROTOCOL_OVERHEAD)

    return {
        "width": width,
        "height": height,
        "channels": channels,
        "total_pixels": total_pixels,
        "total_bits": total_bits,
        "theoretical_capacity_bytes": raw_capacity_bytes,
        "protocol_overhead_bytes": MINIMUM_PROTOCOL_OVERHEAD,
        "usable_capacity_bytes": usable_capacity_bytes,
    }


def check_capacity_feasibility(
    image_shape: Tuple[int, ...],
    payload_size_bytes: int,
    metadata_size_bytes: int = 0,
) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Checks if a secret payload can fit within the cover image.

    Args:
        image_shape: (height, width, channels) or (height, width).
        payload_size_bytes: Size of secret plaintext or file in bytes.
        metadata_size_bytes: Size of metadata JSON in bytes.

    Returns:
        Tuple of (is_feasible, message, stats_dict).
    """
    if len(image_shape) == 2:
        height, width = image_shape
        channels = 1
    else:
        height, width, channels = image_shape[:3]

    cap_info = calculate_image_capacity(width, height, channels)
    usable_bytes = cap_info["usable_capacity_bytes"] - metadata_size_bytes

    if usable_bytes <= 0:
        return False, "Image is too small to embed any SecureStego payload.", cap_info

    if payload_size_bytes > usable_bytes:
        msg = (
            f"Payload size ({payload_size_bytes:,} bytes) exceeds available "
            f"usable capacity ({usable_bytes:,} bytes)."
        )
        return False, msg, cap_info

    utilization_pct = (
        ((payload_size_bytes + MINIMUM_PROTOCOL_OVERHEAD + metadata_size_bytes) / cap_info["theoretical_capacity_bytes"])
        * 100.0
    )
    cap_info["utilization_percent"] = round(utilization_pct, 2)
    cap_info["payload_size_bytes"] = payload_size_bytes

    return True, f"Payload fits! Capacity utilization: {utilization_pct:.2f}%.", cap_info
