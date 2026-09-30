"""
SecureStego Validators Module

Validates user inputs, uploaded image files, payload integrity, and passwords.
"""

import os
import re
from typing import Union, Tuple, Optional
from PIL import Image


class ValidationError(Exception):
    """Raised when input validation fails."""
    pass


ALLOWED_IMAGE_FORMATS = {"PNG", "JPEG", "JPG", "BMP", "WEBP"}


def validate_image(image_input: Union[str, bytes, Image.Image]) -> Image.Image:
    """
    Validates that the input is a valid image readable by Pillow.

    Args:
        image_input: File path, raw bytes, or PIL Image.

    Returns:
        Verified PIL Image in RGB format.

    Raises:
        ValidationError: If the image cannot be read or is invalid.
    """
    try:
        if isinstance(image_input, Image.Image):
            img = image_input
        elif isinstance(image_input, str):
            if not os.path.isfile(image_input):
                raise ValidationError(f"File not found: {image_input}")
            img = Image.open(image_input)
        elif isinstance(image_input, (bytes, bytearray)):
            import io
            img = Image.open(io.BytesIO(image_input))
        else:
            raise ValidationError("Unsupported image input type.")

        img.verify()  # Verify image header and integrity

        # Reopen after verify() because Pillow docs state verify closes file pointer
        if isinstance(image_input, str):
            img = Image.open(image_input)
        elif isinstance(image_input, (bytes, bytearray)):
            import io
            img = Image.open(io.BytesIO(image_input))

        # Convert to RGB mode
        return img.convert("RGB")
    except Exception as e:
        if isinstance(e, ValidationError):
            raise
        raise ValidationError(f"Invalid or corrupted image: {str(e)}")


def validate_password(password: str) -> Tuple[bool, Optional[str]]:
    """
    Validates password and provides security feedback.

    Args:
        password: User-provided passphrase.

    Returns:
        Tuple (is_valid, warning_message)

    Raises:
        ValidationError: If password is empty.
    """
    if not password or not password.strip():
        raise ValidationError("Password cannot be empty.")

    warning = None
    if len(password) < 8:
        warning = "Password is short (< 8 characters). For strong security, use 12+ characters with mixed case and numbers."

    return True, warning


def sanitize_filename(filename: str, default: str = "extracted_file.bin") -> str:
    """
    Sanitizes filename extracted from stego metadata to prevent directory traversal.

    Args:
        filename: Untrusted filename from metadata.
        default: Fallback filename if empty or invalid.

    Returns:
        Safe base filename string.
    """
    if not filename:
        return default
    # Remove any directory components
    clean = os.path.basename(filename)
    # Strip any dangerous characters
    clean = re.sub(r'[^a-zA-Z0-9_.-]', '_', clean)
    return clean if clean else default
