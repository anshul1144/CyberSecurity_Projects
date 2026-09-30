"""
Test Suite for SecureStego Decoder & End-to-End Workflow (core/decoder.py)
Covers TC02, TC05, TC06, TC09, TC10.
"""

import io
import pytest
import numpy as np
from PIL import Image

from core.encoder import encode_data_into_image
from core.decoder import (
    decode_data_from_image,
    InvalidStegoImageError,
    AuthenticationFailureError,
    DecodingError,
)
from utils.validators import validate_image, ValidationError


@pytest.fixture
def cover_image():
    """Returns a sample 150x150 RGB PIL Image."""
    data = np.random.randint(40, 220, (150, 150, 3), dtype=np.uint8)
    return Image.fromarray(data, mode="RGB")


def test_tc02_invalid_image_rejected():
    """TC02: Invalid image bytes or corrupt files are rejected."""
    corrupt_bytes = b"NOT_AN_IMAGE_FILE_DATA_CORRUPT"
    with pytest.raises(ValidationError):
        validate_image(corrupt_bytes)


def test_tc05_end_to_end_text_decryption(cover_image):
    """TC05: Encoded text is flawlessly recovered with the correct password."""
    secret_text = "Mission Alpha: Rendezvous at 0400 hours."
    password = "CorrectPassphrase2026!"

    stego_img = encode_data_into_image(cover_image, secret_text, password)
    result = decode_data_from_image(stego_img, password)

    assert result["is_file"] is False
    assert result["data"] == secret_text
    assert result["payload_size"] == len(secret_text.encode("utf-8"))


def test_tc06_wrong_password_rejected(cover_image):
    """TC06: Incorrect password triggers AuthenticationFailureError."""
    secret_text = "Highly Confidential Data"
    password = "CorrectPass123"
    wrong_password = "WrongPass456"

    stego_img = encode_data_into_image(cover_image, secret_text, password)

    with pytest.raises(AuthenticationFailureError):
        decode_data_from_image(stego_img, wrong_password)


def test_tc09_binary_file_hiding(cover_image):
    """TC09: Binary file (e.g. PDF/ZIP/bytes) encoded and recovered byte-for-byte."""
    binary_content = b"\x25\x50\x44\x46\x2d\x31\x2e\x34\x0a\x25\xd0\xd4\xc5\xd8" + b"A" * 200
    password = "BinaryVaultPass#789"
    metadata = {"filename": "confidential_document.pdf", "mime": "application/pdf"}

    stego_img = encode_data_into_image(
        cover_image=cover_image,
        secret_data=binary_content,
        password=password,
        is_file=True,
        metadata=metadata,
    )

    result = decode_data_from_image(stego_img, password)
    assert result["is_file"] is True
    assert result["data"] == binary_content
    assert result["metadata"]["filename"] == "confidential_document.pdf"
    assert result["metadata"]["mime"] == "application/pdf"


def test_tc10_modified_stego_image_detected(cover_image):
    """TC10: If stego image pixels are altered/tampered, extraction or integrity check fails."""
    secret = "IntegrityProtectedPayload"
    password = "IntegrityPass_999"

    stego_img = encode_data_into_image(cover_image, secret, password)

    # Tamper with the image: flip an LSB directly in the embedded payload region
    stego_arr = np.array(stego_img, dtype=np.uint8)
    flat = stego_arr.reshape(-1)
    flat[40] ^= 1  # Flip a bit inside the payload
    tampered_img = Image.fromarray(stego_arr, mode="RGB")

    with pytest.raises((AuthenticationFailureError, InvalidStegoImageError)):
        decode_data_from_image(tampered_img, password)


def test_clean_image_without_payload(cover_image):
    """Decoding an unaltered cover image raises InvalidStegoImageError."""
    with pytest.raises((InvalidStegoImageError, DecodingError)):
        decode_data_from_image(cover_image, "AnyPassword")
