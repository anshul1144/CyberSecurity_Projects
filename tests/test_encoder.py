"""
Test Suite for SecureStego Encoder Module (core/encoder.py)
Covers TC01, TC03, TC04, TC07, TC08.
"""

import pytest
import numpy as np
from PIL import Image
from core.encoder import encode_data_into_image, EncodingError, CapacityExceededError
from core.capacity import calculate_image_capacity, check_capacity_feasibility


@pytest.fixture
def sample_cover_image():
    """Generates a synthetic 200x200 RGB image for testing."""
    arr = np.random.randint(50, 200, (200, 200, 3), dtype=np.uint8)
    return Image.fromarray(arr, mode="RGB")


def test_tc01_tc03_valid_png_and_small_message(sample_cover_image):
    """TC01 & TC03: Valid PNG accepted, small message successfully encoded."""
    message = "Hello, SecureStego World!"
    password = "MasterPassword2026"

    stego_img = encode_data_into_image(
        cover_image=sample_cover_image,
        secret_data=message,
        password=password,
    )

    assert isinstance(stego_img, Image.Image)
    assert stego_img.size == sample_cover_image.size
    assert stego_img.mode == "RGB"


def test_tc07_empty_message_validation_error(sample_cover_image):
    """TC07: Empty message causes validation failure."""
    with pytest.raises(EncodingError) as exc:
        encode_data_into_image(sample_cover_image, "", "Password123")
    assert "cannot be empty" in str(exc.value).lower()


def test_tc08_unicode_text_support(sample_cover_image):
    """TC08: Unicode and multi-language characters supported."""
    unicode_message = "🔒 SecureStego: Привет мир! 秘密のメッセージ 🚀 123 !@#$%^&*()"
    password = "UnicodePassword🔑"

    stego_img = encode_data_into_image(
        cover_image=sample_cover_image,
        secret_data=unicode_message,
        password=password,
    )
    assert isinstance(stego_img, Image.Image)


def test_tc04_oversized_message_capacity_error():
    """TC04: Oversized payload exceeding image capacity is rejected."""
    # Tiny 10x10 image: 100 pixels * 3 channels = 300 bits ≈ 37 bytes capacity
    tiny_img = Image.fromarray(np.zeros((10, 10, 3), dtype=np.uint8), mode="RGB")
    large_payload = "A" * 1000  # 1000 bytes, far exceeds 37 bytes

    with pytest.raises(CapacityExceededError):
        encode_data_into_image(tiny_img, large_payload, "Pass123")


def test_capacity_feasibility_check():
    """Validates theoretical capacity calculation logic."""
    cap = calculate_image_capacity(100, 100, 3)
    # 10,000 pixels * 3 channels = 30,000 bits = 3,750 bytes
    assert cap["theoretical_capacity_bytes"] == 3750
    assert cap["usable_capacity_bytes"] > 3600

    feasible, msg, info = check_capacity_feasibility((100, 100, 3), 500)
    assert feasible is True
    assert "Capacity utilization" in msg
