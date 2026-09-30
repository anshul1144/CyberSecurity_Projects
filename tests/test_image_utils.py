"""
Test Suite for Steganalysis & Image Metrics (utils/image_utils.py)
"""

import numpy as np
from PIL import Image
from utils.image_utils import (
    compute_psnr,
    compute_ssim,
    compute_entropy,
    analyze_lsb_distribution,
    extract_lsb_plane,
)
from core.encoder import encode_data_into_image


def test_psnr_and_ssim_identical_images():
    """Identical images must have infinite PSNR and 1.0 SSIM."""
    arr = np.random.randint(50, 200, (100, 100, 3), dtype=np.uint8)
    img = Image.fromarray(arr, mode="RGB")

    assert compute_psnr(img, img) == float("inf")
    assert round(compute_ssim(img, img), 4) == 1.0000


def test_stego_image_psnr_and_ssim():
    """Embedding a secret message should yield very high PSNR (>50dB) and SSIM (>0.999)."""
    arr = np.random.randint(50, 200, (200, 200, 3), dtype=np.uint8)
    cover_img = Image.fromarray(arr, mode="RGB")

    stego_img = encode_data_into_image(cover_img, "Secret Steganography Verification Message", "Pass1234!")

    psnr = compute_psnr(cover_img, stego_img)
    ssim = compute_ssim(cover_img, stego_img)

    assert psnr > 50.0  # Typically > 60 dB for small payloads
    assert ssim > 0.999


def test_entropy_and_lsb_plane():
    """Verifies entropy calculation and LSB plane visualizer."""
    arr = np.random.randint(50, 200, (100, 100, 3), dtype=np.uint8)
    img = Image.fromarray(arr, mode="RGB")

    entropy = compute_entropy(img)
    assert "Red" in entropy
    assert "Average" in entropy
    assert 0 < entropy["Average"] <= 8.0

    lsb_plane = extract_lsb_plane(img)
    assert isinstance(lsb_plane, Image.Image)
    assert lsb_plane.size == img.size


def test_lsb_distribution():
    """Verifies LSB distribution statistics."""
    arr = np.random.randint(50, 200, (100, 100, 3), dtype=np.uint8)
    img = Image.fromarray(arr, mode="RGB")

    stats = analyze_lsb_distribution(img)
    assert stats["total_bits"] == 100 * 100 * 3
    assert 0 <= stats["lsb_ones_ratio_pct"] <= 100
