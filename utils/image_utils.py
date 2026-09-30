"""
SecureStego Image Quality & Steganalysis Utilities

Provides metrics and visual tools for evaluating steganographic impact:
- PSNR (Peak Signal-to-Noise Ratio)
- SSIM (Structural Similarity Index)
- Shannon Entropy
- LSB Distribution & Chi-Square Steganalysis indicator
- LSB Visual Bit-Plane Extraction
- RGB Channel Histograms
"""

import math
from typing import Dict, Any, Tuple, Union, Optional
import numpy as np
from PIL import Image
from scipy.ndimage import uniform_filter


def compute_psnr(image1: Union[Image.Image, np.ndarray], image2: Union[Image.Image, np.ndarray]) -> float:
    """
    Calculates Peak Signal-to-Noise Ratio (PSNR) in decibels (dB) between two images.
    Higher is better (>40 dB is generally considered imperceptible to human eye).

    Args:
        image1: Original cover image (PIL Image or uint8 array).
        image2: Stego image (PIL Image or uint8 array).

    Returns:
        PSNR value in dB, or infinity if identical.
    """
    arr1 = np.array(image1, dtype=np.float64)
    arr2 = np.array(image2, dtype=np.float64)

    if arr1.shape != arr2.shape:
        raise ValueError(f"Image shapes must match: {arr1.shape} vs {arr2.shape}")

    mse = np.mean((arr1 - arr2) ** 2)
    if mse == 0:
        return float("inf")

    max_pixel = 255.0
    psnr = 10.0 * np.log10((max_pixel ** 2) / mse)
    return float(psnr)


def compute_ssim(
    image1: Union[Image.Image, np.ndarray],
    image2: Union[Image.Image, np.ndarray],
    window_size: int = 11,
) -> float:
    """
    Calculates Mean Structural Similarity Index (SSIM) between two images.
    Ranges from -1 to 1 (1.0 means identical structure, luminance, and contrast).

    Args:
        image1: Original cover image.
        image2: Stego image.
        window_size: Size of sliding local window (default 11).

    Returns:
        SSIM index between -1.0 and 1.0.
    """
    arr1 = np.array(image1, dtype=np.float64)
    arr2 = np.array(image2, dtype=np.float64)

    if arr1.shape != arr2.shape:
        raise ValueError(f"Image shapes must match: {arr1.shape} vs {arr2.shape}")

    k1, k2 = 0.01, 0.03
    L = 255.0
    c1 = (k1 * L) ** 2
    c2 = (k2 * L) ** 2

    # If RGB, calculate SSIM per channel and average
    if arr1.ndim == 3:
        ssims = []
        for ch in range(arr1.shape[2]):
            ssims.append(_ssim_channel(arr1[:, :, ch], arr2[:, :, ch], window_size, c1, c2))
        return float(np.mean(ssims))
    else:
        return float(_ssim_channel(arr1, arr2, window_size, c1, c2))


def _ssim_channel(x: np.ndarray, y: np.ndarray, window_size: int, c1: float, c2: float) -> float:
    """Computes SSIM for a single channel using a uniform local filter."""
    mu_x = uniform_filter(x, size=window_size)
    mu_y = uniform_filter(y, size=window_size)

    mu_x_sq = mu_x * mu_x
    mu_y_sq = mu_y * mu_y
    mu_xy = mu_x * mu_y

    sigma_x_sq = uniform_filter(x * x, size=window_size) - mu_x_sq
    sigma_y_sq = uniform_filter(y * y, size=window_size) - mu_y_sq
    sigma_xy = uniform_filter(x * y, size=window_size) - mu_xy

    numerator = (2 * mu_xy + c1) * (2 * sigma_xy + c2)
    denominator = (mu_x_sq + mu_y_sq + c1) * (sigma_x_sq + sigma_y_sq + c2)
    ssim_map = numerator / denominator
    return float(np.mean(ssim_map))


def compute_entropy(image: Union[Image.Image, np.ndarray]) -> Dict[str, float]:
    """
    Calculates Shannon Entropy (randomness) of image channels.
    Theoretical maximum for 8-bit image is 8.0 bits per pixel.

    Args:
        image: PIL Image or array.

    Returns:
        Dict of entropy for R, G, B channels and overall average.
    """
    arr = np.array(image, dtype=np.uint8)
    if arr.ndim == 2:
        arr = np.expand_dims(arr, axis=2)

    entropies = {}
    channel_names = ["Red", "Green", "Blue"] if arr.shape[2] == 3 else [f"Ch_{i}" for i in range(arr.shape[2])]

    total = 0.0
    for i, name in enumerate(channel_names):
        channel = arr[:, :, i]
        hist, _ = np.histogram(channel, bins=256, range=(0, 256), density=True)
        # Filter out 0 probabilities
        hist = hist[hist > 0]
        h = -np.sum(hist * np.log2(hist))
        entropies[name] = float(round(h, 4))
        total += h

    entropies["Average"] = float(round(total / len(channel_names), 4))
    return entropies


def analyze_lsb_distribution(image: Union[Image.Image, np.ndarray]) -> Dict[str, Any]:
    """
    Performs steganalysis on LSB distribution:
    - Counts proportion of 0s vs 1s in LSB.
    - Estimates chi-square statistic across Pairs of Values (PoVs).

    Args:
        image: PIL Image or array.

    Returns:
        Dict of LSB statistical indicators.
    """
    arr = np.array(image, dtype=np.uint8)
    flat = arr.flatten()
    lsbs = flat & 1

    ones_count = int(np.sum(lsbs))
    zeros_count = len(lsbs) - ones_count
    ones_ratio = (ones_count / len(lsbs)) * 100.0

    # Chi-Square PoV (Pairs of Values) test
    # Natural images tend to have uneven counts between 2k and 2k+1,
    # whereas LSB substitution equalizes their frequencies.
    hist, _ = np.histogram(flat, bins=256, range=(0, 256))
    even_counts = hist[0::2].astype(np.float64)
    odd_counts = hist[1::2].astype(np.float64)
    pair_sums = even_counts + odd_counts
    valid_pairs = pair_sums > 0

    diffs = (even_counts[valid_pairs] - odd_counts[valid_pairs]) ** 2
    chi2 = np.sum(diffs / (2.0 * pair_sums[valid_pairs]))

    # Anomaly indicator: Encrypted payload has near 50% ones ratio
    anomaly_level = "Low Anomaly (Natural Image)"
    if abs(ones_ratio - 50.0) < 0.2:
        anomaly_level = "Medium/High (Possible high-entropy payload embedded)"

    return {
        "total_bits": len(lsbs),
        "lsb_ones_count": ones_count,
        "lsb_zeros_count": zeros_count,
        "lsb_ones_ratio_pct": round(ones_ratio, 3),
        "chi_square_stat": round(float(chi2), 2),
        "anomaly_level": anomaly_level,
    }


def extract_lsb_plane(image: Union[Image.Image, np.ndarray]) -> Image.Image:
    """
    Extracts the least significant bit plane and scales it to 0 or 255 for visualization.

    Args:
        image: PIL Image or array.

    Returns:
        PIL Image visual plane showing LSB distribution.
    """
    arr = np.array(image, dtype=np.uint8)
    lsb_plane = (arr & 1) * 255
    return Image.fromarray(lsb_plane.astype(np.uint8))


def generate_histogram_figure(
    image1: Union[Image.Image, np.ndarray],
    image2: Optional[Union[Image.Image, np.ndarray]] = None,
    title1: str = "Original Cover Image",
    title2: str = "Stego Image",
):
    """
    Generates a matplotlib Figure comparing RGB histograms.

    Args:
        image1: Primary image.
        image2: Optional second image to compare against.
        title1: Title for primary image histogram.
        title2: Title for second image histogram.

    Returns:
        matplotlib.figure.Figure object.
    """
    import matplotlib.pyplot as plt

    arr1 = np.array(image1, dtype=np.uint8)
    cols = 2 if image2 is not None else 1

    fig, axes = plt.subplots(1, cols, figsize=(7 * cols, 4), dpi=120)
    if cols == 1:
        axes = [axes]

    colors = ("red", "green", "blue")
    channel_labels = ("R", "G", "B")

    # Plot Image 1
    for i, color in enumerate(colors):
        hist, _ = np.histogram(arr1[:, :, i], bins=256, range=(0, 256))
        axes[0].plot(hist, color=color, alpha=0.8, label=f"Channel {channel_labels[i]}")
    axes[0].set_title(title1, fontsize=12, fontweight="bold", pad=10)
    axes[0].set_xlabel("Pixel Intensity (0-255)")
    axes[0].set_ylabel("Pixel Frequency")
    axes[0].grid(True, linestyle="--", alpha=0.4)
    axes[0].legend(loc="upper right")

    # Plot Image 2 if provided
    if image2 is not None:
        arr2 = np.array(image2, dtype=np.uint8)
        for i, color in enumerate(colors):
            hist, _ = np.histogram(arr2[:, :, i], bins=256, range=(0, 256))
            axes[1].plot(hist, color=color, alpha=0.8, label=f"Channel {channel_labels[i]}")
        axes[1].set_title(title2, fontsize=12, fontweight="bold", pad=10)
        axes[1].set_xlabel("Pixel Intensity (0-255)")
        axes[1].set_ylabel("Pixel Frequency")
        axes[1].grid(True, linestyle="--", alpha=0.4)
        axes[1].legend(loc="upper right")

    fig.tight_layout()
    return fig

