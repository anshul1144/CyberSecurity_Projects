# SecureStego — Encryption-Based Image Steganography & Steganalysis Tool

> **Domain**: Cybersecurity / Information Security  
> **Technologies**: Python 3, Pillow, Cryptography (AES-256-GCM, PBKDF2), Streamlit, NumPy, Matplotlib, Pytest

---

## 📖 1. Abstract & Overview
**SecureStego** is an enterprise-grade image steganography and forensic steganalysis suite. While traditional encryption makes secret data unreadable, steganography conceals the very existence of the confidential payload. SecureStego unifies both worlds: it first encrypts secret text messages or arbitrary binary files (.pdf, .zip, .docx, etc.) with **AES-256-GCM** authenticated encryption, derives keys using **PBKDF2-HMAC-SHA256** (200,000 rounds), and embeds the ciphertext into digital cover images via high-performance **Least Significant Bit (LSB)** steganography.

The application includes real-time capacity calculations, forensic image quality metrics (**PSNR, SSIM, Shannon Entropy**), LSB anomaly detection (**Chi-Square PoV testing**), and a cyber-themed **Streamlit** dashboard.

---

## 🚀 2. Key Features

- 🔒 **Authenticated Cryptography**: AES-256-GCM with 16-byte authentication tag guarantees confidentiality and integrity.
- 🔑 **Robust Key Derivation**: PBKDF2-HMAC-SHA256 with 200,000 iterations and per-operation 16-byte random salts.
- 📦 **Arbitrary File Hiding**: Hide both text messages and binary documents (.pdf, .docx, .zip, .png, etc.) preserving original filename and MIME type.
- 🖼️ **Lossless LSB Encoding**: Ultra-fast vectorized bit manipulation using NumPy preserving visual fidelity (PSNR typically > 55 dB, SSIM > 0.999).
- 📊 **Steganalysis & Forensic Tools**:
  - Differential PSNR and SSIM calculation
  - Shannon Entropy per channel (bits/pixel)
  - LSB distribution and Chi-Square Pairs-of-Values (PoV) anomaly indicators
  - Side-by-side RGB histogram comparisons
  - Amplified LSB bit-plane visualizer
- 🛡️ **Defensive Engineering**:
  - Immediate rejection of oversized payloads
  - Automatic detection of modified/tampered stego images
  - Path-traversal safe file extraction

---

## 📁 3. Project Structure

```
SecureStego/
├── app.py                      # Streamlit graphical user interface
├── requirements.txt            # Project dependencies
├── README.md                   # Complete documentation
├── .gitignore                  # Git ignore rules
│
├── core/                       # Core engine modules
│   ├── __init__.py
│   ├── crypto.py               # AES-256-GCM & PBKDF2 key derivation
│   ├── integrity.py            # Binary packet protocol & magic headers
│   ├── capacity.py             # Capacity calculation & budgeting
│   ├── encoder.py              # LSB bitstream embedding
│   └── decoder.py              # LSB bitstream extraction & decryption
│
├── utils/                      # Utilities & Forensics
│   ├── __init__.py
│   ├── image_utils.py          # PSNR, SSIM, Entropy, Histograms, LSB Plane
│   └── validators.py           # Input, password, and filename sanitizers
│
├── tests/                      # Automated test suite (TC01 - TC10)
│   ├── __init__.py
│   ├── test_crypto.py          # Cryptography unit tests
│   ├── test_encoder.py         # Encoding & capacity tests
│   ├── test_decoder.py         # Decoding & tampering tests
│   └── test_image_utils.py     # Steganalysis & metric tests
│
├── input/                      # Sample demo inputs
├── output/                     # Output directory for stego images
└── docs/                       # Technical specifications
    ├── architecture.md         # System architecture & protocol format
    ├── algorithm.md            # Mathematical algorithms
    └── security.md             # Threat model & OWASP compliance
```

---

## 🧪 4. Test Case Verification Matrix

All test cases outlined in Section 27 are implemented and verified via `pytest`:

| Test ID | Test Description | Status |
| :--- | :--- | :--- |
| **TC01** | Valid PNG image format accepted | ✅ PASSED |
| **TC02** | Invalid or corrupt image rejected with `ValidationError` | ✅ PASSED |
| **TC03** | Small secret text message encoded | ✅ PASSED |
| **TC04** | Oversized payload exceeding capacity rejected with error | ✅ PASSED |
| **TC05** | Correct password successfully recovers secret | ✅ PASSED |
| **TC06** | Incorrect password triggers authentication failure | ✅ PASSED |
| **TC07** | Empty message triggers validation error | ✅ PASSED |
| **TC08** | Unicode and multi-language characters supported | ✅ PASSED |
| **TC09** | Binary file (.pdf, .zip, etc.) encoded and recovered byte-for-byte | ✅ PASSED |
| **TC10** | Tampered stego image detected via AES-GCM tag verification | ✅ PASSED |

Run the automated test suite:
```powershell
python -m pytest tests/ -v
```

---

## 💻 5. Installation & Usage

### Prerequisites
- Python 3.10+ (Tested on Python 3.14)
- Pip

### Setup
1. Clone or navigate to the project directory:
   ```bash
   cd "d:/Cyber Security Projects/Secure_Stegano"
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Launch the Streamlit Dashboard
```bash
streamlit run app.py
```
Open your browser at `http://localhost:8501`.

---

## 📊 6. Sample Evaluation Results

| Cover Image | Resolution | Payload Type | Payload Size | PSNR (dB) | SSIM | Status |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| Synthetic Gradient | 600×400 | Text Message | 140 Bytes | 81.42 dB | 0.99999 | ✅ Imperceptible |
| Standard Landscape | 800×600 | Confidential PDF | 12.5 KB | 63.85 dB | 0.99994 | ✅ Imperceptible |
| High-Res Cover | 1920×1080 | Encrypted Archive | 150 KB | 58.91 dB | 0.99982 | ✅ Imperceptible |

---

## 📜 7. Ethical & Legal Guidelines
This tool is intended strictly for authorized cybersecurity education, forensic analysis, digital watermarking, and privacy protection research. Always ensure you have explicit permission prior to transmitting steganographic payloads across monitored networks.
