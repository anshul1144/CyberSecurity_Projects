# SecureStego Architecture

## 1. System Overview
SecureStego is a cybersecurity-oriented steganography and steganalysis platform. It integrates modern cryptographic algorithms with Least Significant Bit (LSB) steganography to conceal confidential data (text or binary files) within lossless digital images.

```
┌─────────────────────────────────────────────────────────────┐
│                         USER INTERFACE                      │
│                    (Streamlit Web Dashboard)                │
└──────────────────────────────┬──────────────────────────────┘
                               │
       ┌───────────────────────┼───────────────────────┐
       │                       │                       │
       ▼                       ▼                       ▼
┌──────────────┐       ┌──────────────┐       ┌─────────────────┐
│ ENCODE ENGINE│       │ DECODE ENGINE│       │ STEGANALYSIS    │
│  (core/      │       │  (core/      │       │  (utils/        │
│   encoder.py)│       │   decoder.py)│       │   image_utils)  │
└──────┬───────┘       └──────┬───────┘       └────────┬────────┘
       │                      │                        │
       ▼                      ▼                        ▼
┌──────────────┐       ┌──────────────┐       ┌─────────────────┐
│ CRYPTO LAYER │       │ INTEGRITY    │       │ CAPACITY ENGINE │
│ AES-256-GCM  │       │ Verification │       │ Bit Budgeting   │
│ PBKDF2-SHA256│       │ Magic + Tags │       │ Utilization %   │
└──────────────┘       └──────────────┘       └─────────────────┘
```

---

## 2. Component Breakdown

### 2.1 Core Modules (`core/`)
- **`crypto.py`**:
  - Implements PBKDF2-HMAC-SHA256 for key derivation (200,000 iterations, 16-byte random salt).
  - Implements AES-256-GCM authenticated encryption/decryption with a 12-byte random nonce.
  - Automatically verifies the 16-byte authentication tag during decryption.
- **`integrity.py`**:
  - Encapsulates payload binary formatting, serialization, and parsing.
  - Formats headers: Magic bytes (`SSTG`), version byte, file flag, salt, nonce, metadata length, and ciphertext length.
- **`capacity.py`**:
  - Computes theoretical image capacity $(W \times H \times 3) / 8$.
  - Deducts protocol overhead to give exact usable capacity.
  - Evaluates payload feasibility and capacity utilization percentages.
- **`encoder.py`**:
  - Converts cover image to RGB numpy array.
  - Encrypts and packs secret payload.
  - Modifies LSB bits using vectorized bitwise masking.
  - Exports lossless PNG.
- **`decoder.py`**:
  - Extracts 32-bit length prefix and full payload bitstream from LSBs.
  - Validates magic bytes, unpacks metadata, and verifies the AES-GCM authentication tag.

### 2.2 Utility Modules (`utils/`)
- **`image_utils.py`**:
  - PSNR (Peak Signal-to-Noise Ratio) in dB.
  - SSIM (Structural Similarity Index) using local uniform filtering.
  - Shannon Entropy (randomness in bits/pixel).
  - LSB Distribution and Chi-Square PoV (Pairs of Values) steganalysis.
  - Amplified LSB Bit-Plane extraction.
  - RGB Channel Histograms.
- **`validators.py`**:
  - Input image format and integrity verification.
  - Password strength guidance and sanity checks.
  - Directory-traversal-safe filename sanitization.

---

## 3. Payload Protocol Structure

| Field | Size | Data Type | Description |
| :--- | :--- | :--- | :--- |
| `BIT_LEN` | 4 Bytes | Unsigned Int (`>I`) | Total bits in payload stream |
| `MAGIC` | 4 Bytes | Bytes (`b"SSTG"`) | Identifies SecureStego protocol |
| `VERSION` | 1 Byte | Unsigned Char (`B`) | Payload format version (0x01) |
| `FILE_FLAG`| 1 Byte | Unsigned Char (`B`) | 0 = Text Message, 1 = Binary File |
| `SALT` | 16 Bytes | Raw Bytes | PBKDF2 salt for key derivation |
| `NONCE` | 12 Bytes | Raw Bytes | AES-GCM IV/Nonce |
| `META_LEN`| 2 Bytes | Unsigned Short (`>H`)| Length of metadata JSON bytes |
| `METADATA`| N Bytes | UTF-8 JSON | Filename, MIME type, original size |
| `DATA_LEN`| 4 Bytes | Unsigned Int (`>I`) | Length of ciphertext + GCM tag |
| `CIPHERTEXT`| M Bytes | Raw Bytes | AES-256-GCM ciphertext + 16-byte tag |
