# SecureStego Security Considerations & Threat Model

## 1. Cryptographic Principles & Standards Compliance
SecureStego strictly adheres to the OWASP Cryptographic Storage and Key Management recommendations:
- **No Custom Cryptography**: Uses certified primitives from the `cryptography` library (`hazmat.primitives.ciphers.aead.AESGCM`).
- **Key Derivation Function (KDF)**: Uses PBKDF2-HMAC-SHA256 with 200,000 iterations to resist GPU-based dictionary and brute-force attacks.
- **Unique Salt**: Every encoding process generates a fresh, cryptographically secure 16-byte random salt (`os.urandom(16)`), preventing rainbow table attacks.
- **Unique Nonce/IV**: Every encryption uses a fresh 12-byte random nonce (`os.urandom(12)`), preventing replay attacks and keystream reuse.
- **Authenticated Encryption (AEAD)**: AES-256-GCM produces a 128-bit (16-byte) authentication tag that protects both ciphertext and packet integrity.

---

## 2. Threat Analysis

| Threat Vector | Potential Impact | Mitigation in SecureStego |
| :--- | :--- | :--- |
| **Tampering / Bit-flipping** | Malicious alteration of hidden payload | AES-GCM authentication tag verification rejects any altered payload with `AuthenticationFailureError`. |
| **Brute-force Passphrase** | Offline key recovery | 200,000 PBKDF2 iterations make each password attempt computationally expensive. |
| **Unauthorized Extraction** | Adversary extracts LSBs without key | Ciphertext is indistinguishable from random noise; no information is leaked without the key. |
| **Path Traversal Attack** | Hidden file metadata contains malicious paths (e.g. `../../etc/passwd`) | `sanitize_filename` strips directory paths and allows only alphanumeric and safe characters. |
| **Lossy Compression Damage** | Saving as JPEG strips LSBs | System strictly enforces lossless PNG output format. |

---

## 3. Steganographic Limitations & Steganalysis

1. **LSB Detectability**:
   - Because encrypted ciphertext has near-maximum entropy, embedding a large payload causes the LSB plane to shift toward an exact 50.0% ratio of 0s and 1s.
   - Advanced steganalysis tools (e.g., Chi-Square analysis, Sample Pairs analysis) can detect high embedding ratios.
2. **Robustness**:
   - LSB steganography is fragile. Image resizing, cropping, color space transformation, or re-compression will destroy the payload.
   - For tamper resistance, images should be transferred in bit-exact PNG format.
