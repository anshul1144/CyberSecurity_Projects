# SecureStego Algorithms

## 1. Encoding Algorithm (Encryption + LSB Embedding)

```text
Input: Cover Image (I), Secret Data (D), Passphrase (P), IsFile (bool)
Output: Stego Image (S) in Lossless PNG

1. Load Image I and convert to RGB matrix of size [H, W, 3].
2. Generate 16-byte random Salt (S) and 12-byte random Nonce (N).
3. Derive 256-bit Key K = PBKDF2-HMAC-SHA256(P, S, iterations=200,000).
4. Encrypt D using AES-256-GCM(K, N, D) -> Ciphertext C (including 16-byte tag).
5. Assemble protocol packet:
   Packet = MAGIC(b'SSTG') || VERSION(1) || FLAG || S || N || META_LEN || META || DATA_LEN || C.
6. Compute Payload Bits:
   Bitstream = 32_BIT_LENGTH_PREFIX(len(Packet)*8) || UNPACK_BITS(Packet).
7. Total Available Image Bits = H * W * 3.
8. If len(Bitstream) > Available Bits:
   Raise CapacityExceededError.
9. For index i in [0 ... len(Bitstream) - 1]:
   Pixel[i] = (Pixel[i] & 0xFE) | Bitstream[i]
10. Reshape modified pixels to [H, W, 3] and save as PNG.
```

---

## 2. Decoding Algorithm (LSB Extraction + Authenticated Decryption)

```text
Input: Stego Image (S), Passphrase (P)
Output: Recovered Secret Data (D), Metadata (M)

1. Load Image S and convert to RGB array.
2. Flatten pixels into 1D array of 8-bit unsigned integers.
3. Extract LSBs: LSB_Array = Flat_Pixels & 1.
4. Read first 32 bits and unpack into Big-Endian unsigned integer:
   Payload_Bits_Count = UNPACK(">I", PACK_BITS(LSB_Array[0:32]))
5. Validate bounds:
   If Payload_Bits_Count <= 0 or (32 + Payload_Bits_Count > len(LSB_Array)):
       Raise InvalidStegoImageError.
6. Extract Payload Bits = LSB_Array[32 : 32 + Payload_Bits_Count].
7. Convert to bytes: Raw_Packet = PACK_BITS(Payload_Bits).
8. Parse Header:
   - Check MAGIC == b"SSTG"
   - Check VERSION == 1
   - Extract FLAG, SALT (16B), NONCE (12B), METADATA, CIPHERTEXT.
9. Derive 256-bit Key K = PBKDF2-HMAC-SHA256(P, SALT, iterations=200,000).
10. Decrypt and Authenticate via AES-256-GCM(K, NONCE, CIPHERTEXT):
    - If GCM tag check fails: Raise AuthenticationFailureError (Wrong password or tampered image).
11. Return decrypted text or binary file with sanitized metadata.
```

---

## 3. Mathematical Quality & Steganalysis Metrics

### Peak Signal-to-Noise Ratio (PSNR)
$$\text{MSE} = \frac{1}{3 \cdot W \cdot H} \sum_{x=0}^{W-1} \sum_{y=0}^{H-1} \sum_{c=0}^{2} \left[I_{cover}(x, y, c) - I_{stego}(x, y, c)\right]^2$$
$$\text{PSNR} = 10 \cdot \log_{10}\left(\frac{255^2}{\text{MSE}}\right)$$

### Structural Similarity Index (SSIM)
$$\text{SSIM}(x, y) = \frac{(2\mu_x\mu_y + c_1)(2\sigma_{xy} + c_2)}{(\mu_x^2 + \mu_y^2 + c_1)(\sigma_x^2 + \sigma_y^2 + c_2)}$$

### Shannon Entropy
$$H = -\sum_{k=0}^{255} P(k) \log_2 P(k)$$
