"""
SecureStego — Authenticated Image Steganography and Steganalysis Platform
Streamlit Web Interface
"""

import io
import os
import time
import streamlit as st
import numpy as np
from PIL import Image

from core.encoder import encode_data_into_image, EncodingError, CapacityExceededError
from core.decoder import (
    decode_data_from_image,
    InvalidStegoImageError,
    AuthenticationFailureError,
    DecodingError,
)
from core.capacity import calculate_image_capacity, check_capacity_feasibility
from utils.image_utils import (
    compute_psnr,
    compute_ssim,
    compute_entropy,
    analyze_lsb_distribution,
    extract_lsb_plane,
    generate_histogram_figure,
)
from utils.validators import validate_image, validate_password, sanitize_filename

# --- Page Configuration ---
st.set_page_config(
    page_title="SecureStego — Image Steganography & Steganalysis",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# --- Custom Cyber Dark CSS ---
st.markdown(
    """
    <style>
    /* Main container background */
    .stApp {
        background-color: #0b0f19;
        color: #e2e8f0;
    }
    
    /* Header Styling */
    .hero-title {
        font-size: 2.3rem;
        font-weight: 800;
        background: linear-gradient(90deg, #00f2fe 0%, #4facfe 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 0.2rem;
    }
    .hero-subtitle {
        font-size: 1.05rem;
        color: #94a3b8;
        margin-bottom: 1.5rem;
    }

    /* Glassmorphism Cards */
    .stCard {
        background: rgba(17, 24, 39, 0.7);
        border: 1px solid rgba(56, 189, 248, 0.2);
        border-radius: 12px;
        padding: 1.25rem;
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
        margin-bottom: 1rem;
    }

    /* Metric Badges */
    .metric-chip {
        display: inline-block;
        padding: 0.25rem 0.6rem;
        border-radius: 6px;
        font-size: 0.85rem;
        font-weight: 600;
        margin-right: 0.5rem;
    }
    .metric-success {
        background: rgba(16, 185, 129, 0.15);
        color: #10b981;
        border: 1px solid #10b981;
    }
    .metric-info {
        background: rgba(14, 165, 233, 0.15);
        color: #38bdf8;
        border: 1px solid #38bdf8;
    }
    .metric-warning {
        background: rgba(245, 158, 11, 0.15);
        color: #f59e0b;
        border: 1px solid #f59e0b;
    }

    /* Streamlit tabs styling */
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        height: 48px;
        white-space: pre-wrap;
        background-color: rgba(30, 41, 59, 0.6);
        border-radius: 8px;
        color: #cbd5e1;
        font-weight: 600;
        padding: 0 20px;
    }
    .stTabs [aria-selected="true"] {
        background-color: rgba(14, 165, 233, 0.2) !important;
        border: 1px solid #38bdf8 !important;
        color: #38bdf8 !important;
    }
    /* Completely hide sidebar and collapse button */
    [data-testid="stSidebar"],
    [data-testid="stSidebarCollapsedControl"],
    section[data-testid="stSidebar"] {
        display: none !important;
    }
    </style>
    """,
    unsafe_allow_html=True,
)

# --- Main App Header ---
st.markdown('<div class="hero-title">SecureStego: Encryption-Based Steganography</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="hero-subtitle">Conceal secret messages or binary files into digital images with authenticated encryption & comprehensive steganalysis.</div>',
    unsafe_allow_html=True,
)

# --- System Overview & Quick Demo Assets ---
with st.expander("🛡️ System Architecture & Quick Demo Files", expanded=False):
    col_spec, col_demo = st.columns([3, 2], gap="large")
    with col_spec:
        st.markdown(
            """
            **Cryptographic & Steganographic Specifications:**
            - **Cipher:** AES-256-GCM (AEAD with 16-byte authentication tag)
            - **KDF:** PBKDF2-HMAC-SHA256 (200,000 iterations)
            - **Salt & Nonce:** 16-byte random salt, 12-byte random nonce per operation
            - **Embedding:** 1-Bit LSB Embedding into Lossless PNG
            """
        )
    with col_demo:
        st.markdown("**Sample Assets:**")
        sample_img_path = os.path.join("input", "sample_cover.png")
        sample_txt_path = os.path.join("input", "secret_document.txt")

        btn_col1, btn_col2 = st.columns(2)
        if os.path.exists(sample_img_path):
            with open(sample_img_path, "rb") as f:
                btn_col1.download_button(
                    label="📥 Demo Cover",
                    data=f.read(),
                    file_name="sample_cover.png",
                    mime="image/png",
                    use_container_width=True,
                )
        if os.path.exists(sample_txt_path):
            with open(sample_txt_path, "rb") as f:
                btn_col2.download_button(
                    label="📥 Demo Secret",
                    data=f.read(),
                    file_name="secret_document.txt",
                    mime="text/plain",
                    use_container_width=True,
                )

tab_encode, tab_decode, tab_analyze = st.tabs(
    ["🔒 1. Encode & Conceal", "🔓 2. Extract & Decrypt", "📊 3. Steganalysis & Metrics"]
)

# ==============================================================================
# TAB 1: ENCODE & CONCEAL
# ==============================================================================
with tab_encode:
    st.markdown("### 🔒 Embed Secret Payload into Cover Image")

    col1, col2 = st.columns([1, 1], gap="large")

    with col1:
        st.markdown("#### Step 1: Select Cover Image")
        cover_file = st.file_uploader(
            "Upload Cover Image (PNG, JPG, BMP)",
            type=["png", "jpg", "jpeg", "bmp"],
            key="cover_uploader",
        )

        cover_img = None
        if cover_file:
            try:
                cover_img = validate_image(cover_file.getvalue())
                w, h = cover_img.size
                cap = calculate_image_capacity(w, h, channels=3)

                st.image(cover_img, caption=f"Cover Image ({w}×{h} px)", use_container_width=True)

                st.markdown(
                    f"""
                    <div style="background: rgba(30, 41, 59, 0.7); padding: 10px; border-radius: 8px; border: 1px solid #334155;">
                        <span class="metric-chip metric-info">Dimensions: {w} × {h}</span>
                        <span class="metric-chip metric-success">Usable Capacity: {cap['usable_capacity_bytes']:,} Bytes ({cap['usable_capacity_bytes']/1024:.1f} KB)</span>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            except Exception as e:
                st.error(f"Error validating image: {str(e)}")
                cover_img = None

    with col2:
        st.markdown("#### Step 2: Secret Payload & Password")

        payload_mode = st.radio(
            "Payload Type",
            ["Secret Text Message", "Secret Binary File"],
            horizontal=True,
        )

        secret_data = None
        is_file_mode = False
        meta_dict = {}
        payload_bytes_len = 0

        if payload_mode == "Secret Text Message":
            is_file_mode = False
            secret_text = st.text_area(
                "Secret Message",
                placeholder="Enter confidential message here...",
                height=140,
            )
            if secret_text:
                secret_data = secret_text
                payload_bytes_len = len(secret_text.encode("utf-8"))
                st.caption(f"Payload Size: {payload_bytes_len} bytes ({len(secret_text)} characters)")
        else:
            is_file_mode = True
            secret_upload = st.file_uploader(
                "Upload Secret File (.txt, .pdf, .docx, .zip, .png, etc.)",
                type=None,
                key="secret_file_uploader",
            )
            if secret_upload:
                secret_data = secret_upload.getvalue()
                payload_bytes_len = len(secret_data)
                meta_dict = {
                    "filename": secret_upload.name,
                    "mime": secret_upload.type or "application/octet-stream",
                    "size": payload_bytes_len,
                }
                st.caption(f"Selected File: `{secret_upload.name}` ({payload_bytes_len:,} bytes)")

        password = st.text_input(
            "Encryption Passphrase",
            type="password",
            placeholder="Enter strong encryption passphrase...",
            key="encode_password",
        )

        # Real-time capacity utilization bar
        if cover_img and payload_bytes_len > 0:
            feasible, cap_msg, cap_info = check_capacity_feasibility(
                cover_img.size[::-1] + (3,), payload_bytes_len, metadata_size_bytes=len(str(meta_dict))
            )
            if feasible:
                util = cap_info.get("utilization_percent", 0.0)
                st.progress(min(1.0, util / 100.0), text=f"Capacity Usage: {util:.2f}%")
            else:
                st.error(f"⚠️ {cap_msg}")

        st.markdown("<br>", unsafe_allow_html=True)
        encode_btn = st.button("🔐 Encrypt & Embed into Stego Image", type="primary", use_container_width=True)

        if encode_btn:
            if not cover_img:
                st.error("Please upload a valid cover image first.")
            elif not secret_data:
                st.error("Please provide secret text or a secret file to hide.")
            elif not password:
                st.error("Please provide an encryption passphrase.")
            else:
                try:
                    with st.spinner("Encrypting with AES-256-GCM and embedding LSBs..."):
                        start_time = time.time()
                        stego_img = encode_data_into_image(
                            cover_image=cover_img,
                            secret_data=secret_data,
                            password=password,
                            is_file=is_file_mode,
                            metadata=meta_dict,
                        )
                        elapsed = time.time() - start_time

                    # Compute image metrics
                    psnr_val = compute_psnr(cover_img, stego_img)
                    ssim_val = compute_ssim(cover_img, stego_img)

                    st.success(f"✅ Stego Image successfully generated in {elapsed:.3f} seconds!")

                    # Show comparison preview
                    buf = io.BytesIO()
                    stego_img.save(buf, format="PNG")
                    stego_bytes = buf.getvalue()

                    st.markdown(
                        f"""
                        <div class="stCard">
                            <span class="metric-chip metric-success">PSNR: {psnr_val:.2f} dB</span>
                            <span class="metric-chip metric-info">SSIM: {ssim_val:.5f}</span>
                            <span class="metric-chip metric-warning">Payload: {payload_bytes_len:,} bytes</span>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

                    st.download_button(
                        label="💾 Download Stego Image (Lossless PNG)",
                        data=stego_bytes,
                        file_name="secure_stego_image.png",
                        mime="image/png",
                        use_container_width=True,
                    )

                except CapacityExceededError as ce:
                    st.error(f"❌ Capacity Exceeded: {str(ce)}")
                except Exception as e:
                    st.error(f"❌ Encoding Failed: {str(e)}")

# ==============================================================================
# TAB 2: DECODE & DECRYPT
# ==============================================================================
with tab_decode:
    st.markdown("### 🔓 Extract & Authenticate Secret Payload")

    d_col1, d_col2 = st.columns([1, 1], gap="large")

    with d_col1:
        st.markdown("#### Step 1: Upload Stego Image")
        stego_file = st.file_uploader(
            "Upload Stego Image (PNG)",
            type=["png"],
            key="stego_uploader",
        )

        stego_input_img = None
        if stego_file:
            try:
                stego_input_img = validate_image(stego_file.getvalue())
                w, h = stego_input_img.size
                st.image(stego_input_img, caption=f"Uploaded Stego Image ({w}×{h} px)", use_container_width=True)
            except Exception as e:
                st.error(f"Invalid image file: {str(e)}")
                stego_input_img = None

    with d_col2:
        st.markdown("#### Step 2: Provide Decryption Passphrase")
        decode_pass = st.text_input(
            "Enter Secret Passphrase",
            type="password",
            placeholder="Passphrase used during encoding...",
            key="decode_password",
        )

        st.markdown("<br>", unsafe_allow_html=True)
        decode_btn = st.button("🔓 Extract & Decrypt", type="primary", use_container_width=True)

        if decode_btn:
            if not stego_input_img:
                st.error("Please upload a stego image.")
            elif not decode_pass:
                st.error("Please enter the decryption passphrase.")
            else:
                try:
                    with st.spinner("Extracting bitstream and validating AES-256-GCM authentication tag..."):
                        start_time = time.time()
                        result = decode_data_from_image(stego_input_img, decode_pass)
                        elapsed = time.time() - start_time

                    st.success(f"✅ Authentication Verified! Payload recovered in {elapsed:.3f}s")

                    if not result["is_file"]:
                        st.markdown("#### 📜 Decrypted Secret Message:")
                        st.text_area("Secret Text", value=result["data"], height=160, disabled=True)
                        st.download_button(
                            label="📥 Download Extracted Text",
                            data=result["data"].encode("utf-8"),
                            file_name="decrypted_message.txt",
                            mime="text/plain",
                            use_container_width=True,
                        )
                    else:
                        meta = result.get("metadata", {})
                        raw_filename = meta.get("filename", "extracted_payload.bin")
                        safe_filename = sanitize_filename(raw_filename)
                        mime_type = meta.get("mime", "application/octet-stream")

                        st.markdown("#### 📦 Decrypted File Details:")
                        st.markdown(
                            f"""
                            <div class="stCard">
                                <div><b>Filename:</b> <code>{safe_filename}</code></div>
                                <div><b>Type:</b> {mime_type}</div>
                                <div><b>Size:</b> {result['payload_size']:,} bytes</div>
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )

                        st.download_button(
                            label=f"📥 Download '{safe_filename}'",
                            data=result["data"],
                            file_name=safe_filename,
                            mime=mime_type,
                            use_container_width=True,
                        )

                except AuthenticationFailureError:
                    st.error(
                        "❌ Decryption Failed: Authentication tag mismatch! "
                        "Either the password is incorrect or the image pixels have been altered."
                    )
                except InvalidStegoImageError as ise:
                    st.error(f"❌ Invalid Stego Image: {str(ise)}")
                except Exception as e:
                    st.error(f"❌ Decoding Error: {str(e)}")

# ==============================================================================
# TAB 3: STEGANALYSIS & IMAGE METRICS
# ==============================================================================
with tab_analyze:
    st.markdown("### 📊 Forensic Steganalysis & Image Quality Evaluation")

    ana_mode = st.radio(
        "Analysis Mode",
        ["Compare Cover vs. Stego Image", "Single Image Statistical Inspection"],
        horizontal=True,
    )

    if ana_mode == "Compare Cover vs. Stego Image":
        c_col1, c_col2 = st.columns(2)
        with c_col1:
            cover_ana_file = st.file_uploader("Upload Original Cover Image", type=["png", "jpg", "bmp"], key="ana_cover")
        with c_col2:
            stego_ana_file = st.file_uploader("Upload Stego Image", type=["png", "jpg", "bmp"], key="ana_stego")

        if cover_ana_file and stego_ana_file:
            try:
                img_cover = validate_image(cover_ana_file.getvalue())
                img_stego = validate_image(stego_ana_file.getvalue())

                if img_cover.size != img_stego.size:
                    st.error("Images must have identical dimensions for differential comparison.")
                else:
                    psnr = compute_psnr(img_cover, img_stego)
                    ssim = compute_ssim(img_cover, img_stego)
                    ent_cover = compute_entropy(img_cover)
                    ent_stego = compute_entropy(img_stego)
                    lsb_stats = analyze_lsb_distribution(img_stego)

                    st.markdown("#### 📈 Differential Metrics")
                    m1, m2, m3, m4 = st.columns(4)
                    m1.metric("PSNR (dB)", f"{psnr:.2f} dB" if psnr != float("inf") else "∞ (Identical)")
                    m2.metric("SSIM Index", f"{ssim:.5f}")
                    m3.metric("Cover Entropy", f"{ent_cover['Average']:.3f} b/px")
                    m4.metric("Stego Entropy", f"{ent_stego['Average']:.3f} b/px")

                    st.markdown("---")
                    st.markdown("#### 🔬 LSB Bit-Plane Forensic Visualizer")
                    v_col1, v_col2 = st.columns(2)
                    with v_col1:
                        st.image(extract_lsb_plane(img_cover), caption="Cover LSB Plane (Amplified)", use_container_width=True)
                    with v_col2:
                        st.image(extract_lsb_plane(img_stego), caption="Stego LSB Plane (Amplified)", use_container_width=True)

                    st.markdown("---")
                    st.markdown("#### 📊 RGB Channel Histograms")
                    fig = generate_histogram_figure(img_cover, img_stego, "Original Cover Histogram", "Stego Image Histogram")
                    st.pyplot(fig)

            except Exception as e:
                st.error(f"Analysis error: {str(e)}")

    else:
        single_file = st.file_uploader("Upload Image to Inspect", type=["png", "jpg", "bmp"], key="single_ana")
        if single_file:
            try:
                img = validate_image(single_file.getvalue())
                w, h = img.size
                ent = compute_entropy(img)
                lsb_stats = analyze_lsb_distribution(img)

                st.markdown("#### 🔍 Image Statistics")
                s1, s2, s3 = st.columns(3)
                s1.metric("Resolution", f"{w} × {h} px")
                s2.metric("Mean Shannon Entropy", f"{ent['Average']:.3f} b/px")
                s3.metric("LSB 1-Bit Ratio", f"{lsb_stats['lsb_ones_ratio_pct']:.2f}%")

                st.markdown(
                    f"""
                    <div class="stCard">
                        <b>LSB Anomaly Assessment:</b> <code>{lsb_stats['anomaly_level']}</code><br>
                        <b>Chi-Square PoV Metric:</b> <code>{lsb_stats['chi_square_stat']}</code><br>
                        <i>Note: Natural uncompressed images usually deviate slightly from 50% ones in the LSB plane. High-entropy encryption pulls the ratio close to 50.0%.</i>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                st.markdown("#### 🔬 LSB Plane & Channel Histogram")
                p_col1, p_col2 = st.columns(2)
                with p_col1:
                    st.image(extract_lsb_plane(img), caption="Extracted LSB Bit-Plane", use_container_width=True)
                with p_col2:
                    fig = generate_histogram_figure(img, title1=f"RGB Histogram ({w}x{h})")
                    st.pyplot(fig)

            except Exception as e:
                st.error(f"Error inspecting image: {str(e)}")
