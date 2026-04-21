import pytest
import io
from crypto_utils import (
    generate_rsa_keypair, 
    generate_aes_key, 
    encrypt_file_data, 
    decrypt_file_data, 
    wrap_aes_key, 
    unwrap_aes_key, 
    sign_data, 
    verify_signature
)
from reportlab.pdfgen import canvas

from watermark_utils import embed_watermark_text, extract_watermark_text, extract_watermark_from_text_blob

def test_rsa_key_generation():
    priv, pub = generate_rsa_keypair()
    assert priv.startswith(b"-----BEGIN PRIVATE KEY-----")
    assert pub.startswith(b"-----BEGIN PUBLIC KEY-----")

def test_aes_encryption_decryption():
    aes_key = generate_aes_key()
    original_data = b"This is a secret question paper."
    
    encrypted = encrypt_file_data(original_data, aes_key)
    assert encrypted != original_data
    
    decrypted = decrypt_file_data(encrypted, aes_key)
    assert decrypted == original_data

def test_rsa_key_wrapping():
    aes_key = generate_aes_key()
    priv_pem, pub_pem = generate_rsa_keypair()
    
    wrapped = wrap_aes_key(aes_key, pub_pem)
    assert wrapped != aes_key
    
    unwrapped = unwrap_aes_key(wrapped, priv_pem)
    assert unwrapped == aes_key

def test_rsa_signing_verification():
    priv_pem, pub_pem = generate_rsa_keypair()
    data = b"Important encrypted paper blob"
    
    signature = sign_data(data, priv_pem)
    assert verify_signature(data, signature, pub_pem) is True
    
    # Test tamper
    tampered_data = b"tampered paper blob"
    assert verify_signature(tampered_data, signature, pub_pem) is False


def test_text_blob_watermark_detection():
    leaked_text = "The exam paper says CENTER: 7 | CODE: BS1:12:YWJjZA"
    assert extract_watermark_from_text_blob(leaked_text) == "CENTER: 7 | CODE: BS1:12:YWJjZA"


def test_zero_width_obfuscated_watermark_detection():
    leaked_text = "CENTER:\u200b 7 | CODE: BS1:12:YWJjZA"
    assert extract_watermark_from_text_blob(leaked_text) == "CENTER: 7 | CODE: BS1:12:YWJjZA"


def test_pdf_watermark_detection_from_text_layer():
    buffer = io.BytesIO()
    pdf_canvas = canvas.Canvas(buffer)
    pdf_canvas.drawString(100, 750, "Confidential exam paper")
    pdf_canvas.save()

    pdf_bytes = buffer.getvalue()
    watermark_text = "CENTER: 12 | CODE: BS1:8:YWJjaWQ"
    watermarked_bytes = embed_watermark_text(pdf_bytes, watermark_text)

    extracted = extract_watermark_text(watermarked_bytes)
    assert "CENTER: 12" in extracted
    assert "BS1:8:YWJjaWQ" in extracted
