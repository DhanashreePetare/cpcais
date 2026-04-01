import pytest
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
