import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def generate_rsa_keypair():
    """Generates a 2048-bit RSA keypair. Returns (private_pem, public_pem)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem

def generate_aes_key():
    """Generates a 256-bit (32 byte) AES key."""
    return AESGCM.generate_key(bit_length=256)

def encrypt_file_data(data: bytes, aes_key: bytes) -> bytes:
    """Encrypts data using AES-256 GCM. Returns nonce + ciphertext."""
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext

def decrypt_file_data(encrypted_data: bytes, aes_key: bytes) -> bytes:
    """Decrypts data using AES-256 GCM. Input should be nonce + ciphertext."""
    aesgcm = AESGCM(aes_key)
    nonce = encrypted_data[:12]
    ciphertext = encrypted_data[12:]
    return aesgcm.decrypt(nonce, ciphertext, None)

def wrap_aes_key(aes_key: bytes, public_key_pem: bytes) -> bytes:
    """Wraps (encrypts) the AES key using an RSA public key."""
    public_key = serialization.load_pem_public_key(public_key_pem)
    wrapped_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return wrapped_key

def unwrap_aes_key(wrapped_key: bytes, private_key_pem: bytes) -> bytes:
    """Unwraps (decrypts) the AES key using an RSA private key."""
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    aes_key = private_key.decrypt(
        wrapped_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key

def sign_data(data: bytes, private_key_pem: bytes) -> bytes:
    """Signs data (the encrypted paper file) using RSA-PSS and SHA256."""
    private_key = serialization.load_pem_private_key(private_key_pem, password=None)
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(data: bytes, signature: bytes, public_key_pem: bytes) -> bool:
    """Verifies the signature of the data using the public key."""
    public_key = serialization.load_pem_public_key(public_key_pem)
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False
