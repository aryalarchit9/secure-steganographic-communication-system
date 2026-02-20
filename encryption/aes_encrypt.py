import os
import base64
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derives a 256-bit AES key from a password using PBKDF2.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def encrypt_message(message: str, password: str) -> str:
    """
    Encrypts a message using AES-256 in CBC mode.
    Returns base64 encoded string containing salt + IV + ciphertext.
    """
    backend = default_backend()

    # Generate random salt
    salt = os.urandom(16)

    # Derive key
    key = derive_key(password, salt)

    # Generate random IV
    iv = os.urandom(16)

    # Pad message to 128-bit block size
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(message.encode()) + padder.finalize()

    # Create AES cipher
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()

    # Encrypt
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Combine salt + IV + ciphertext
    encrypted_data = base64.b64encode(salt + iv + ciphertext).decode()

    return encrypted_data