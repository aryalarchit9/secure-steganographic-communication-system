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
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def decrypt_message(encrypted_data: str, password: str) -> str:
    """
    Decrypts base64 encoded data containing salt + IV + ciphertext.
    Returns the original plaintext message.
    """
    backend = default_backend()

    decoded_data = base64.b64decode(encrypted_data.encode())

    salt = decoded_data[:16]
    iv = decoded_data[16:32]
    ciphertext = decoded_data[32:]

    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    decryptor = cipher.decryptor()

    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext.decode()