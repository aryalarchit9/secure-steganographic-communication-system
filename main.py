from encryption.aes_encrypt import encrypt_message
from encryption.aes_decrypt import decrypt_message

if __name__ == "__main__":
    message = "Hello Secure World"
    password = "strongpassword123"

    encrypted = encrypt_message(message, password)
    print("Encrypted:", encrypted)

    decrypted = decrypt_message(encrypted, password)
    print("Decrypted:", decrypted)