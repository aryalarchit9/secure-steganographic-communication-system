from encryption.aes_encrypt import encrypt_message
from encryption.aes_decrypt import decrypt_message
from steganography.embed import embed_message

if __name__ == "__main__":
    message = "Hello Secure World"
    password = "strongpassword123"

    encrypted = encrypt_message(message, password)

    embed_message(
        "test_images/input.png",
        "test_images/output.png",
        encrypted
    )

    print("Message encrypted and embedded successfully!")