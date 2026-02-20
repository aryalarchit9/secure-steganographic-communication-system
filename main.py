from encryption.aes_encrypt import encrypt_message
from encryption.aes_decrypt import decrypt_message
from steganography.embed import embed_message
from steganography.extract import extract_message

if __name__ == "__main__":
    message = "Hello Secure World"
    password = "strongpassword123"

    # Encrypt
    encrypted = encrypt_message(message, password)

    # Embed
    embed_message(
        "test_images/input.png",
        "test_images/output.png",
        encrypted
    )

    print("Message encrypted and embedded.")

    # Extract
    extracted_encrypted = extract_message("test_images/output.png")

    # Decrypt
    decrypted = decrypt_message(extracted_encrypted, password)

    print("Decrypted message:", decrypted)