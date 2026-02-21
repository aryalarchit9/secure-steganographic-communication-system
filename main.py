from encryption.aes_encrypt import encrypt_message
from encryption.aes_decrypt import decrypt_message
from steganography.embed import embed_message
from steganography.extract import extract_message


def main():
    print("=== Secure Steganographic Communication System ===")

    message = input("Enter secret message: ")
    password = input("Enter encryption password: ")

    input_image = "test_images/input.png"
    output_image = "test_images/output.png"

    try:
        # Encrypt
        encrypted = encrypt_message(message, password)
        print("\n[+] Message encrypted.")

        # Embed
        embed_message(input_image, output_image, encrypted)
        print("[+] Message embedded into image.")

        # Extract
        extracted_encrypted = extract_message(output_image)
        print("[+] Encrypted message extracted from image.")

        # Decrypt
        decrypted = decrypt_message(extracted_encrypted, password)
        print("\n[+] Decrypted message:")
        print(decrypted)

    except Exception as e:
        print("\n[!] Error:", str(e))


if __name__ == "__main__":
    main()