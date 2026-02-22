from encryption.aes_encrypt import encrypt_message
from encryption.aes_decrypt import decrypt_message
from steganography.embed import embed_message
from steganography.extract import extract_message
from steganalysis.histogram_analysis import compare_images
import sys

def main():
    print("=== Secure Steganographic Communication System ===")

    if len(sys.argv) != 5:
        print("Usage: python main.py <input_image> <output_image> <message> <password>")
        sys.exit(1)

    input_image = sys.argv[1]
    output_image = sys.argv[2]
    message = sys.argv[3]
    password = sys.argv[4]

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

        # Steganalysis
        print("\n[+] Performing histogram analysis...")
        compare_images(input_image, output_image)

    except Exception as e:
        print("\n[!] Error:", str(e))


if __name__ == "__main__":
    main()