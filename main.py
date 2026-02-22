from encryption.aes_encrypt import encrypt_message
from encryption.aes_decrypt import decrypt_message
from steganography.embed import embed_message
from steganography.extract import extract_message
from steganalysis.histogram_analysis import compare_images
import sys
import logging

logging.basicConfig(
    filename="app.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

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
        logging.info("Message encrypted successfully.")
        print("\n[+] Message encrypted.")

        # Embed
        embed_message(input_image, output_image, encrypted)
        logging.info("Message embedded successfully.")
        print("[+] Message embedded into image.")

        # Extract
        extracted_encrypted = extract_message(output_image)
        logging.info("Message extracted successfully.")
        print("[+] Encrypted message extracted from image.")

        # Decrypt
        decrypted = decrypt_message(extracted_encrypted, password)
        logging.info("Message decrypted successfully.")
        print("\n[+] Decrypted message:")
        print(decrypted)

        # Steganalysis
        logging.info("Performing histogram analysis.")
        print("\n[+] Performing histogram analysis...")
        compare_images(input_image, output_image)

    except Exception as e:
        logging.error(f"Error occurred: {str(e)}")
        print("\n[!] Error:", str(e))

if __name__ == "__main__":
    main()