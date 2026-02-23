import sys
import logging

from encryption.aes_encrypt import encrypt_message
from encryption.aes_decrypt import decrypt_message
from steganography.embed import embed_message
from steganography.extract import extract_message
from steganalysis.histogram_analysis import (
    compare_images,
    calculate_histogram_difference,
)
from utils.utils import validate_password_strength


def main():
    print("=== Secure Steganographic Communication System ===")

    # ---------------- CLI ARGUMENT CHECK ----------------
    if len(sys.argv) not in (5, 6):
        print("Usage: python main.py <input_image> <output_image> <message> <password> [--debug]")
        sys.exit(1)

    input_image = sys.argv[1]
    output_image = sys.argv[2]
    message = sys.argv[3]
    password = sys.argv[4]

    debug_mode = False
    if len(sys.argv) == 6 and sys.argv[5] == "--debug":
        debug_mode = True

    # ---------------- LOGGING CONFIG ----------------
    log_level = logging.DEBUG if debug_mode else logging.INFO

    logging.basicConfig(
        filename="app.log",
        level=log_level,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )

    logging.info("Application started.")

    # ---------------- PASSWORD VALIDATION ----------------
    valid, pw_message = validate_password_strength(password)

    if not valid:
        print(f"[!] Weak Password: {pw_message}")
        logging.warning(f"Weak password attempt: {pw_message}")
        sys.exit(1)

    logging.info("Password strength validated.")

    # ---------------- MAIN PROCESS ----------------
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

        # Steganalysis (Visual)
        logging.info("Performing histogram comparison.")
        print("\n[+] Performing histogram analysis...")
        compare_images(input_image, output_image)

        # Detection Score
        score = calculate_histogram_difference(input_image, output_image)
        print(f"[+] Histogram difference score: {score}")
        logging.info(f"Histogram difference score: {score}")

        if score > 100000:
            print("[!] Warning: Significant image modification detected.")
            logging.warning("High histogram difference detected.")

    except Exception as e:
        logging.error(f"Error occurred: {str(e)}")
        print("\n[!] Error:", str(e))


if __name__ == "__main__":
    main()