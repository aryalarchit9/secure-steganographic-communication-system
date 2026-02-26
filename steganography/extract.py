from PIL import Image
from security.encryption import decrypt_message
import os


def extract_message(image_path, password):

    if not os.path.exists(image_path):
        raise Exception("Image path does not exist")

    try:
        image = Image.open(image_path)
    except Exception as e:
        raise Exception(f"Failed to open image: {str(e)}")

    pixels = list(image.getdata())

    binary_data = ""

    for pixel in pixels:
        for value in pixel[:3]:
            binary_data += str(value & 1)

    extracted_text = ""

    for i in range(0, len(binary_data), 8):
        byte = binary_data[i:i+8]
        if len(byte) < 8:
            break

        extracted_text += chr(int(byte, 2))

        if extracted_text.endswith("###"):
            break

    if "###" not in extracted_text:
        raise Exception("No hidden message found")

    encrypted_message = extracted_text[:-3]

    return decrypt_message(encrypted_message, password)