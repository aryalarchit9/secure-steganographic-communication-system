from email.mime import image

from PIL import Image
import os


def message_to_binary(message: str):
    return ''.join(format(ord(char), '08b') for char in message)

def embed_message(input_image, output_image, encrypted_message):
    # Open and convert to RGB
    image = Image.open(input_image)

    # Convert to PNG-safe RGB format
    if image.format != "PNG":
        image = image.convert("RGB")
        input_image = "temp_input.png"
        image.save(input_image, "PNG")
        image = Image.open(input_image)
        image = image.convert("RGB")
        pixels = image.load()

    binary_message = message_to_binary(encrypted_message)
    binary_message += '1111111111111110'  # Delimiter

    width, height = image.size
    max_capacity = width * height * 3

    if len(binary_message) > max_capacity:
        raise ValueError("Message too large to fit in selected image.")

    data_index = 0

    for y in range(height):
        for x in range(width):
            if data_index < len(binary_message):
                r, g, b = pixels[x, y]

                r = (r & ~1) | int(binary_message[data_index])
                data_index += 1

                if data_index < len(binary_message):
                    g = (g & ~1) | int(binary_message[data_index])
                    data_index += 1

            if data_index < len(binary_message):
                b = (b & ~1) | int(binary_message[data_index])
                data_index += 1

            pixels[x, y] = (r, g, b)
    # Ensure PNG extension
    if not output_image.lower().endswith(".png"):
        output_image += ".png"

    # Create directory if missing
    directory = os.path.dirname(output_image)
    if directory and not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)

    # Save image
    image.save(output_image, format="PNG")
                 