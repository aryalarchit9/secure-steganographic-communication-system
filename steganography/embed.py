from PIL import Image
import os


def message_to_binary(message: str):
    return ''.join(format(ord(char), '08b') for char in message)


def embed_message(input_image, output_image, encrypted_message):
    # Open and convert to RGB (works for PNG/JPG/BMP and avoids mode issues like RGBA/P)
    image = Image.open(input_image).convert("RGB")
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
            if data_index >= len(binary_message):
                break

            r, g, b = pixels[x, y]

            # R
            r = (r & ~1) | int(binary_message[data_index])
            data_index += 1

            # G
            if data_index < len(binary_message):
                g = (g & ~1) | int(binary_message[data_index])
                data_index += 1

            # B
            if data_index < len(binary_message):
                b = (b & ~1) | int(binary_message[data_index])
                data_index += 1

            pixels[x, y] = (r, g, b)

        if data_index >= len(binary_message):
            break

    # Ensure PNG extension
    if not output_image.lower().endswith(".png"):
        output_image += ".png"

    # Create directory if missing
    directory = os.path.dirname(output_image)
    if directory and not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)

    # Save image as PNG (lossless, keeps embedded bits intact)
    image.save(output_image, format="PNG")