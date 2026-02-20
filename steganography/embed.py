from PIL import Image


def message_to_binary(message: str):
    return ''.join(format(ord(char), '08b') for char in message)


def embed_message(input_image_path, output_image_path, secret_message):
    image = Image.open(input_image_path)
    image = image.convert("RGB")
    pixels = image.load()

    binary_message = message_to_binary(secret_message)
    binary_message += '1111111111111110'  # Delimiter

    data_index = 0
    width, height = image.size

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
            else:
                image.save(output_image_path)
                return

    image.save(output_image_path)