from PIL import Image


def binary_to_message(binary_data):
    chars = []
    for i in range(0, len(binary_data), 8):
        byte = binary_data[i:i+8]
        chars.append(chr(int(byte, 2)))
    return ''.join(chars)


def extract_message(image_path):
    image = Image.open(image_path)
    image = image.convert("RGB")
    pixels = image.load()

    width, height = image.size
    binary_data = ""

    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]

            binary_data += str(r & 1)
            binary_data += str(g & 1)
            binary_data += str(b & 1)

    # Look for delimiter
    delimiter = "1111111111111110"
    end_index = binary_data.find(delimiter)

    if end_index == -1:
        return None

    binary_message = binary_data[:end_index]

    return binary_to_message(binary_message)