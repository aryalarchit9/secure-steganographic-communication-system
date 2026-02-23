from PIL import Image
import matplotlib.pyplot as plt
import numpy as np


def plot_histogram(image_path, title):
    image = Image.open(image_path)
    image = image.convert("RGB")
    data = np.array(image)

    colors = ('red', 'green', 'blue')

    plt.figure()
    plt.title(title)
    plt.xlabel("Pixel Value")
    plt.ylabel("Frequency")

    for i, color in enumerate(colors):
        histogram, bins = np.histogram(
            data[:, :, i].flatten(),
            bins=256,
            range=(0, 256)
        )
        plt.plot(histogram)

    plt.xlim([0, 256])
    plt.show()


def compare_images(original_image, stego_image):
    plot_histogram(original_image, "Original Image Histogram")
    plot_histogram(stego_image, "Stego Image Histogram")


def calculate_histogram_difference(original_image, stego_image):
    image1 = Image.open(original_image).convert("RGB")
    image2 = Image.open(stego_image).convert("RGB")

    data1 = np.array(image1)
    data2 = np.array(image2)

    diff = np.sum(np.abs(data1 - data2))
    return diff    