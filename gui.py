import tkinter as tk
from tkinter import filedialog, messagebox
import logging

from encryption.aes_encrypt import encrypt_message
from encryption.aes_decrypt import decrypt_message
from steganography.embed import embed_message
from steganography.extract import extract_message
from steganalysis.histogram_analysis import calculate_histogram_difference
from utils.utils import validate_password_strength


logging.basicConfig(
    filename="app.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


def browse_input():
    filename = filedialog.askopenfilename(filetypes=[("Image Files", "*.png *.jpg *.jpeg *.bmp *.tiff")])
    input_path.set(filename)


def browse_output():
    filename = filedialog.asksaveasfilename(
        defaultextension=".png",
        filetypes=[("PNG Image", "*.png")]
    )

    if filename and not filename.lower().endswith(".png"):
        filename += ".png"

    output_path.set(filename)

def encrypt_and_embed():
    if not input_path.get() or not output_path.get():
        messagebox.showerror("Error", "Please select both input and output image paths.")
        return
    try:
        input_img = input_path.get()
        output_img = output_path.get()
        message = message_entry.get("1.0", tk.END).strip()
        password = password_entry.get()

        valid, pw_message = validate_password_strength(password)
        if not valid:
            messagebox.showerror("Weak Password", pw_message)
            return

        encrypted = encrypt_message(message, password)
        embed_message(input_img, output_img, encrypted)

        score = calculate_histogram_difference(input_img, output_img)

        result_label.config(
            text=f"Message Embedded Successfully!\nDetection Score: {score}"
        )

        logging.info("Encryption and embedding successful.")

    except Exception as e:
        logging.error(str(e))
        messagebox.showerror("Error", str(e))


def extract_and_decrypt():
    try:
        output_img = output_path.get()
        password = password_entry.get()

        encrypted = extract_message(output_img)
        decrypted = decrypt_message(encrypted, password)

        result_label.config(text=f"Decrypted Message:\n{decrypted}")

        logging.info("Extraction and decryption successful.")

    except Exception as e:
        logging.error(str(e))
        messagebox.showerror("Error", str(e))


# ---------------- GUI SETUP ----------------

root = tk.Tk()
root.title("Secure Steganographic Communication System")
root.geometry("600x500")

input_path = tk.StringVar()
output_path = tk.StringVar()

tk.Label(root, text="Input Image").pack()
tk.Entry(root, textvariable=input_path, width=50).pack()
tk.Button(root, text="Browse Input", command=browse_input).pack()

tk.Label(root, text="Output Image").pack()
tk.Entry(root, textvariable=output_path, width=50).pack()
tk.Button(root, text="Browse Output", command=browse_output).pack()

tk.Label(root, text="Secret Message").pack()
message_entry = tk.Text(root, height=5, width=50)
message_entry.pack()

tk.Label(root, text="Password").pack()
password_entry = tk.Entry(root, show="*", width=50)
password_entry.pack()

tk.Button(root, text="Encrypt & Embed", command=encrypt_and_embed).pack(pady=10)
tk.Button(root, text="Extract & Decrypt", command=extract_and_decrypt).pack(pady=5)

result_label = tk.Label(root, text="", wraplength=500)
result_label.pack(pady=20)

root.mainloop()