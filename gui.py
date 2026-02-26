import os
from tkinter import *
from tkinter import filedialog, messagebox
from PIL import Image

from steganography.embed import embed_message
from steganography.extract import extract_message
from security.password_checker import check_password_strength
from security.encryption import encrypt_message, decrypt_message

# ---------------------- MAIN WINDOW ----------------------

root = Tk()
root.title("Secure Steganography System")
root.geometry("500x600")

input_path = StringVar()
output_path = StringVar()

# ---------------------- BROWSE FUNCTIONS ----------------------

def browse_input():
    file_path = filedialog.askopenfilename(
        filetypes=[("Image Files", "*.png *.jpg *.jpeg *.bmp")]
    )
    if file_path:
        input_path.set(file_path)
        show_image_info(file_path)

def browse_output():
    file_path = filedialog.asksaveasfilename(
        defaultextension=".png",
        filetypes=[("PNG Files", "*.png")]
    )
    if file_path:
        output_path.set(file_path)

# ---------------------- IMAGE INFO ----------------------

info_label = Label(root, text="", fg="blue")
info_label.pack(pady=5)

def show_image_info(path):
    try:
        img = Image.open(path)
        width, height = img.size
        capacity = (width * height * 3) // 8

        info_label.config(
            text=f"Image Size: {width} x {height}\nMax Capacity: {capacity} bytes"
        )
    except:
        info_label.config(text="")

# ---------------------- PASSWORD STRENGTH ----------------------

strength_label = Label(root, text="Strength: ", font=("Arial", 10))
strength_label.pack(pady=5)

def update_strength(event=None):
    pwd = password_entry.get()
    score = check_password_strength(pwd)

    if score < 3:
        strength_label.config(text="Strength: Weak", fg="red")
    elif score < 6:
        strength_label.config(text="Strength: Medium", fg="orange")
    else:
        strength_label.config(text="Strength: Strong", fg="green")

# ---------------------- EMBED FUNCTION ----------------------

def encrypt_and_embed():
    try:
        input_image = input_path.get().strip()
        output_image = output_path.get().strip()
        secret_message = message_entry.get("1.0", END).strip()
        password = password_entry.get().strip()

        if not input_image or not os.path.exists(input_image):
            messagebox.showerror("Error", "Valid input image required.")
            return

        if not output_image:
            messagebox.showerror("Error", "Output location required.")
            return

        if not secret_message:
            messagebox.showerror("Error", "Secret message cannot be empty.")
            return

        # Capacity check
        img = Image.open(input_image)
        width, height = img.size
        max_capacity = (width * height * 3) // 8

        if len(secret_message.encode()) > max_capacity:
            messagebox.showerror("Error", "Message too large for selected image.")
            return

        # Normalize output path
        output_image = os.path.normpath(output_image)

        if not output_image.lower().endswith(".png"):
            output_image += ".png"

        directory = os.path.dirname(output_image)
        if directory and not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)

        encrypted = encrypt_message(secret_message, password)
        encrypted += "###"
        embed_message(input_image, output_image, encrypted)

        messagebox.showinfo(
            "Success",
            f"Message embedded successfully!\nSaved at:\n{output_image}"
        )

    except Exception as e:
        messagebox.showerror("Error", str(e))

# ---------------------- EXTRACT FUNCTION ----------------------

def decrypt_and_extract():
    try:
        input_image = input_path.get().strip()
        password = password_entry.get().strip()

        if not input_image or not os.path.exists(input_image):
            messagebox.showerror("Error", "Valid input image required.")
            return

        extracted = extract_message(input_image, password)

        messagebox.showinfo("Extracted Message", extracted)

    except Exception as e:
        messagebox.showerror("Error", str(e))

# ---------------------- UI LAYOUT ----------------------

Label(root, text="Input Image").pack()
Entry(root, textvariable=input_path, width=50).pack()
Button(root, text="Browse Input", command=browse_input).pack(pady=5)

Label(root, text="Output Image").pack()
Entry(root, textvariable=output_path, width=50).pack()
Button(root, text="Browse Output", command=browse_output).pack(pady=5)

Label(root, text="Secret Message").pack()
message_entry = Text(root, height=5, width=50)
message_entry.pack(pady=5)

Label(root, text="Password").pack()
password_entry = Entry(root, show="*", width=30)
password_entry.pack(pady=5)
password_entry.bind("<KeyRelease>", update_strength)

Button(root, text="Encrypt & Embed", command=encrypt_and_embed, bg="green", fg="white").pack(pady=10)
Button(root, text="Decrypt & Extract", command=decrypt_and_extract, bg="blue", fg="white").pack(pady=5)

root.mainloop()