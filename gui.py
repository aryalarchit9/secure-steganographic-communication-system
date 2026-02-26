import os
import tempfile
from tkinter import *
from tkinter import filedialog, messagebox
from tkinter import ttk
from PIL import Image

from steganography.embed import embed_message
from steganography.extract import extract_message
from security.password_checker import check_password_strength
from security.encryption import encrypt_message, decrypt_message  # kept as-is

# ---------------------- MAIN WINDOW ----------------------

root = Tk()
root.title("Secure Steganography System")
root.geometry("760x720")
root.minsize(720, 640)

# ---------------------- COLOR THEME (Charcoal + Teal) ----------------------

COLORS = {
    "bg": "#111827",
    "panel": "#0b1220",
    "text": "#e5e7eb",
    "muted": "#9ca3af",
    "accent": "#14b8a6",
    "accent_dark": "#0f766e",
    "good": "#22c55e",
    "warn": "#f59e0b",
    "bad": "#ef4444",
}

root.configure(bg=COLORS["bg"])

# ttk style
style = ttk.Style()
try:
    style.theme_use("clam")
except:
    pass

style.configure("TFrame", background=COLORS["bg"])
style.configure("TLabel", background=COLORS["bg"], foreground=COLORS["text"], font=("Segoe UI", 10))
style.configure("Header.TLabel", font=("Segoe UI", 18, "bold"), foreground="#ffffff", background=COLORS["bg"])
style.configure("SubHeader.TLabel", font=("Segoe UI", 10), foreground=COLORS["muted"], background=COLORS["bg"])
style.configure("TEntry", fieldbackground=COLORS["panel"], foreground=COLORS["text"])
style.configure("TButton", font=("Segoe UI", 10), padding=(10, 6))
style.configure("Card.TLabelframe", background=COLORS["bg"], foreground=COLORS["text"], padding=12)
style.configure("Card.TLabelframe.Label", font=("Segoe UI", 11, "bold"), foreground=COLORS["text"], background=COLORS["bg"])

# ---------------------- STATE ----------------------

input_path = StringVar()
output_path = StringVar()
info_var = StringVar(value="Select an image to see size and capacity.")
strength_var = StringVar(value="Strength: —")

# ---------------------- SCROLLABLE CONTENT WRAPPER ----------------------

outer = Frame(root, bg=COLORS["bg"])
outer.pack(fill="both", expand=True)

# Bottom pinned action bar (always visible)
action_bar = Frame(outer, bg=COLORS["bg"])
action_bar.pack(side="bottom", fill="x", padx=18, pady=(0, 16))

# Scroll area (everything else)
scroll_area = Frame(outer, bg=COLORS["bg"])
scroll_area.pack(side="top", fill="both", expand=True)

canvas = Canvas(scroll_area, bg=COLORS["bg"], highlightthickness=0)
canvas.pack(side="left", fill="both", expand=True)

scrollbar = ttk.Scrollbar(scroll_area, orient="vertical", command=canvas.yview)
scrollbar.pack(side="right", fill="y")

canvas.configure(yscrollcommand=scrollbar.set)

content = Frame(canvas, bg=COLORS["bg"])
content_window = canvas.create_window((0, 0), window=content, anchor="nw")

def _on_configure(event=None):
    canvas.configure(scrollregion=canvas.bbox("all"))

def _on_canvas_configure(event):
    canvas.itemconfig(content_window, width=event.width)

content.bind("<Configure>", _on_configure)
canvas.bind("<Configure>", _on_canvas_configure)

# Mousewheel support
def _on_mousewheel(event):
    if event.delta:
        canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

def _on_mousewheel_linux_up(event):
    canvas.yview_scroll(-1, "units")

def _on_mousewheel_linux_down(event):
    canvas.yview_scroll(1, "units")

canvas.bind_all("<MouseWheel>", _on_mousewheel)
canvas.bind_all("<Button-4>", _on_mousewheel_linux_up)
canvas.bind_all("<Button-5>", _on_mousewheel_linux_down)

# ---------------------- IMPORTANT FIX: SAFE INPUT PREPROCESS ----------------------
# This is the key change that prevents "blue screen" / corrupted output when users pick JPG
# or images with modes like RGBA/P. It converts to RGB and saves as a temporary PNG before embedding.

def preprocess_to_rgb_png(input_image_path: str) -> str:
    """
    Returns a path to a temporary PNG (RGB) made from the input image.
    Prevents issues with JPG compression and non-RGB modes.
    """
    img = Image.open(input_image_path)
    if img.mode != "RGB":
        img = img.convert("RGB")

    temp_path = os.path.join(tempfile.gettempdir(), "steg_input_preprocessed.png")
    img.save(temp_path, format="PNG", optimize=True)
    return temp_path

# ---------------------- HELPERS ----------------------

def show_image_info(path):
    try:
        img = Image.open(path)
        width, height = img.size
        capacity = (width * height * 3) // 8
        info_var.set(f"Image Size: {width} × {height}    |    Max Capacity: {capacity} bytes")
    except:
        info_var.set("Select an image to see size and capacity.")

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

def update_strength(event=None):
    pwd = password_entry.get()
    score = check_password_strength(pwd)

    if not pwd:
        strength_var.set("Strength: —")
        strength_label.config(fg=COLORS["muted"])
    elif score < 3:
        strength_var.set("Strength: Weak")
        strength_label.config(fg=COLORS["bad"])
    elif score < 6:
        strength_var.set("Strength: Medium")
        strength_label.config(fg=COLORS["warn"])
    else:
        strength_var.set("Strength: Strong")
        strength_label.config(fg=COLORS["good"])

# ---------------------- CORE FUNCTIONS ----------------------

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

        # Capacity check (use original file for user-friendly estimate)
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

        # IMPORTANT: preprocess input -> RGB PNG before embedding
        safe_input = preprocess_to_rgb_png(input_image)

        embed_message(safe_input, output_image, encrypted)

        messagebox.showinfo("Success", f"Message embedded successfully!\nSaved at:\n{output_image}")

    except Exception as e:
        messagebox.showerror("Error", str(e))

def decrypt_and_extract():
    try:
        input_image = input_path.get().strip()
        password = password_entry.get().strip()

        if not input_image or not os.path.exists(input_image):
            messagebox.showerror("Error", "Valid input image required.")
            return

        extracted = extract_message(input_image, password)

        extracted_entry.config(state="normal")
        extracted_entry.delete("1.0", END)
        extracted_entry.insert("1.0", extracted)
        extracted_entry.config(state="disabled")

        canvas.update_idletasks()
        canvas.yview_moveto(1.0)

    except Exception as e:
        messagebox.showerror("Error", str(e))

def clear_all():
    input_path.set("")
    output_path.set("")
    message_entry.delete("1.0", END)
    password_entry.delete(0, END)

    extracted_entry.config(state="normal")
    extracted_entry.delete("1.0", END)
    extracted_entry.config(state="disabled")

    show_image_info("")
    update_strength()

# ---------------------- CONSISTENT COLORED BUTTONS ----------------------

def make_action_button(parent, text, command, bg, active_bg, fg="#0b1220"):
    btn = Button(
        parent,
        text=text,
        command=command,
        bg=bg,
        fg=fg,
        activebackground=active_bg,
        activeforeground=fg,
        relief="flat",
        bd=0,
        font=("Segoe UI", 10, "bold"),
        padx=16,
        pady=10,
        cursor="hand2",
    )
    btn.bind("<Enter>", lambda e: btn.config(bg=active_bg))
    btn.bind("<Leave>", lambda e: btn.config(bg=bg))
    return btn

# ---------------------- UI BUILD ----------------------

container = Frame(content, bg=COLORS["bg"])
container.pack(fill="both", expand=True, padx=18, pady=18)

# Header
hdr = Frame(container, bg=COLORS["bg"])
hdr.pack(fill="x", pady=(0, 14))

Label(hdr, text="Secure Steganography System", fg="#ffffff", bg=COLORS["bg"], font=("Segoe UI", 18, "bold")).pack(anchor="w")
Label(
    hdr,
    text="Encrypt a message with a password and hide it inside an image. Decrypt extracts it back into the app.",
    fg=COLORS["muted"],
    bg=COLORS["bg"],
    font=("Segoe UI", 10),
).pack(anchor="w", pady=(6, 0))

Label(container, textvariable=info_var, fg=COLORS["accent"], bg=COLORS["bg"], font=("Segoe UI", 10)).pack(anchor="w", pady=(0, 10))

# Files card
files_card = ttk.Labelframe(container, text="Files", style="Card.TLabelframe")
files_card.pack(fill="x", pady=(0, 12))

files_grid = ttk.Frame(files_card)
files_grid.pack(fill="x")
files_grid.columnconfigure(1, weight=1)

ttk.Label(files_grid, text="Input Image:").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=6)
ttk.Entry(files_grid, textvariable=input_path).grid(row=0, column=1, sticky="ew", pady=6)
ttk.Button(files_grid, text="Browse", command=browse_input).grid(row=0, column=2, padx=(8, 0), pady=6)

ttk.Label(files_grid, text="Output Image:").grid(row=1, column=0, sticky="w", padx=(0, 8), pady=6)
ttk.Entry(files_grid, textvariable=output_path).grid(row=1, column=1, sticky="ew", pady=6)
ttk.Button(files_grid, text="Browse", command=browse_output).grid(row=1, column=2, padx=(8, 0), pady=6)

# Secret card
secret_card = ttk.Labelframe(container, text="Secret", style="Card.TLabelframe")
secret_card.pack(fill="both", expand=True, pady=(0, 12))

ttk.Label(secret_card, text="Secret Message:").pack(anchor="w")

message_entry = Text(
    secret_card,
    height=7,
    wrap="word",
    bg=COLORS["panel"],
    fg=COLORS["text"],
    insertbackground=COLORS["text"],
    font=("Consolas", 11),
    relief="flat",
    padx=10,
    pady=10,
    highlightthickness=1,
    highlightbackground="#1f2937",
    highlightcolor=COLORS["accent"],
)
message_entry.pack(fill="both", expand=True, pady=(6, 10))

pwd_row = Frame(secret_card, bg=COLORS["bg"])
pwd_row.pack(fill="x")

Label(pwd_row, text="Password:", fg=COLORS["text"], bg=COLORS["bg"], font=("Segoe UI", 10)).pack(side="left")
password_entry = ttk.Entry(pwd_row, show="*")
password_entry.pack(side="left", fill="x", expand=True, padx=(8, 8))
password_entry.bind("<KeyRelease>", update_strength)

strength_label = Label(pwd_row, textvariable=strength_var, fg=COLORS["muted"], bg=COLORS["bg"], font=("Segoe UI", 10, "bold"))
strength_label.pack(side="right")
update_strength()

Label(
    secret_card,
    text="Tip: Use a larger PNG image for bigger messages. JPG may reduce reliability due to compression.",
    fg=COLORS["muted"],
    bg=COLORS["bg"],
    font=("Segoe UI", 9),
).pack(anchor="w", pady=(10, 0))

# Output card
output_card = ttk.Labelframe(container, text="Extracted Message (Output)", style="Card.TLabelframe")
output_card.pack(fill="both", expand=True, pady=(0, 12))

extracted_entry = Text(
    output_card,
    height=7,
    wrap="word",
    bg=COLORS["panel"],
    fg=COLORS["text"],
    insertbackground=COLORS["text"],
    font=("Consolas", 11),
    relief="flat",
    padx=10,
    pady=10,
    highlightthickness=1,
    highlightbackground="#1f2937",
    highlightcolor=COLORS["accent"],
)
extracted_entry.pack(fill="both", expand=True, pady=(6, 0))
extracted_entry.config(state="disabled")

# ---------------------- PINNED BUTTONS (ALWAYS VISIBLE) ----------------------

make_action_button(action_bar, "Encrypt & Embed", encrypt_and_embed, COLORS["accent"], COLORS["accent_dark"]).pack(side="left")
make_action_button(action_bar, "Decrypt & Extract", decrypt_and_extract, "#a78bfa", "#7c3aed").pack(side="left", padx=10)
make_action_button(action_bar, "Clear All", clear_all, "#374151", "#4b5563", fg=COLORS["text"]).pack(side="right")

root.mainloop()