import os
import hashlib
import tempfile
from tkinter import Tk, filedialog, StringVar, messagebox
from tkinter.ttk import Frame, Label, Entry, Button, Style
import hmac

BLOCK_SIZE = 16
MASTER_PASSWORD = "fallback_password"  # Use a secure fallback password
HMAC_KEY = b"super_secure_hmac_key"  # Separate key for integrity checks

# Utility functions
def pad(data):
    padding_length = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([padding_length] * padding_length)

def unpad(data):
    padding_length = data[-1]
    if padding_length > BLOCK_SIZE:
        raise ValueError("Invalid padding length")
    return data[:-padding_length]

def xor_block(data_block, key):
    return bytes(a ^ b for a, b in zip(data_block, key))

def hash_password(password):
    return hashlib.sha256(password.encode()).digest()[:BLOCK_SIZE]

def generate_hmac(data):
    return hmac.new(HMAC_KEY, data, hashlib.sha256).digest()

def verify_hmac(data, received_hmac):
    expected_hmac = generate_hmac(data)
    if not hmac.compare_digest(expected_hmac, received_hmac):
        raise ValueError("File integrity check failed. Data may have been tampered with.")

# Permission checking function
def check_file_access(filepath, mode):
    if mode == 'r' and not os.access(filepath, os.R_OK):
        raise PermissionError(f"Cannot read file: {filepath}. Check permissions.")
    elif mode == 'w' and not os.access(filepath, os.W_OK):
        raise PermissionError(f"Cannot write to file: {filepath}. Check permissions.")

# Encryption function
def encrypt_file(filepath, user_password):
    try:
        check_file_access(filepath, 'r')

        with open(filepath, "rb") as file:
            plaintext = file.read()

        user_key = hash_password(user_password)
        master_key = hash_password(MASTER_PASSWORD)
        iv = os.urandom(BLOCK_SIZE)

        padded_data = pad(plaintext)
        ciphertext = b""
        for i in range(0, len(padded_data), BLOCK_SIZE):
            block = padded_data[i:i + BLOCK_SIZE]
            ciphertext += xor_block(block, user_key)

        encrypted_password = xor_block(user_key, master_key)
        hmac_signature = generate_hmac(ciphertext)
        encrypted_filepath = filepath + ".enc"

        check_file_access(os.path.dirname(encrypted_filepath), 'w')

        with open(encrypted_filepath, "wb") as file:
            file.write(iv + encrypted_password + hmac_signature + ciphertext)

        messagebox.showinfo("Success", f"File encrypted successfully: {encrypted_filepath}")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {e}")

# Decryption function
def decrypt_file(filepath, user_password):
    try:
        check_file_access(filepath, 'r')

        with open(filepath, "rb") as file:
            file_data = file.read()

        iv = file_data[:BLOCK_SIZE]
        encrypted_password = file_data[BLOCK_SIZE:BLOCK_SIZE * 2]
        hmac_signature = file_data[BLOCK_SIZE * 2:BLOCK_SIZE * 2 + 32]
        ciphertext = file_data[BLOCK_SIZE * 2 + 32:]

        master_key = hash_password(MASTER_PASSWORD)
        user_key = hash_password(user_password) if user_password else xor_block(encrypted_password, master_key)

        verify_hmac(ciphertext, hmac_signature)

        plaintext = b""
        for i in range(0, len(ciphertext), BLOCK_SIZE):
            block = ciphertext[i:i + BLOCK_SIZE]
            plaintext += xor_block(block, user_key)

        plaintext = unpad(plaintext)

        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as temp_file:
            temp_file.write(plaintext)
            temp_file_path = temp_file.name

        messagebox.showinfo("Success", "File decrypted successfully. Opening the file...")
        os.startfile(temp_file_path)
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {e}")

# GUI setup
class FileEncryptorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Encryptor")
        self.root.geometry("500x200")
        self.root.resizable(False, False)

        # Style setup
        style = Style()
        style.configure("TLabel", font=("Arial", 12))
        style.configure("TButton", font=("Arial", 12))
        style.configure("TEntry", font=("Arial", 12))

        # Layout
        frame = Frame(root, padding=10)
        frame.pack(fill="both", expand=True)

        Label(frame, text="Password:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        self.password_entry = Entry(frame, show="*")
        self.password_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        Button(frame, text="Encrypt File", command=self.start_encrypt).grid(row=1, column=0, padx=5, pady=5)
        Button(frame, text="Decrypt File", command=self.start_decrypt).grid(row=1, column=1, padx=5, pady=5)

    def select_file(self):
        return filedialog.askopenfilename()

    def start_encrypt(self):
        filepath = self.select_file()
        if filepath:
            password = self.password_entry.get()
            encrypt_file(filepath, password)

    def start_decrypt(self):
        filepath = self.select_file()
        if filepath:
            password = self.password_entry.get()
            decrypt_file(filepath, password)

# Main application
if __name__ == "__main__":
    root = Tk()
    app = FileEncryptorApp(root)
    root.mainloop()
