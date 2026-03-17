import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes


# ---------- GENERATE RSA KEYS ----------
def generate_keys():
    key = RSA.generate(2048)

    with open("private.pem", "wb") as f:
        f.write(key.export_key())

    with open("public.pem", "wb") as f:
        f.write(key.publickey().export_key())


# ---------- ENCRYPT FILE ----------
def encrypt_file():

    filepath = filedialog.askopenfilename()

    if not filepath:
        return

    with open(filepath, "rb") as f:
        data = f.read()

    aes_key = get_random_bytes(16)

    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    public_key = RSA.import_key(open("public.pem").read())
    cipher_rsa = PKCS1_OAEP.new(public_key)

    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    with open(filepath + ".enc", "wb") as f:
        f.write(encrypted_aes_key)
        f.write(cipher_aes.nonce)
        f.write(tag)
        f.write(ciphertext)

    messagebox.showinfo("Success", "File Encrypted Successfully!")


# ---------- DECRYPT FILE ----------
def decrypt_file():

    filepath = filedialog.askopenfilename()

    if not filepath:
        return

    with open(filepath, "rb") as f:
        encrypted_aes_key = f.read(256)
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()

    private_key = RSA.import_key(open("private.pem").read())
    cipher_rsa = PKCS1_OAEP.new(private_key)

    aes_key = cipher_rsa.decrypt(encrypted_aes_key)

    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)

    new_file = filepath.replace(".enc", "_decrypted")

    with open(new_file, "wb") as f:
        f.write(data)

    messagebox.showinfo("Success", "File Decrypted Successfully!")


# ---------- GUI ----------
generate_keys()

root = tk.Tk()
root.title("Hybrid Encryption Tool (AES + RSA)")
root.geometry("350x200")

label = tk.Label(root, text="Hybrid Encryption Application", font=("Arial", 14))
label.pack(pady=15)

encrypt_btn = tk.Button(root, text="Encrypt File", command=encrypt_file, width=20)
encrypt_btn.pack(pady=10)

decrypt_btn = tk.Button(root, text="Decrypt File", command=decrypt_file, width=20)
decrypt_btn.pack(pady=10)

root.mainloop()