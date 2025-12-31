import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import secrets

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes = 256 bits
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(filename, password):
    salt = secrets.token_bytes(16)
    key = derive_key(password, salt)
    iv = secrets.token_bytes(16)

    with open(filename, "rb") as f:
        data = f.read()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded_data) + encryptor.finalize()

    with open(filename + ".enc", "wb") as f:
        f.write(salt + iv + encrypted)

    print("File encrypted successfully")

def decrypt_file(filename, password):
    with open(filename, "rb") as f:
        salt = f.read(16)
        iv = f.read(16)
        encrypted_data = f.read()

    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()

    output_file = filename.replace(".enc", ".dec")
    with open(output_file, "wb") as f:
        f.write(data)

    print("File decrypted successfully")

def main():
    print("Advanced Encryption Tool (AES‑256)")
    print("1. Encrypt File")
    print("2. Decrypt File")

    choice = input("Enter choice: ")

    file = input("Enter file name: ")
    password = input("Enter password: ")

    if choice == "1":
        encrypt_file(file, password)
    elif choice == "2":
        decrypt_file(file, password)
    else:
        print("Invalid choice")

if __name__ == "__main__":
    main()
