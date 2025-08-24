import os
from crypto_utils import encrypt_file, decrypt_file
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import urlsafe_b64encode
from getpass import getpass

def derive_key(password: str) -> bytes:
    salt = b"CipherVaultSalt"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    return kdf.derive(password.encode())

def main():
    print("🔐 CipherVault - Secure File Encryption Tool")
    choice = input("1. Encrypt File\n2. Decrypt File\nChoose: ")

    password = getpass("Enter password: ")
    key = derive_key(password)

    if choice == "1":
        filepath = input("Enter file path to encrypt: ")
        file_hash = encrypt_file(filepath, key)
        print(f"✅ Encrypted successfully. SHA256: {file_hash}")
    elif choice == "2":
        filepath = input("Enter .enc file path to decrypt: ")
        decrypt_file(filepath, key)
        print("✅ Decrypted successfully.")
    else:
        print("Invalid choice!")

if __name__ == "__main__":
    main()
