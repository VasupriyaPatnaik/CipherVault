# ----- RSA Key Generation -----
from Crypto.PublicKey import RSA

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    # Make sure the keys folder exists
    import os
    if not os.path.exists("keys"):
        os.makedirs("keys")

    with open("keys/private.pem", "wb") as f:
        f.write(private_key)
    with open("keys/public.pem", "wb") as f:
        f.write(public_key)

    print("RSA Keys generated and saved in /keys/")

# ----- SHA256 Hashing -----
import hashlib

def sha256_hash(file_or_path):
    if hasattr(file_or_path, "read"):
        data = file_or_path.read()
        file_or_path.seek(0)  # Reset pointer for reuse
    else:
        with open(file_or_path, "rb") as f:
            data = f.read()
    return hashlib.sha256(data).hexdigest()

# ----- AES Encryption -----
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt_file(filepath, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(filepath, "rb") as f:
        plaintext = f.read()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    encrypted_data = iv + ciphertext
    enc_hash = hashlib.sha256(encrypted_data).hexdigest()
    return encrypted_data, enc_hash

# ----- AES Decryption -----
def decrypt_file(filepath, key):
    with open(filepath, "rb") as f:
        iv = f.read(16)
        ciphertext = f.read()

    if len(iv) != 16 or not ciphertext:
        raise ValueError("Encrypted file is empty or corrupted (missing IV or ciphertext).")

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext
