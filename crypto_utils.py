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

def sha256_hash(filepath):
    with open(filepath, "rb") as f:
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

    with open(filepath + ".enc", "wb") as f:
        f.write(iv + ciphertext)

    return sha256_hash(filepath)

# ----- AES Decryption -----
def decrypt_file(filepath, key):
    with open(filepath, "rb") as f:
        iv = f.read(16)
        ciphertext = f.read()

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    with open(filepath.replace(".enc", "_decrypted.txt"), "wb") as f:
        f.write(plaintext)
