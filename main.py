import streamlit as st
import os
import io
from crypto_utils import encrypt_file, decrypt_file, sha256_hash
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ----- Key derivation -----
def derive_key(password: str) -> bytes:
    salt = b"CipherVaultSalt"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    return kdf.derive(password.encode())

# ----- Setup folders -----
FILES_DIR = "files"
os.makedirs(FILES_DIR, exist_ok=True)

# ----- Streamlit UI -----
st.title("🔐 CipherVault - File Encryption Tool")

password = st.text_input("Enter Password:", type="password")
uploaded_file = st.file_uploader("Select File to Encrypt/Decrypt")

if uploaded_file and password:
    file_name = uploaded_file.name
    file_path = os.path.join(FILES_DIR, file_name)
    with open(file_path, "wb") as f:
        f.write(uploaded_file.read())

    key = derive_key(password)

    st.write(f"**File Selected:** {file_name}")
    file_hash = sha256_hash(file_path)
    st.write(f"**SHA256 (Original):** {file_hash}")

    # Encrypt
    if st.button("Encrypt File"):
        base_name = os.path.splitext(file_name)[0]
        enc_file_path = os.path.join(FILES_DIR, base_name + ".enc")
        encrypted_bytes, enc_hash = encrypt_file(file_path, key)
        with open(enc_file_path, "wb") as f:
            f.write(encrypted_bytes)

        st.success(f"✅ File Encrypted!\nSHA256: {enc_hash}")
        st.download_button(
            label="Download Encrypted File",
            data=encrypted_bytes,
            file_name=base_name + ".enc"
        )

    # Decrypt
    if st.button("Decrypt File"):
        base_name = os.path.splitext(file_name)[0]
        dec_file_path = os.path.join(FILES_DIR, base_name + "_decrypted.txt")
        decrypted_bytes = decrypt_file(file_path, key)
        with open(dec_file_path, "wb") as f:
            f.write(decrypted_bytes)

        st.success("✅ File Decrypted!")
        st.download_button(
            label="Download Decrypted File",
            data=decrypted_bytes,
            file_name=os.path.basename(dec_file_path)
        )
