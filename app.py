import streamlit as st
import os
import io
from crypto_utils import encrypt_file, decrypt_file, sha256_hash
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Directories
ENCRYPTED_DIR = "encrypted_files"
DECRYPTED_DIR = "decrypted_files"
os.makedirs(ENCRYPTED_DIR, exist_ok=True)
os.makedirs(DECRYPTED_DIR, exist_ok=True)

# Key derivation
def derive_key(password: str) -> bytes:
    salt = b"CipherVaultSalt"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    return kdf.derive(password.encode())

# Streamlit UI
st.title("🔐 CipherVault - File Encryption Tool")

password = st.text_input("Enter Password:", type="password")
uploaded_file = st.file_uploader("Select File to Encrypt/Decrypt")

if uploaded_file and password:
    file_bytes = uploaded_file.getvalue()
    file_name = uploaded_file.name

    key = derive_key(password)

    st.write(f"**File Selected:** {file_name}")
    st.write(f"**SHA256 (Original):** {sha256_hash(file_bytes)}")

    # Encrypt
    if st.button("Encrypt File"):
        encrypted_bytes, enc_hash = encrypt_file(io.BytesIO(file_bytes), key)

        st.success(f"✅ File Encrypted!\nSHA256: {enc_hash}")

        # Provide BytesIO buffer for download
        st.download_button(
            label="Download Encrypted File",
            data=encrypted_bytes,
            file_name=file_name + ".enc"
        )

    # Decrypt
    if st.button("Decrypt File"):
        decrypted_bytes = decrypt_file(io.BytesIO(file_bytes), key)

        st.success("✅ File Decrypted!")

        # Provide BytesIO buffer for download
        dec_name = file_name.replace(".enc", "_decrypted")
        st.download_button(
            label="Download Decrypted File",
            data=decrypted_bytes,
            file_name=dec_name
        )
