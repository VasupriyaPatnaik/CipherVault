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
ENCRYPTED_DIR = "files/encrypted"
DECRYPTED_DIR = "files/decrypted"
os.makedirs(ENCRYPTED_DIR, exist_ok=True)
os.makedirs(DECRYPTED_DIR, exist_ok=True)

# ----- Streamlit UI -----
st.title("🔐 CipherVault - File Encryption Tool")

password = st.text_input("Enter Password:", type="password")
uploaded_file = st.file_uploader("Select File to Encrypt/Decrypt")

if uploaded_file and password:
    file_bytes = uploaded_file.read()
    key = derive_key(password)

    st.write(f"**File Selected:** {uploaded_file.name}")

    # Compute original file hash
    file_hash = sha256_hash(io.BytesIO(file_bytes))
    st.write(f"**SHA256 (Original):** {file_hash}")

    # Encrypt
    if st.button("Encrypt File"):
        encrypted_bytes, enc_hash = encrypt_file(io.BytesIO(file_bytes), key)

        # Save in encrypted folder
        enc_file_path = os.path.join(ENCRYPTED_DIR, uploaded_file.name + ".enc")
        with open(enc_file_path, "wb") as f:
            f.write(encrypted_bytes)

        st.success(f"✅ File Encrypted!\nSHA256: {enc_hash}")

        with open(enc_file_path, "rb") as f:
            st.download_button(
                label="Download Encrypted File",
                data=f,
                file_name=os.path.basename(enc_file_path)
            )

    # Decrypt
    if st.button("Decrypt File"):
        decrypted_bytes = decrypt_file(io.BytesIO(file_bytes), key)

        # Save in decrypted folder
        dec_file_path = os.path.join(DECRYPTED_DIR, uploaded_file.name.replace(".enc", "_decrypted.txt"))
        with open(dec_file_path, "wb") as f:
            f.write(decrypted_bytes)

        st.success("✅ File Decrypted!")

        with open(dec_file_path, "rb") as f:
            st.download_button(
                label="Download Decrypted File",
                data=f,
                file_name=os.path.basename(dec_file_path)
            )
