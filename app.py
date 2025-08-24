import streamlit as st
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

# ----- Streamlit UI -----
st.title("🔐 CipherVault - File Encryption Tool")

password = st.text_input("Enter Password:", type="password")
uploaded_file = st.file_uploader("Select File to Encrypt/Decrypt")

if uploaded_file and password:
    file_bytes = uploaded_file.getvalue()
    file_name = uploaded_file.name

    # Write uploaded file to temp (required for sha256 + utils)
    with open(file_name, "wb") as f:
        f.write(file_bytes)

    key = derive_key(password)

    st.write(f"**File Selected:** {file_name}")
    st.write(f"**SHA256 (Original):** {sha256_hash(file_name)}")

    if st.button("Encrypt File"):
        hash_val = encrypt_file(file_name, key)

        with open(file_name + ".enc", "rb") as f:
            enc_data = f.read()

        st.success(f"✅ File Encrypted!\nSHA256: {hash_val}")
        st.download_button(
            label="Download Encrypted File",
            data=enc_data,
            file_name=file_name + ".enc",
            mime="application/octet-stream"
        )

    if st.button("Decrypt File"):
        decrypt_file(file_name, key)
        decrypted_file = file_name.replace(".enc", "_decrypted.txt")

        with open(decrypted_file, "rb") as f:
            dec_data = f.read()

        st.success("✅ File Decrypted!")
        st.download_button(
            label="Download Decrypted File",
            data=dec_data,
            file_name=decrypted_file,
            mime="application/octet-stream"
        )
