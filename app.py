import streamlit as st
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
    # Save uploaded file temporarily
    temp_filename = uploaded_file.name
    with open(temp_filename, "wb") as f:
        f.write(uploaded_file.getbuffer())

    key = derive_key(password)

    st.write(f"**File Selected:** {temp_filename}")
    st.write(f"**SHA256 (Original):** {sha256_hash(temp_filename)}")

    if st.button("Encrypt File"):
        hash_val = encrypt_file(temp_filename, key)
        st.success(f"✅ File Encrypted!\nSHA256: {hash_val}")
        st.download_button(
            label="Download Encrypted File",
            data=open(temp_filename + ".enc", "rb").read(),
            file_name=temp_filename + ".enc"
        )

    if st.button("Decrypt File"):
        decrypt_file(temp_filename, key)
        decrypted_file = temp_filename.replace(".enc", "_decrypted.txt")
        st.success("✅ File Decrypted!")
        st.download_button(
            label="Download Decrypted File",
            data=open(decrypted_file, "rb").read(),
            file_name=decrypted_file
        )
