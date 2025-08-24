# CipherVault

CipherVault is a simple, secure file encryption and decryption tool with a Streamlit-based user interface. It uses AES for file encryption and RSA for key generation, allowing users to protect sensitive files with password-based encryption.

## Features

- Encrypt any file using AES symmetric encryption
- Decrypt previously encrypted files
- Password-based key derivation (PBKDF2)
- SHA256 hash display for file integrity
- RSA key generation for advanced use
- All files are managed in the `files` directory, with encrypted files in `files/encrypted/` and decrypted files in `files/decrypted/`
- Simple, user-friendly Streamlit web interface

## Directory Structure

```
CipherVault/
├── app.py
├── main.py
├── crypto_utils.py
├── requirements.txt
├── README.md
├── files/
│   ├── encrypted/
│   ├── decrypted/
│   └── ...
├── keys/
│   ├── private.pem
│   ├── public.pem
│   └── README.md
└── ...
```

## Getting Started

### Prerequisites

- Python 3.8+
- pip

### Installation

1. Clone the repository:
	```sh
	git clone https://github.com/VasupriyaPatnaik/CipherVault.git
	cd CipherVault
	```
2. Install dependencies:
	```sh
	pip install -r requirements.txt
	```

### Running the App

Start the Streamlit app:

```sh
streamlit run app.py
```

Open the provided local URL in your browser to use the app.

## Usage

1. Enter a password (used for key derivation)
2. Upload a file to encrypt or decrypt
3. Click "Encrypt File" to encrypt and download the result
4. Click "Decrypt File" to decrypt and download the result

Encrypted files are saved in `files/encrypted/` as `<filename>.enc`.
Decrypted files are saved in `files/decrypted/` as `<filename>_decrypted.txt`.

## Security Notes

- Uses PBKDF2 for password-based key derivation
- AES encryption with random IV
- SHA256 hash for file integrity
- RSA key generation for advanced cryptographic use

## License

MIT License

## Author

Vasupriya Patnaik