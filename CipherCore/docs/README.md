# CipherCore

**CipherCore** is a secure file encryption and decryption tool that helps protect sensitive data by encrypting files with a password. It ensures robust security with password-based encryption and HMAC-based integrity checks, providing users with an easy-to-use and reliable way to safeguard their files.


## Features
- **Password-based Encryption**: Encrypt files using a secure password to protect sensitive data.
- **HMAC File Integrity**: Verifies the integrity of files during encryption and decryption for added security.
- **Cross-Platform**: Can be used as a Python script or a standalone executable for various operating systems.
- **Simple GUI**: A user-friendly graphical interface that makes it easy to encrypt and decrypt files.

## Installation

1. **Clone this repository**:
   ```bash
   git clone https://github.com/aishwarya-bhatt/CipherCore.git

2. **Install required dependencies (if using Python directly)**:
    pip install -r requirements.txt

    For creating the executable, you will need pyinstaller:
        pip install pyinstaller

3.**Use the executable**:

    If you don't want to install Python, simply run the pre-packaged CipherCore.exe from the dist folder after building the executable with PyInstaller.
    To create this, use:
    pyinstaller --onefile --noconsole file_encryptor.py

## Usage
1. **Encrypting a File**:
    Open CipherCore and select "Encrypt File".
    Browse and choose the file you wish to encrypt.
    Provide a strong password for encryption.
    The encrypted file will be saved with a .enc extension.

2. **Decrypting a File**:
    Open CipherCore and select "Decrypt File".
    Browse and select the .enc file you wish to decrypt.
    Enter the password used during encryption to decrypt the file.

## Diagram
CipherCore/
│
├── src/
│   ├── __init__.py
│   └── file_encryptor.py
│
├── assets/
│   └── icon.ico           
│
├── docs/
│   └── README.md          # Documentation file for usage and instructions
│
├── .gitignore
├── LICENSE                
├── requirements.txt       
└── setup.py               
