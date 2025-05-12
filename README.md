# Secure Python Password Manager

## Overview

This is a secure, locally-stored password management application built in Python. It provides a simple command-line interface for storing and retrieving passwords using strong encryption.

## Features

- **Secure Encryption**: Uses Fernet symmetric encryption with PBKDF2 key derivation
- **Master Password Protection**: Encrypts all stored passwords with a master password
- **Simple Interface**: Easy-to-use command-line menu
- **Flexible Storage**: Store multiple usernames for the same service
- **Lightweight**: No external database required

## Prerequisites

- Python 3.7+
- Cryptography library

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/password-manager.git
cd password-manager
```

2. Install required dependencies:
```bash
pip install cryptography
```

## Usage

Run the script:
```bash
python password_manager.py
```

### Main Menu Options

1. **Add Password**
   - Add a new password for a service
   - Enter service name, username, and password

2. **Get Password**
   - Retrieve passwords for a specific service
   - View all stored usernames and passwords for the service

3. **List Services**
   - View all services with stored passwords

4. **Exit**
   - Close the application

## Security Notes

- Keep your master password secure and memorable
- Passwords are encrypted locally in "password_vault.txt"
- Losing the master password means losing access to stored passwords
- Do not share the `password_vault.txt` file

## How It Works

1. When first launched, you create a master password.
2. The master password is used to derive an encryption key.
3. Passwords are encrypted before being stored.
4. Each password is stored with its service name and username.
5. Passwords can only be decrypted with the correct master password.

## Limitations

- Local storage only
- Single-device use
- Command-line interface
- No password generation feature

## Potential Improvements

- Add password generation
- Implement cloud sync
- Create GUI interface
- Add password strength checking
- Implement more robust error handling

## Security Disclaimer

While this password manager provides basic encryption, it is not recommended for storing extremely sensitive information. Always use established, professionally audited password management solutions for critical data.

