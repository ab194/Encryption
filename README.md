# Encryption

Small Python examples for two common cryptography workflows:

- `AES` for symmetric file encryption
- `RSA` for asymmetric encryption and digital signatures

This repository is still a learning project, but it now includes small command-line interfaces for both examples.

## Project Layout

```text
.
├── aes/
│   ├── aes-archive.py
│   ├── aes-xts-archive.py
│   ├── aes-encrypt.py
│   └── aes-decrypt.py
├── bash/
│   ├── gpg.sh
│   └── password_generator.sh
├── password_generator.py
├── crypto.requirements.txt
├── passwdGen.requirements.txt
└── rsa/
    └── rsa_cli.py
```

## Requirements

- Python 3
- `gpg` (for the Bash demo)
- `pycryptodome`
- `rsa`
- `cryptography`

Install the dependencies with:

```bash
python3 -m pip install -r crypto.requirements.txt
```

Note: The password generators require no external dependencies; they use only Python standard library and bash built-ins respectively.

- copy `.env.example` to `.env`
- load that `.env` file in your shell or editor if you want to change the default keys, file paths, or RSA key size
- CLI arguments still override the environment-based defaults

## AES Demo

The AES example uses:

- `aes/aes-encrypt.py` to encrypt a file
- `aes/aes-decrypt.py` to decrypt it
- `aes/aes-archive.py` to encrypt and decrypt complete files or folders
- `aes/aes-xts-archive.py` to encrypt and decrypt complete files or folders with AES-XTS

### What It Does

- reads plaintext bytes from a file
- encrypts them with AES in `OCB` mode
- stores the result as `tag + nonce + ciphertext`
- verifies integrity during decryption
- writes the decrypted bytes back to a file

By default, these scripts read and write files inside the `aes/` directory:

- input plaintext: `aes/file_to_encrypt`
- encrypted output: `aes/encrypted.aes`
- decrypted output: `aes/decrypted_file`

### AES CLI Usage

Create a sample file and encrypt it:

```bash
printf 'hello world' > aes/file_to_encrypt
python3 aes/aes-encrypt.py
```

Decrypt the result:

```bash
python3 aes/aes-decrypt.py
```

You can also override the defaults:

```bash
python3 aes/aes-encrypt.py ./message.txt --output ./message.aes --key 1234567891234567
python3 aes/aes-decrypt.py ./message.aes --output ./message.txt --key 1234567891234567
```

### AES Folder/File Archive Usage

Use `aes/aes-archive.py` when you want to encrypt a complete folder, a nested folder tree, or a file of any type. It first stores the input as a TAR archive, then encrypts that archive with AES in `OCB` mode.

Encrypt a folder:

```bash
python3 aes/aes-archive.py encrypt ./my-folder --output ./my-folder.aes --key 12345678912345678912345678912345
```

Decrypt and extract it:

```bash
python3 aes/aes-archive.py decrypt ./my-folder.aes --output ./restored --key 12345678912345678912345678912345
```

Encrypt a single file, including binary files:

```bash
python3 aes/aes-archive.py encrypt ./photo.png --output ./photo.png.aes --key 12345678912345678912345678912345
```

The extracted folder keeps the original top-level name. For example, decrypting `./my-folder.aes` into `./restored` creates `./restored/my-folder/...`.

### AES-XTS Folder/File Archive Usage

Use `aes/aes-xts-archive.py` when you specifically want AES-XTS. It stores the input as a TAR archive, encrypts that archive in XTS sectors, and adds an HMAC so wrong keys or corrupted encrypted archives are rejected before extraction.

Encrypt a folder with AES-256-XTS:

```bash
python3 aes/aes-xts-archive.py encrypt ./my-folder --output ./my-folder.xts.aes --key 0123456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210
```

Decrypt and extract it:

```bash
python3 aes/aes-xts-archive.py decrypt ./my-folder.xts.aes --output ./restored --key 0123456789abcdef0123456789abcdeffedcba9876543210fedcba9876543210
```

AES-XTS uses double-length keys:

- 32 bytes total for AES-128-XTS
- 64 bytes total for AES-256-XTS

AES-192-XTS is not supported. The two halves of the XTS key must be different.

## RSA Demo

The RSA example lives in `rsa/rsa_cli.py`.

The module was renamed from `rsa.py` to `rsa_cli.py` so it no longer collides with the third-party `rsa` package it imports.

### What It Does

The RSA CLI supports:

- generating a 2048-bit key pair
- signing a message
- verifying a signature
- encrypting a short message
- decrypting a short message

By default, these files are created inside the `rsa/` directory:

- `public_key.txt`
- `private_key.txt`
- `signature`
- `encrypted_message.bin`

### RSA CLI Usage

Generate keys:

```bash
python3 rsa/rsa_cli.py generate-keys
```

Sign and verify a message:

```bash
python3 rsa/rsa_cli.py sign "hello world"
python3 rsa/rsa_cli.py verify "hello world"
```

Encrypt and decrypt a short message:

```bash
python3 rsa/rsa_cli.py encrypt "hello world"
python3 rsa/rsa_cli.py decrypt
```

You can override paths when needed:

```bash
python3 rsa/rsa_cli.py generate-keys --public-key ./pub.pem --private-key ./priv.pem
python3 rsa/rsa_cli.py encrypt "hello world" --public-key ./pub.pem --output ./cipher.bin
python3 rsa/rsa_cli.py decrypt --input ./cipher.bin --private-key ./priv.pem
```

## Bash GPG Demo

The Bash example lives in `bash/gpg-file.sh`.

### What It Does

The script automates file encryption and decryption with the Linux `gpg` CLI.

- encrypts files with either a recipient public key or a symmetric passphrase
- decrypts `.gpg`, `.pgp`, or `.asc` files back to plaintext
- supports optional ASCII armor output
- supports optional custom `--homedir` paths for isolated GPG keyrings

### Bash GPG Usage

Make the script executable once:

```bash
chmod +x bash/gpg-file.sh
```

Encrypt a file with a symmetric passphrase:

```bash
printf 'my secret data' > bash/message.txt
printf 'strong-passphrase' > bash/pass.txt
bash/gpg-file.sh encrypt --input bash/message.txt --symmetric --passphrase-file bash/pass.txt
```

Decrypt the result:

```bash
bash/gpg-file.sh decrypt --input bash/message.txt.gpg --passphrase-file bash/pass.txt
```

Encrypt for a GPG recipient:

```bash
bash/gpg-file.sh encrypt --input bash/message.txt --recipient alice@example.com --armor
```

You can override the output path when needed:

```bash
bash/gpg-file.sh encrypt --input ./message.txt --symmetric --output ./message.txt.gpg
bash/gpg-file.sh decrypt --input ./message.txt.gpg --output ./message.txt
```

## Password Generators

Two password generator implementations are provided: one in Python and one in Bash. Both support the same options and generate cryptographically secure random passwords.

### Python Version

The Python implementation (`password_generator.py`) uses the cryptographically secure `secrets` module.

**Features:**

- Generates passwords with customizable character types
- Create multiple passwords at once
- Support for uppercase, lowercase, digits, and special characters
- Special modes: digits-only, alphanumeric

**Usage:**

```bash
python3 password_generator.py              # 16 char password with all types
python3 password_generator.py -l 32        # 32 character password
python3 password_generator.py -c 5         # Generate 5 passwords
python3 password_generator.py -l 20 --no-special  # Without special chars
python3 password_generator.py --digits-only -l 12 # 12 digit PIN
python3 password_generator.py --alphanumeric      # Letters and numbers only
```

### Bash Version

The Bash implementation (`bash/password_generator.sh`) is a pure Bash script with no external dependencies.

**Features:**

- Lightweight, bash-only implementation
- Same options as Python version
- Color-coded error messages
- Works on any Linux/Unix system with Bash

**Usage:**

```bash
./bash/password_generator.sh              # 16 char password with all types
./bash/password_generator.sh -l 32        # 32 character password
./bash/password_generator.sh -c 5         # Generate 5 passwords
./bash/password_generator.sh -l 20 --no-special  # Without special chars
./bash/password_generator.sh --digits-only -l 12 # 12 digit PIN
```

**Both versions support:**

- `-l, --length NUM` - Set password length (default: 16)
- `-c, --count NUM` - Generate multiple passwords (default: 1)
- `--no-uppercase` - Exclude uppercase letters
- `--no-lowercase` - Exclude lowercase letters
- `--no-digits` - Exclude digits
- `--no-special` - Exclude special characters
- `--digits-only` - Generate digits only
- `--alphanumeric` - Letters and numbers only
- `-h, --help` - Show help message

## Notes

These scripts are useful for learning and local experimentation, but they are not production-ready security tooling.

- The default AES key is hard-coded for example purposes.
- Use a 32-byte AES key for AES-256, a 24-byte key for AES-192, or a 16-byte key for AES-128.
- AES-XTS uses 32-byte keys for AES-128-XTS and 64-byte keys for AES-256-XTS.
- XTS mode is designed for disk encryption; this repository wraps it around TAR archives for learning and adds an HMAC for integrity.
- RSA encryption is only suitable here for short messages.
- Private keys are written to disk without extra protection.
- There is no secret management, passphrase handling, or automated tests.

## Summary

This repository now provides:

- `crypto.requirements.txt` for cryptography dependencies (AES/RSA)
- `passwdGen.requirements.txt` for password generator dependencies (none)
- `.env.example` for documented default configuration
- a working AES encrypt/decrypt CLI
- an AES archive CLI for encrypting complete folders and binary files
- an AES-XTS archive CLI for encrypting complete folders and binary files
- a Bash GPG encrypt/decrypt CLI
- a renamed RSA module that avoids the original import conflict
- a small RSA CLI for key generation, signing, verification, encryption, and decryption
- password generators in both Python and Bash with customizable options
