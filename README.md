# Encryption

Small Python examples for two common cryptography workflows:

- `AES` for symmetric file encryption
- `RSA` for asymmetric encryption and digital signatures

This repository is still a learning project, but it now includes small command-line interfaces for both examples.

## Project Layout

```text
.
├── aes/
│   ├── aes-encrypt.py
│   └── aes-decrypt.py
├── bash/
│   └── gpg-file.sh
├── requirements.txt
└── rsa/
    └── rsa_cli.py
```

## Requirements

- Python 3
- `gpg` (for the Bash demo)
- `pycryptodome`
- `rsa`

Install the dependencies with:

```bash
python3 -m pip install -r requirements.txt
```

Optional configuration:

- copy `.env.example` to `.env`
- load that `.env` file in your shell or editor if you want to change the default keys, file paths, or RSA key size
- CLI arguments still override the environment-based defaults

## AES Demo

The AES example uses:

- `aes/aes-encrypt.py` to encrypt a file
- `aes/aes-decrypt.py` to decrypt it

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

## Notes

These scripts are useful for learning and local experimentation, but they are not production-ready security tooling.

- The default AES key is hard-coded for example purposes.
- RSA encryption is only suitable here for short messages.
- Private keys are written to disk without extra protection.
- There is no secret management, passphrase handling, or automated tests.

## Summary

This repository now provides:

- `requirements.txt` for dependencies
- `.env.example` for documented default configuration
- a working AES encrypt/decrypt CLI
- a Bash GPG encrypt/decrypt CLI
- a renamed RSA module that avoids the original import conflict
- a small RSA CLI for key generation, signing, verification, encryption, and decryption
