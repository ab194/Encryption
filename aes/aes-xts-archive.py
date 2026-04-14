import argparse
import io
import os
import struct
import sys
import tarfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
MAGIC = b"AXTSAR01"
HEADER = struct.Struct(">8sI16s16sQ")
HMAC_SIZE = 32
DEFAULT_SECTOR_SIZE = 4096


def env_text(name, default):
    return os.environ.get(name, default)


def env_path(name, default):
    value = os.environ.get(name)
    if value is None:
        return default

    path = Path(value)
    return path if path.is_absolute() else REPO_ROOT / path


DEFAULT_KEY_TEXT = env_text(
    "AES_XTS_KEY",
    "1234567891234567891234567891234567891234567891234567891234567891",
)
DEFAULT_INPUT_PATH = env_path("AES_XTS_INPUT_PATH", SCRIPT_DIR / "file_to_encrypt")


def parse_key(key_text):
    key = key_text.encode("utf-8")
    if len(key) not in (32, 64):
        raise argparse.ArgumentTypeError(
            "AES-XTS key must be 32 bytes for AES-128-XTS or "
            "64 bytes for AES-256-XTS after UTF-8 encoding."
        )

    midpoint = len(key) // 2
    if key[:midpoint] == key[midpoint:]:
        raise argparse.ArgumentTypeError(
            "AES-XTS requires two different key halves."
        )
    return key


def load_cryptography():
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes, hmac
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    except ModuleNotFoundError as exc:
        if exc.name == "cryptography":
            raise RuntimeError(
                "Missing dependency 'cryptography'. Install it with "
                "'python3 -m pip install -r crypto.requirements.txt'."
            ) from exc
        raise

    return Cipher, algorithms, modes, hashes, hmac, HKDF, InvalidSignature


def default_encrypt_output(input_path):
    return input_path.with_name(f"{input_path.name}.xts.aes")


def default_decrypt_output(input_path):
    name = input_path.name
    if name.endswith(".xts.aes"):
        name = name[: -len(".xts.aes")]
    elif name.endswith(".aes"):
        name = name[: -len(".aes")]
    return input_path.with_name(f"{name}_decrypted")


def create_archive_bytes(input_path):
    archive_buffer = io.BytesIO()
    with tarfile.open(fileobj=archive_buffer, mode="w") as archive:
        archive.add(input_path, arcname=input_path.name, recursive=True)
    return archive_buffer.getvalue()


def is_relative_to(path, parent):
    try:
        path.relative_to(parent)
    except ValueError:
        return False
    return True


def validate_encrypt_paths(input_path, output_path):
    input_root = input_path.resolve()
    output_target = output_path.resolve(strict=False)

    if output_target == input_root:
        raise ValueError("encrypted output path must be different from input path")

    if input_path.is_dir() and is_relative_to(output_target, input_root):
        raise ValueError("encrypted output path must be outside the input folder")


def derive_mac_key(xts_key, salt, hashes, HKDF):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"aes-xts-archive-v1 mac",
    ).derive(xts_key)


def sign_container(header, ciphertext, xts_key, salt, hashes, hmac, HKDF):
    mac_key = derive_mac_key(xts_key, salt, hashes, HKDF)
    signer = hmac.HMAC(mac_key, hashes.SHA256())
    signer.update(header)
    signer.update(ciphertext)
    return signer.finalize()


def verify_container(header, ciphertext, tag, xts_key, salt, hashes, hmac, HKDF):
    mac_key = derive_mac_key(xts_key, salt, hashes, HKDF)
    verifier = hmac.HMAC(mac_key, hashes.SHA256())
    verifier.update(header)
    verifier.update(ciphertext)
    verifier.verify(tag)


def sector_tweak(base_tweak, sector_index):
    tweak_value = int.from_bytes(base_tweak, "little")
    tweak_value = (tweak_value + sector_index) % (1 << 128)
    return tweak_value.to_bytes(16, "little")


def crypt_sector(data, key, tweak, decrypt, Cipher, algorithms, modes):
    cipher = Cipher(algorithms.AES(key), modes.XTS(tweak))
    context = cipher.decryptor() if decrypt else cipher.encryptor()
    return context.update(data) + context.finalize()


def crypt_sectors(data, key, base_tweak, sector_size, decrypt, Cipher, algorithms, modes):
    result = bytearray()
    for sector_index, offset in enumerate(range(0, len(data), sector_size)):
        sector = data[offset : offset + sector_size]
        if not sector:
            continue
        tweak = sector_tweak(base_tweak, sector_index)
        result.extend(crypt_sector(sector, key, tweak, decrypt, Cipher, algorithms, modes))
    return bytes(result)


def encrypt_path(input_path, output_path, key, sector_size):
    Cipher, algorithms, modes, hashes, hmac, HKDF, _ = load_cryptography()
    archive_bytes = create_archive_bytes(input_path)
    salt = os.urandom(16)
    base_tweak = os.urandom(16)
    ciphertext = crypt_sectors(
        archive_bytes,
        key,
        base_tweak,
        sector_size,
        decrypt=False,
        Cipher=Cipher,
        algorithms=algorithms,
        modes=modes,
    )
    header = HEADER.pack(MAGIC, sector_size, salt, base_tweak, len(archive_bytes))
    tag = sign_container(header, ciphertext, key, salt, hashes, hmac, HKDF)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(header + ciphertext + tag)
    return len(archive_bytes)


def validate_archive_member(member, output_dir):
    member_path = Path(member.name)
    if member_path.is_absolute():
        raise ValueError(f"archive member uses an absolute path: {member.name}")

    output_root = output_dir.resolve()
    target_path = (output_root / member_path).resolve(strict=False)
    if not is_relative_to(target_path, output_root):
        raise ValueError(f"archive member escapes output directory: {member.name}")

    if member.issym() or member.islnk():
        link_path = Path(member.linkname)
        if link_path.is_absolute():
            raise ValueError(f"archive link uses an absolute target: {member.name}")
        link_target = (target_path.parent / link_path).resolve(strict=False)
        if not is_relative_to(link_target, output_root):
            raise ValueError(f"archive link escapes output directory: {member.name}")


def extract_archive_bytes(archive_bytes, output_dir):
    output_dir.mkdir(parents=True, exist_ok=True)
    output_root = output_dir.resolve()

    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:*") as archive:
        members = archive.getmembers()
        for member in members:
            validate_archive_member(member, output_root)

        try:
            archive.extractall(output_root, members=members, filter="data")
        except TypeError:
            archive.extractall(output_root, members=members)


def decrypt_archive(input_path, output_dir, key):
    Cipher, algorithms, modes, hashes, hmac, HKDF, InvalidSignature = load_cryptography()
    payload = input_path.read_bytes()
    minimum_size = HEADER.size + HMAC_SIZE
    if len(payload) < minimum_size:
        raise ValueError("encrypted archive is too short to contain header and HMAC.")

    header = payload[: HEADER.size]
    tag = payload[-HMAC_SIZE:]
    ciphertext = payload[HEADER.size : -HMAC_SIZE]

    magic, sector_size, salt, base_tweak, archive_size = HEADER.unpack(header)
    if magic != MAGIC:
        raise ValueError("input is not an AES-XTS archive created by this script.")

    if sector_size < 16:
        raise ValueError("invalid sector size in encrypted archive.")

    if len(ciphertext) != archive_size:
        raise ValueError("encrypted archive size does not match its header.")

    try:
        verify_container(header, ciphertext, tag, key, salt, hashes, hmac, HKDF)
    except InvalidSignature as exc:
        raise ValueError("HMAC verification failed. Wrong key or corrupted archive.") from exc

    archive_bytes = crypt_sectors(
        ciphertext,
        key,
        base_tweak,
        sector_size,
        decrypt=True,
        Cipher=Cipher,
        algorithms=algorithms,
        modes=modes,
    )
    extract_archive_bytes(archive_bytes, output_dir)
    return len(archive_bytes)


def build_parser():
    parser = argparse.ArgumentParser(
        description="Encrypt or decrypt complete files and folders with AES-XTS."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    encrypt_parser = subparsers.add_parser(
        "encrypt", help="Encrypt a file or folder as an AES-XTS archive."
    )
    encrypt_parser.add_argument(
        "input_path",
        nargs="?",
        type=Path,
        default=DEFAULT_INPUT_PATH,
        help=f"File or folder to encrypt. Default: {DEFAULT_INPUT_PATH.name}",
    )
    encrypt_parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Encrypted output path. Default: INPUT.xts.aes",
    )
    encrypt_parser.add_argument(
        "-k",
        "--key",
        default=DEFAULT_KEY_TEXT,
        type=parse_key,
        help=(
            "AES-XTS key text. Must encode to 32 bytes for AES-128-XTS "
            "or 64 bytes for AES-256-XTS."
        ),
    )
    encrypt_parser.add_argument(
        "--sector-size",
        type=int,
        default=DEFAULT_SECTOR_SIZE,
        help=f"XTS sector size in bytes. Default: {DEFAULT_SECTOR_SIZE}",
    )

    decrypt_parser = subparsers.add_parser(
        "decrypt", help="Decrypt and extract an AES-XTS archive."
    )
    decrypt_parser.add_argument("input_path", type=Path, help="Encrypted archive path.")
    decrypt_parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Directory to extract into. Default: encrypted-name_decrypted",
    )
    decrypt_parser.add_argument(
        "-k",
        "--key",
        default=DEFAULT_KEY_TEXT,
        type=parse_key,
        help=(
            "AES-XTS key text. Must encode to 32 bytes for AES-128-XTS "
            "or 64 bytes for AES-256-XTS."
        ),
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.command == "encrypt":
            if not args.input_path.exists():
                parser.error(f"input path not found: {args.input_path}")

            if args.sector_size < 16:
                parser.error("--sector-size must be at least 16 bytes")

            output_path = args.output or default_encrypt_output(args.input_path)
            validate_encrypt_paths(args.input_path, output_path)
            archive_size = encrypt_path(
                args.input_path,
                output_path,
                args.key,
                args.sector_size,
            )
            print(
                f"Encrypted {args.input_path} into {output_path} "
                f"with AES-XTS ({archive_size} archived bytes)."
            )
            return 0

        if not args.input_path.is_file():
            parser.error(f"encrypted archive not found: {args.input_path}")

        output_dir = args.output or default_decrypt_output(args.input_path)
        archive_size = decrypt_archive(args.input_path, output_dir, args.key)
        print(
            f"Decrypted {args.input_path} into {output_dir} "
            f"({archive_size} archived bytes)."
        )
        return 0
    except RuntimeError as exc:
        parser.exit(status=1, message=f"{exc}\n")
    except (ValueError, tarfile.TarError) as exc:
        print(f"Unable to process archive: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
