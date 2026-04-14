import argparse
import io
import os
import sys
import tarfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
TAG_SIZE = 16
NONCE_SIZE = 15


def env_text(name, default):
    return os.environ.get(name, default)


def env_path(name, default):
    value = os.environ.get(name)
    if value is None:
        return default

    path = Path(value)
    return path if path.is_absolute() else REPO_ROOT / path


DEFAULT_KEY_TEXT = env_text("AES_KEY", "1234567891234567")
DEFAULT_INPUT_PATH = env_path("AES_ARCHIVE_INPUT_PATH", SCRIPT_DIR / "file_to_encrypt")


def parse_key(key_text):
    key = key_text.encode("utf-8")
    if len(key) not in (16, 24, 32):
        raise argparse.ArgumentTypeError(
            "AES key must be 16, 24, or 32 bytes after UTF-8 encoding."
        )
    return key


def load_aes_module():
    try:
        from Crypto.Cipher import AES
    except ModuleNotFoundError as exc:
        if exc.name == "Crypto":
            raise RuntimeError(
                "Missing dependency 'pycryptodome'. Install it with "
                "'python3 -m pip install -r crypto.requirements.txt'."
            ) from exc
        raise
    return AES


def default_encrypt_output(input_path):
    return input_path.with_name(f"{input_path.name}.aes")


def default_decrypt_output(input_path):
    name = input_path.name
    if name.endswith(".aes"):
        name = name[: -len(".aes")]
    return input_path.with_name(f"{name}_decrypted")


def create_archive_bytes(input_path):
    archive_buffer = io.BytesIO()
    with tarfile.open(fileobj=archive_buffer, mode="w") as archive:
        archive.add(input_path, arcname=input_path.name, recursive=True)
    return archive_buffer.getvalue()


def encrypt_path(input_path, output_path, key):
    aes_module = load_aes_module()
    archive_bytes = create_archive_bytes(input_path)
    cipher = aes_module.new(key, aes_module.MODE_OCB)
    ciphertext, tag = cipher.encrypt_and_digest(archive_bytes)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(tag + cipher.nonce + ciphertext)
    return len(archive_bytes)


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
    aes_module = load_aes_module()
    encrypted_payload = input_path.read_bytes()
    if len(encrypted_payload) < TAG_SIZE + NONCE_SIZE:
        raise ValueError("Encrypted archive is too short to contain tag and nonce.")

    tag = encrypted_payload[:TAG_SIZE]
    nonce = encrypted_payload[TAG_SIZE : TAG_SIZE + NONCE_SIZE]
    ciphertext = encrypted_payload[TAG_SIZE + NONCE_SIZE :]

    cipher = aes_module.new(key, aes_module.MODE_OCB, nonce=nonce)
    archive_bytes = cipher.decrypt_and_verify(ciphertext, tag)
    extract_archive_bytes(archive_bytes, output_dir)
    return len(archive_bytes)


def build_parser():
    parser = argparse.ArgumentParser(
        description="Encrypt or decrypt complete files and folders with AES-OCB."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    encrypt_parser = subparsers.add_parser(
        "encrypt", help="Encrypt a file or folder as an AES-OCB archive."
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
        help="Encrypted output path. Default: INPUT.aes",
    )
    encrypt_parser.add_argument(
        "-k",
        "--key",
        default=DEFAULT_KEY_TEXT,
        type=parse_key,
        help="AES key text. Must encode to 16, 24, or 32 bytes.",
    )

    decrypt_parser = subparsers.add_parser(
        "decrypt", help="Decrypt and extract an AES-OCB archive."
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
        help="AES key text. Must encode to 16, 24, or 32 bytes.",
    )
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.command == "encrypt":
            if not args.input_path.exists():
                parser.error(f"input path not found: {args.input_path}")

            output_path = args.output or default_encrypt_output(args.input_path)
            validate_encrypt_paths(args.input_path, output_path)
            archive_size = encrypt_path(args.input_path, output_path, args.key)
            print(
                f"Encrypted {args.input_path} into {output_path} "
                f"({archive_size} archived bytes)."
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
