#!/usr/bin/env python3
"""Reassemble and decrypt data produced by encrypt.py."""

import argparse
import base64
import json
from pathlib import Path
from typing import List

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PBKDF2_ITERATIONS = 390000
NONCE_SIZE = 12
TAG_SIZE = 16
READ_BLOCK_SIZE = 1024 * 1024


def derive_key(password: str, salt: bytes, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def load_metadata(folder_path: Path) -> dict:
    metadata_path = folder_path / "metadata.json"
    if not metadata_path.is_file():
        raise FileNotFoundError(f"Missing metadata.json in {folder_path}")
    return json.loads(metadata_path.read_text())


def join_chunks(folder_path: Path, chunk_names: List[str], output_path: Path) -> None:
    with output_path.open("wb") as dest:
        for chunk_name in chunk_names:
            chunk_path = folder_path / chunk_name
            if not chunk_path.is_file():
                raise FileNotFoundError(f"Missing chunk: {chunk_path}")
            with chunk_path.open("rb") as src:
                while True:
                    chunk = src.read(READ_BLOCK_SIZE)
                    if not chunk:
                        break
                    dest.write(chunk)


def decrypt_filename(folder_path: Path, key: bytes) -> str:
    try:
        payload = bytes.fromhex(folder_path.name)
    except ValueError as exc:
        raise ValueError("Folder name is not valid hexadecimal data") from exc

    if len(payload) < NONCE_SIZE + TAG_SIZE:
        raise ValueError("Encrypted filename payload is too short")

    nonce = payload[:NONCE_SIZE]
    tag = payload[NONCE_SIZE : NONCE_SIZE + TAG_SIZE]
    ciphertext = payload[NONCE_SIZE + TAG_SIZE :]
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode("utf-8")


def decrypt_file(
    encrypted_path: Path,
    output_path: Path,
    key: bytes,
    nonce: bytes,
    tag: bytes,
) -> None:
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()

    try:
        with encrypted_path.open("rb") as src, output_path.open("wb") as dest:
            while True:
                chunk = src.read(READ_BLOCK_SIZE)
                if not chunk:
                    break
                dest.write(decryptor.update(chunk))
            dest.write(decryptor.finalize())
    except InvalidTag as exc:
        output_path.unlink(missing_ok=True)
        raise InvalidTag("Decryption failed: authentication tag mismatch") from exc


def decrypt_folder(folder_path: Path, password: str) -> Path:
    if not folder_path.is_dir():
        raise NotADirectoryError(f"Folder does not exist: {folder_path}")

    metadata = load_metadata(folder_path)
    salt = base64.b64decode(metadata["salt"])
    iterations = metadata.get("kdf_iterations", PBKDF2_ITERATIONS)
    key = derive_key(password, salt, iterations)

    chunk_names = metadata.get("chunks")
    if not chunk_names:
        chunk_names = sorted(
            p.name for p in folder_path.glob("part_*.bin") if p.is_file()
        )
        if not chunk_names:
            raise FileNotFoundError("No encrypted chunks found")

    joined_path = folder_path / "_joined.enc"
    join_chunks(folder_path, chunk_names, joined_path)

    original_filename = decrypt_filename(folder_path, key)
    output_path = folder_path.parent / original_filename
    if output_path.exists():
        joined_path.unlink(missing_ok=True)
        raise FileExistsError(
            f"Cannot write decrypted output, file already exists: {output_path}"
        )

    renamed_path = folder_path / original_filename
    if renamed_path.exists():
        # A previous run already joined and renamed the encrypted payload.
        joined_path.unlink(missing_ok=True)
        encrypted_source = renamed_path
    else:
        joined_path.rename(renamed_path)
        encrypted_source = renamed_path

    file_nonce = base64.b64decode(metadata["file_nonce"])
    file_tag = base64.b64decode(metadata["file_tag"])

    decrypt_file(encrypted_source, output_path, key, file_nonce, file_tag)
    return output_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Decrypt folders produced by encrypt.py")
    parser.add_argument(
        "-F",
        "--folder-path",
        type=Path,
        required=True,
        help="Folder containing encrypted chunks",
    )
    parser.add_argument(
        "-p",
        "--password",
        type=str,
        required=True,
        help="Password used during encryption",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_path = decrypt_folder(args.folder_path, args.password)
    print(f"Decrypted file available at: {output_path}")


if __name__ == "__main__":
    main()
