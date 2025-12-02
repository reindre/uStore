#!/usr/bin/env python3
"""Encrypt a file and its filename, emitting 10 MB chunks."""

import argparse
import base64
import json
import os
import shutil
from pathlib import Path
from typing import List, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PBKDF2_ITERATIONS = 390000
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
PIECE_SIZE = 10 * 1024 * 1024  # 10 MB pieces
READ_BLOCK_SIZE = 1024 * 1024  # 1 MB streaming blocks


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def aes_gcm_encrypt_bytes(key: bytes, data: bytes) -> Tuple[bytes, bytes, bytes]:
    nonce = os.urandom(NONCE_SIZE)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return nonce, ciphertext, encryptor.tag


def stream_encrypt_file(
    source_path: Path,
    destination_folder: Path,
    key: bytes,
    nonce: bytes,
    piece_size: int,
) -> Tuple[bytes, List[str], int]:
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()

    piece_index = 0
    chunk_files: List[str] = []
    bytes_in_piece = 0
    total_cipher_bytes = 0

    def new_piece_handle(idx: int):
        path = destination_folder / f"part_{idx:05d}.bin"
        chunk_files.append(path.name)
        return open(path, "wb")

    current_handle = new_piece_handle(piece_index)

    with source_path.open("rb") as src:
        while True:
            chunk = src.read(READ_BLOCK_SIZE)
            if not chunk:
                break
            encrypted_chunk = encryptor.update(chunk)
            total_cipher_bytes += len(encrypted_chunk)
            offset = 0
            while offset < len(encrypted_chunk):
                space_left = piece_size - bytes_in_piece
                to_write = min(space_left, len(encrypted_chunk) - offset)
                current_handle.write(encrypted_chunk[offset : offset + to_write])
                bytes_in_piece += to_write
                offset += to_write
                if bytes_in_piece == piece_size:
                    current_handle.close()
                    piece_index += 1
                    current_handle = new_piece_handle(piece_index)
                    bytes_in_piece = 0

    final_bytes = encryptor.finalize()
    if final_bytes:
        total_cipher_bytes += len(final_bytes)
        offset = 0
        while offset < len(final_bytes):
            space_left = piece_size - bytes_in_piece
            to_write = min(space_left, len(final_bytes) - offset)
            current_handle.write(final_bytes[offset : offset + to_write])
            bytes_in_piece += to_write
            offset += to_write
            if bytes_in_piece == piece_size:
                current_handle.close()
                piece_index += 1
                current_handle = new_piece_handle(piece_index)
                bytes_in_piece = 0

    # Ensure at least one piece exists even for empty inputs.
    if piece_index == 0 and chunk_files and bytes_in_piece == 0:
        current_handle.flush()

    current_handle.close()
    return encryptor.tag, chunk_files, total_cipher_bytes


def encrypt(file_path: Path, password: str, piece_size: int = PIECE_SIZE) -> Path:
    if not file_path.is_file():
        raise FileNotFoundError(f"File does not exist: {file_path}")

    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    filename_nonce, filename_ciphertext, filename_tag = aes_gcm_encrypt_bytes(
        key, file_path.name.encode("utf-8")
    )

    folder_payload = filename_nonce + filename_tag + filename_ciphertext
    folder_name = folder_payload.hex()
    folder_path = file_path.parent / folder_name
    folder_path.mkdir(parents=False, exist_ok=False)

    metadata_path = folder_path / "metadata.json"
    try:
        file_nonce = os.urandom(NONCE_SIZE)
        file_tag, chunk_files, total_cipher_bytes = stream_encrypt_file(
            file_path, folder_path, key, file_nonce, piece_size
        )

        metadata = {
            "version": 1,
            "kdf": "pbkdf2_sha256",
            "kdf_iterations": PBKDF2_ITERATIONS,
            "salt": base64.b64encode(salt).decode("ascii"),
            "piece_size": piece_size,
            "chunks": chunk_files,
            "file_nonce": base64.b64encode(file_nonce).decode("ascii"),
            "file_tag": base64.b64encode(file_tag).decode("ascii"),
            "original_size": file_path.stat().st_size,
            "cipher_size": total_cipher_bytes,
            "read_block_size": READ_BLOCK_SIZE,
        }
        metadata_path.write_text(json.dumps(metadata, indent=2))
    except Exception:
        shutil.rmtree(folder_path)
        raise

    return folder_path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Encrypt files and filenames")
    parser.add_argument(
        "-F",
        "--file-path",
        type=Path,
        required=True,
        help="Path to the file that should be encrypted",
    )
    parser.add_argument(
        "-p",
        "--password",
        type=str,
        required=True,
        help="Password used to derive the AES key",
    )
    parser.add_argument(
        "--piece-size",
        type=int,
        default=PIECE_SIZE,
        help="Size of each encrypted piece in bytes (default: 10MB)",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    folder_path = encrypt(args.file_path, args.password, args.piece_size)
    print(f"Encrypted data stored in: {folder_path}")


if __name__ == "__main__":
    main()
