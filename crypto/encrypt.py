from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from crypto.key_manager import load_key
from crypto.key_registry import KeyRegistry
from crypto.key_rotation import get_current_key_id
from crypto.file_format import (
    create_header,
    NONCE_SIZE,
    TAG_SIZE
)

REGISTRY_PATH = Path("keys/registry.json")

CHUNK_SIZE = 1024 * 1024  # 1 MB


def encrypt_file(input_path, output_path):
    input_path = Path(input_path)
    output_path = Path(output_path)

    # -----------------------------
    # Validate input
    # -----------------------------
    if not input_path.exists():
        raise FileNotFoundError(
            f"Input file not found: {input_path}"
        )

    if input_path.is_symlink():
        raise ValueError(
            "Symbolic links are not allowed."
        )

    if not input_path.is_file():
        raise ValueError(
            f"Input is not a regular file: {input_path}"
        )

    # -----------------------------
    # Get current encryption key
    # -----------------------------
    key_id = get_current_key_id()

    print(f"Key ID: {key_id.hex()}")

    registry = KeyRegistry(REGISTRY_PATH)

    if not registry.can_encrypt(key_id):
        status = registry.get_status(key_id)

        raise PermissionError(
            "Encryption denied: current key "
            f"{key_id.hex()} has status "
            f"{status}."
        )

    key_path = registry.get_key_path(key_id)
    key = load_key(key_path)

    # -----------------------------
    # Create authenticated header
    # -----------------------------
    header = create_header(key_id)

    # -----------------------------
    # Generate random nonce
    # -----------------------------
    nonce = get_random_bytes(NONCE_SIZE)

    # -----------------------------
    # Create AES-GCM cipher
    # -----------------------------
    cipher = AES.new(
        key,
        AES.MODE_GCM,
        nonce=nonce
    )

    # Header is authenticated as AAD
    cipher.update(header)

    # -----------------------------
    # Prepare output directory
    # -----------------------------
    output_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    # -----------------------------
    # Streaming encryption
    # -----------------------------
    with open(input_path, "rb") as input_file:

        # Write header and nonce first
        with open(output_path, "wb") as output_file:

            output_file.write(header)
            output_file.write(nonce)

            while True:

                chunk = input_file.read(CHUNK_SIZE)

                if not chunk:
                    break

                encrypted_chunk = cipher.encrypt(chunk)

                output_file.write(encrypted_chunk)

            # Final authentication tag
            tag = cipher.digest()

            if len(tag) != TAG_SIZE:
                raise RuntimeError(
                    "Invalid authentication tag size."
                )

            output_file.write(tag)

    print("Encryption successful.")
    print(f"Input : {input_path}")
    print(f"Output: {output_path}")
    print(f"Key ID: {key_id.hex()}")


if __name__ == "__main__":
    encrypt_file(
        "data/original.txt",
        "data/encrypted.bin"
    )