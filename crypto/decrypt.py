from pathlib import Path

from Crypto.Cipher import AES

from crypto.key_manager import load_key
from crypto.key_registry import KeyRegistry
from crypto.file_format import (
    HEADER_SIZE,
    parse_header
)

REGISTRY_FILE = Path("keys/registry.json")

CHUNK_SIZE = 1024 * 1024  # 1 MB


def decrypt_file(input_path, output_path):
    input_path = Path(input_path)
    output_path = Path(output_path)

    if not input_path.exists():
        raise FileNotFoundError(
            f"Encrypted file not found: {input_path}"
        )

    if input_path.is_symlink():
        raise ValueError(
            "Refusing to decrypt a symbolic link."
        )

    if not input_path.is_file():
        raise ValueError(
            f"Not a regular file: {input_path}"
        )

    temporary_path = output_path.with_suffix(
        output_path.suffix + ".tmp"
    )

    if temporary_path.exists():
        temporary_path.unlink()

    try:
        with open(input_path, "rb") as file:

            header = file.read(HEADER_SIZE)

            metadata = parse_header(header)

            nonce_size = metadata["nonce_size"]
            tag_size = metadata["tag_size"]
            key_id = metadata["key_id"]

            print(f"Key ID: {key_id.hex()}")

            nonce = file.read(nonce_size)

            if len(nonce) != nonce_size:
                raise ValueError(
                    "Invalid encrypted file: "
                    "nonce is missing."
                )

            file.seek(0, 2)
            file_size = file.tell()

            ciphertext_start = (
                HEADER_SIZE + nonce_size
            )

            ciphertext_size = (
                file_size
                - ciphertext_start
                - tag_size
            )

            if ciphertext_size <= 0:
                raise ValueError(
                    "Invalid encrypted file: "
                    "ciphertext is empty."
                )

            file.seek(file_size - tag_size)

            tag = file.read(tag_size)

            if len(tag) != tag_size:
                raise ValueError(
                    "Invalid encrypted file: "
                    "authentication tag is missing."
                )

            file.seek(ciphertext_start)

            registry = KeyRegistry(REGISTRY_FILE)

            try:
                key_path = registry.get_key_path(key_id)
            except KeyError:
                raise ValueError(
                    "Decryption failed: encryption key "
                    "is not registered for Key ID "
                    f"{key_id.hex()}."
                )

            if not registry.can_decrypt(key_id):
                status = registry.get_status(key_id)

                raise PermissionError(
                    "Decryption denied: key "
                    f"{key_id.hex()} has status "
                    f"{status}."
                )

            print(f"Key found: {key_path}")

            key = load_key(key_path)

            cipher = AES.new(
                key,
                AES.MODE_GCM,
                nonce=nonce
            )

            cipher.update(header)

            output_path.parent.mkdir(
                parents=True,
                exist_ok=True
            )

            with open(temporary_path, "wb") as output_file:

                remaining = ciphertext_size

                while remaining > 0:

                    chunk_size = min(
                        CHUNK_SIZE,
                        remaining
                    )

                    encrypted_chunk = file.read(
                        chunk_size
                    )

                    if len(encrypted_chunk) != chunk_size:
                        raise ValueError(
                            "Invalid encrypted file: "
                            "ciphertext is truncated."
                        )

                    plaintext_chunk = cipher.decrypt(
                        encrypted_chunk
                    )

                    output_file.write(
                        plaintext_chunk
                    )

                    remaining -= chunk_size

                # Authenticate the complete ciphertext
                cipher.verify(tag)

        # Authentication succeeded.
        # Only now expose plaintext as the final output.
        temporary_path.replace(output_path)

    except ValueError:
        if temporary_path.exists():
            temporary_path.unlink()

        raise ValueError(
            "Decryption failed: file is corrupted, "
            "has been modified, or the encryption key "
            "is incorrect."
        )

    except Exception:
        if temporary_path.exists():
            temporary_path.unlink()

        raise

    print("Decryption successful.")
    print(f"Input : {input_path}")
    print(f"Output: {output_path}")