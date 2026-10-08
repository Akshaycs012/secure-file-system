import hashlib
from pathlib import Path


CHUNK_SIZE = 1024 * 1024  # 1 MB


def calculate_file_hash(file_path):
    """
    Calculate the SHA-256 hash of a file.
    """

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(
            f"File not found: {file_path}"
        )

    if not path.is_file():
        raise ValueError(
            f"Not a regular file: {file_path}"
        )

    sha256 = hashlib.sha256()

    with open(path, "rb") as file:

        while True:

            chunk = file.read(CHUNK_SIZE)

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest()