from pathlib import Path
from Crypto.Random import get_random_bytes


KEY_SIZE = 32
KEY_PERMISSIONS = 0o600


def generate_key():
    """
    Generate a cryptographically secure 256-bit AES key.
    """
    return get_random_bytes(KEY_SIZE)


def save_key(key, key_path):
    """
    Save an AES-256 key securely.
    """

    if not isinstance(key, bytes):
        raise TypeError("Key must be bytes.")

    if len(key) != KEY_SIZE:
        raise ValueError(
            "Invalid AES-256 key. "
            "Key must be exactly 32 bytes."
        )

    key_path = Path(key_path)

    key_path.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    if key_path.is_symlink():
        raise ValueError(
            "Refusing to write through a symbolic link."
        )

    with open(key_path, "wb") as file:
        file.write(key)

    # Owner: read + write
    # Group: no access
    # Others: no access
    key_path.chmod(KEY_PERMISSIONS)


def load_key(key_path):
    """
    Load and validate an AES-256 key.
    """

    key_path = Path(key_path)

    if not key_path.exists():
        raise FileNotFoundError(
            f"Key file not found: {key_path}"
        )

    if key_path.is_symlink():
        raise ValueError(
            "Refusing to load key through a symbolic link."
        )

    if not key_path.is_file():
        raise ValueError(
            f"Key path is not a regular file: {key_path}"
        )

    with open(key_path, "rb") as file:
        key = file.read()

    if len(key) != KEY_SIZE:
        raise ValueError(
            "Invalid AES-256 key. "
            "Key must be exactly 32 bytes."
        )

    return key


def initialize_key(key_path):
    """
    Initialize the AES-256 encryption key.

    If the key already exists, validate and return it.
    If it does not exist, generate and securely save a new key.
    """

    key_path = Path(key_path)

    if key_path.exists():

        print("Encryption key already exists.")

        key = load_key(key_path)

        print("Existing key validated.")

        return key

    print("No encryption key found.")
    print("Generating new AES-256 key...")

    key = generate_key()

    save_key(
        key,
        key_path
    )

    print("New encryption key created.")
    print(f"Key location: {key_path}")

    return key