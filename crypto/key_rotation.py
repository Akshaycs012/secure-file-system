from pathlib import Path
import sys

from crypto.key_manager import (
    generate_key,
    save_key,
    load_key,
    KEY_SIZE
)

from crypto.key_registry import (
    KeyRegistry,
    generate_key_id
)


# --------------------------------------------------
# Paths
# --------------------------------------------------

KEYS_DIR = Path("keys")

CURRENT_KEY_FILE = KEYS_DIR / "current_key_id"

REGISTRY_PATH = KEYS_DIR / "registry.json"


# --------------------------------------------------
# Initialize encryption key
# --------------------------------------------------

def initialize_key():
    """
    Initialize the active encryption key.

    If an active key already exists:
        - Validate it
        - Preserve it

    If no active key exists:
        - Generate a new AES-256 key
        - Generate its Key ID
        - Save the key
        - Register the key
        - Make it the active key
    """

    print("Initializing encryption key...")

    KEYS_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    # --------------------------------------------------
    # Check whether an active key already exists
    # --------------------------------------------------

    if CURRENT_KEY_FILE.exists():

        key_id_hex = CURRENT_KEY_FILE.read_text(
            encoding="utf-8"
        ).strip()

        if len(key_id_hex) != 32:
            raise ValueError(
                "Invalid current key ID."
            )

        try:
            key_id = bytes.fromhex(
                key_id_hex
            )

        except ValueError:
            raise ValueError(
                "Current key ID is not valid hexadecimal."
            )

        if len(key_id) != 16:
            raise ValueError(
                "Current key ID must be exactly 16 bytes."
            )

        # --------------------------------------------------
        # Find key in registry
        # --------------------------------------------------

        registry = KeyRegistry(
            REGISTRY_PATH
        )

        key_path = registry.get_key_path(
            key_id
        )

        # --------------------------------------------------
        # Validate key
        # --------------------------------------------------

        key = load_key(
            key_path
        )

        if len(key) != KEY_SIZE:
            raise ValueError(
                "Active key is not a valid AES-256 key."
            )

        # --------------------------------------------------
        # Verify Key ID matches actual key
        # --------------------------------------------------

        calculated_key_id = generate_key_id(
            key
        )

        if calculated_key_id != key_id:
            raise ValueError(
                "Active key ID does not match the actual key."
            )

        print(
            f"Current Key ID: {key_id.hex()}"
        )

        return key_id

    # --------------------------------------------------
    # No active key exists
    # --------------------------------------------------

    print(
        "No encryption key found."
    )

    print(
        "Generating new AES-256 key..."
    )

    # Generate random AES-256 key
    key = generate_key()

    # Generate deterministic Key ID
    key_id = generate_key_id(
        key
    )

    # Key filename uses Key ID
    key_path = KEYS_DIR / (
        f"{key_id.hex()}.key"
    )

    # Save key
    save_key(
        key,
        key_path
    )

    # Register key
    registry = KeyRegistry(
        REGISTRY_PATH
    )

    registry.register_key(
        key_id,
        key_path
    )

    # Make this key active
    CURRENT_KEY_FILE.write_text(
        key_id.hex(),
        encoding="utf-8"
    )

    print(
        "New encryption key created."
    )

    print(
        f"Key ID: {key_id.hex()}"
    )

    print(
        f"Key file: {key_path}"
    )

    return key_id


# --------------------------------------------------
# Get current active key ID
# --------------------------------------------------

def get_current_key_id():
    """
    Return the ID of the currently active encryption key.

    If no active key exists, initialize one.
    """

    # --------------------------------------------------
    # No current key -> initialize
    # --------------------------------------------------

    if not CURRENT_KEY_FILE.exists():
        return initialize_key()

    # --------------------------------------------------
    # Read current Key ID
    # --------------------------------------------------

    key_id_hex = CURRENT_KEY_FILE.read_text(
        encoding="utf-8"
    ).strip()

    if len(key_id_hex) != 32:
        raise ValueError(
            "Invalid current key ID."
        )

    try:
        key_id = bytes.fromhex(
            key_id_hex
        )

    except ValueError:
        raise ValueError(
            "Current key ID is not valid hexadecimal."
        )

    if len(key_id) != 16:
        raise ValueError(
            "Current key ID must be exactly 16 bytes."
        )

    # --------------------------------------------------
    # Find key in registry
    # --------------------------------------------------

    registry = KeyRegistry(
        REGISTRY_PATH
    )

    key_path = registry.get_key_path(
        key_id
    )

    # --------------------------------------------------
    # Validate actual key
    # --------------------------------------------------

    key = load_key(
        key_path
    )

    if len(key) != KEY_SIZE:
        raise ValueError(
            "Current encryption key is invalid."
        )

    # --------------------------------------------------
    # Verify Key ID matches actual key
    # --------------------------------------------------

    calculated_key_id = generate_key_id(
        key
    )

    if calculated_key_id != key_id:
        raise ValueError(
            "Current key ID does not match the actual key."
        )

    return key_id


# --------------------------------------------------
# Rotate encryption key
# --------------------------------------------------

def rotate_key():
    """
    Generate a completely new AES-256 key
    and make it the active encryption key.

    Existing keys are preserved so old encrypted
    files can still be decrypted.
    """

    print(
        "Rotating encryption key..."
    )

    KEYS_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    # --------------------------------------------------
    # Get old active key
    # --------------------------------------------------

    old_key_id = None

    if CURRENT_KEY_FILE.exists():

        old_key_id = get_current_key_id()

        print(
            f"Old Key ID: {old_key_id.hex()}"
        )

    # --------------------------------------------------
    # Generate NEW AES-256 key
    # --------------------------------------------------

    new_key = generate_key()

    # --------------------------------------------------
    # Generate NEW Key ID
    # --------------------------------------------------

    new_key_id = generate_key_id(
        new_key
    )

    # --------------------------------------------------
    # Extremely unlikely collision protection
    # --------------------------------------------------

    if old_key_id is not None:

        if new_key_id == old_key_id:
            raise RuntimeError(
                "Generated key ID is identical to "
                "the current key ID."
            )

    # --------------------------------------------------
    # Create new key path
    # --------------------------------------------------

    new_key_path = KEYS_DIR / (
        f"{new_key_id.hex()}.key"
    )

    # --------------------------------------------------
    # Save new key
    # --------------------------------------------------

    save_key(
        new_key,
        new_key_path
    )

    # --------------------------------------------------
    # Register new key
    # --------------------------------------------------

    registry = KeyRegistry(
        REGISTRY_PATH
    )

    # Register the new key as ACTIVE
    registry.register_key(
        new_key_id,
        new_key_path,
        status="ACTIVE"
    )

    # --------------------------------------------------
    # Make new key active
    # --------------------------------------------------

    # The previous active key is now retired
    if old_key_id is not None:
        registry.retire_key(old_key_id)

    # Make the new key the current encryption key
    CURRENT_KEY_FILE.write_text(
        new_key_id.hex(),
        encoding="utf-8"
    )

    # --------------------------------------------------
    # Output
    # --------------------------------------------------

    print(
        "New encryption key created."
    )

    print(
        f"Key ID: {new_key_id.hex()}"
    )

    print(
        f"Key file: {new_key_path}"
    )

    print(
        f"Current Key ID: {new_key_id.hex()}"
    )

    return new_key_id


# --------------------------------------------------
# Command-line execution
# --------------------------------------------------

if __name__ == "__main__":

    if len(sys.argv) > 1:

        command = sys.argv[1].lower()

        if command == "rotate":

            rotate_key()

        elif command == "initialize":

            initialize_key()

        else:

            print(
                "Usage:"
            )

            print(
                "  python -m crypto.key_rotation"
            )

            print(
                "  python -m crypto.key_rotation initialize"
            )

            print(
                "  python -m crypto.key_rotation rotate"
            )

            sys.exit(1)

    else:

        # Default operation
        initialize_key()