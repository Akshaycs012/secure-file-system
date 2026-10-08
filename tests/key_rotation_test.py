from pathlib import Path
import subprocess
import sys
import hashlib

from crypto.key_registry import KeyRegistry
from crypto.key_rotation import (
    get_current_key_id as get_active_key_id
)


# --------------------------------------------------
# Test files
# --------------------------------------------------

ORIGINAL_FILE = Path(
    "data/original.txt"
)

ENCRYPTED_FILE = Path(
    "data/key_rotation_test.bin"
)

RECOVERED_FILE = Path(
    "data/key_rotation_recovered.txt"
)

REGISTRY_FILE = Path(
    "keys/registry.json"
)


# --------------------------------------------------
# SHA-256 helper
# --------------------------------------------------

def file_hash(file_path):
    """
    Calculate SHA-256 hash of a file.
    """

    sha256 = hashlib.sha256()

    with open(
        file_path,
        "rb"
    ) as file:

        while chunk := file.read(8192):

            sha256.update(
                chunk
            )

    return sha256.hexdigest()


# --------------------------------------------------
# Get current active Key ID
# --------------------------------------------------

def get_current_key_id():
    """
    Return the currently active Key ID.
    """

    return get_active_key_id().hex()


# --------------------------------------------------
# Main test
# --------------------------------------------------

def main():

    print(
        "==================================="
    )

    print(
        "KEY ROTATION TEST"
    )

    print(
        "==================================="
    )

    # --------------------------------------------------
    # Validate original file
    # --------------------------------------------------

    if not ORIGINAL_FILE.exists():

        raise FileNotFoundError(
            f"Original file not found: "
            f"{ORIGINAL_FILE}"
        )

    # --------------------------------------------------
    # Step 1
    # Encrypt using Key A
    # --------------------------------------------------

    print(
        "\n[1] Encrypting file with Key A..."
    )

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "crypto.encrypt"
        ],
        capture_output=True,
        text=True,
        check=True
    )

    print(
        result.stdout.strip()
    )

    # --------------------------------------------------
    # Extract Key A ID
    # --------------------------------------------------

    key_a = None

    for line in result.stdout.splitlines():

        if line.startswith("Key ID:"):

            key_a = line.split(
                ":",
                1
            )[1].strip()

            break

    if key_a is None:

        raise RuntimeError(
            "Could not determine Key A ID."
        )

    print(
        f"Key A ID: {key_a}"
    )

    # --------------------------------------------------
    # Copy encrypted file
    # --------------------------------------------------

    source_encrypted = Path(
        "data/encrypted.bin"
    )

    if not source_encrypted.exists():

        raise FileNotFoundError(
            "data/encrypted.bin was not created."
        )

    ENCRYPTED_FILE.write_bytes(
        source_encrypted.read_bytes()
    )

    # --------------------------------------------------
    # Save original hash
    # --------------------------------------------------

    original_hash = file_hash(
        ORIGINAL_FILE
    )

    # --------------------------------------------------
    # Step 2
    # Rotate key
    # --------------------------------------------------

    print(
        "\n[2] Rotating encryption key..."
    )

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "crypto.key_rotation",
            "rotate"
        ],
        capture_output=True,
        text=True,
        check=True
    )

    print(
        result.stdout.strip()
    )

    # --------------------------------------------------
    # Get Key B
    # --------------------------------------------------

    key_b = get_current_key_id()

    print(
        f"\nKey B ID: {key_b}"
    )

    # --------------------------------------------------
    # Verify Key B is different
    # --------------------------------------------------

    if key_a == key_b:

        raise AssertionError(
            "Key rotation failed: "
            "new key ID is same as old key ID."
        )

    print(
        "New key generated: SUCCESS"
    )

    # --------------------------------------------------
    # Step 3
    # Verify new key is active
    # --------------------------------------------------

    print(
        "\n[3] Verifying key rotation..."
    )

    current_key = get_current_key_id()

    if current_key != key_b:

        raise AssertionError(
            "New key is not the active key."
        )

    print(
        "New key active: SUCCESS"
    )

    if key_a == current_key:

        raise AssertionError(
            "Old key is still active."
        )

    print(
        "Old key replaced as active key: SUCCESS"
    )

    # --------------------------------------------------
    # Step 4
    # Decrypt old Key A encrypted file
    # --------------------------------------------------

    print(
        "\n[4] Decrypting file encrypted with Key A..."
    )

    source_normal = Path(
        "data/encrypted.bin"
    )

    backup_normal = None

    if source_normal.exists():

        backup_normal = (
            source_normal.read_bytes()
        )

    # Replace normal encrypted file
    # with the Key A encrypted file.

    source_normal.write_bytes(
        ENCRYPTED_FILE.read_bytes()
    )

    try:

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "crypto.decrypt"
            ],
            capture_output=True,
            text=True,
            check=True
        )

        print(
            result.stdout.strip()
        )

    finally:

        # --------------------------------------------------
        # Restore normal encrypted file
        # --------------------------------------------------

        if backup_normal is not None:

            source_normal.write_bytes(
                backup_normal
            )

    # --------------------------------------------------
    # Step 5
    # Verify recovered file
    # --------------------------------------------------

    print(
        "\n[5] Comparing original and recovered files..."
    )

    recovered_normal = Path(
        "data/recovered.txt"
    )

    if not recovered_normal.exists():

        raise FileNotFoundError(
            "data/recovered.txt was not created."
        )

    recovered_hash = file_hash(
        recovered_normal
    )

    if original_hash != recovered_hash:

        print(
            f"Original : {original_hash}"
        )

        print(
            f"Recovered: {recovered_hash}"
        )

        raise AssertionError(
            "Recovered file does not match original."
        )

    print(
        "File recovery: SUCCESS"
    )

    # --------------------------------------------------
    # Step 6
    # Verify both keys exist
    # --------------------------------------------------

    print(
        "\n[6] Checking key registry..."
    )

    registry = KeyRegistry(
        REGISTRY_FILE
    )

    key_a_bytes = bytes.fromhex(
        key_a
    )

    key_b_bytes = bytes.fromhex(
        key_b
    )

    # --------------------------------------------------
    # Check Key A
    # --------------------------------------------------

    if not registry.contains(
        key_a_bytes
    ):

        raise AssertionError(
            "Key A is missing from registry."
        )

    print(
        "Key A registered: SUCCESS"
    )

    # --------------------------------------------------
    # Check Key B
    # --------------------------------------------------

    if not registry.contains(
        key_b_bytes
    ):

        raise AssertionError(
            "Key B is missing from registry."
        )

    print(
        "Key B registered: SUCCESS"
    )

    # --------------------------------------------------
    # Step 7
    # Verify Key A still exists
    # --------------------------------------------------

    print(
        "\n[7] Verifying old key lookup..."
    )

    key_a_path = registry.get_key_path(
        key_a_bytes
    )

    if not key_a_path.exists():

        raise AssertionError(
            f"Key A file does not exist: "
            f"{key_a_path}"
        )

    print(
        f"Key A path: {key_a_path}"
    )

    print(
        "Old key preserved: SUCCESS"
    )

    # --------------------------------------------------
    # Cleanup
    # --------------------------------------------------

    if ENCRYPTED_FILE.exists():

        ENCRYPTED_FILE.unlink()

    if RECOVERED_FILE.exists():

        RECOVERED_FILE.unlink()

    # --------------------------------------------------
    # Complete
    # --------------------------------------------------

    print(
        "\n==================================="
    )

    print(
        "KEY ROTATION TEST COMPLETE"
    )

    print(
        "==================================="
    )


# --------------------------------------------------
# Run test
# --------------------------------------------------

if __name__ == "__main__":
    main()