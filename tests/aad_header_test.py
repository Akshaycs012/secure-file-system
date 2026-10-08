from pathlib import Path

from crypto.decrypt import decrypt_file
from crypto.key_registry import KeyRegistry

SOURCE_FILE = Path("data/encrypted.bin")
TEST_DIR = Path("data/aad_tests")
BACKUP_FILE = TEST_DIR / "original.bin"
OUTPUT_FILE = TEST_DIR / "recovered.txt"

REGISTRY_FILE = Path("keys/registry.json")

print("===================================")
print("GCM AAD HEADER AUTHENTICATION TEST")
print("===================================")


def reset_test_file():
    SOURCE_FILE.write_bytes(BACKUP_FILE.read_bytes())


if not SOURCE_FILE.exists():
    raise FileNotFoundError(
        f"Encrypted file not found: {SOURCE_FILE}"
    )


TEST_DIR.mkdir(parents=True, exist_ok=True)

BACKUP_FILE.write_bytes(SOURCE_FILE.read_bytes())

print("\nOriginal encrypted file backed up.")


# --------------------------------------------------
# Read original Key ID
# --------------------------------------------------

original_data = bytearray(SOURCE_FILE.read_bytes())

# File format:
# 0-3   = MAGIC
# 4     = VERSION
# 5     = ALGORITHM
# 6     = NONCE SIZE
# 7     = TAG SIZE
# 8-23  = KEY ID

original_key_id = bytes(original_data[8:24])

print(f"Original Key ID: {original_key_id.hex()}")


# --------------------------------------------------
# Find another registered key
# --------------------------------------------------

registry = KeyRegistry(REGISTRY_FILE)

registered_ids = [
    bytes.fromhex(key_id)
    for key_id in registry._load().keys()
]

replacement_key_id = None

for key_id in registered_ids:
    if key_id != original_key_id:
        replacement_key_id = key_id
        break


if replacement_key_id is None:
    reset_test_file()
    BACKUP_FILE.unlink()

    raise RuntimeError(
        "A second registered key is required for this test."
    )


print(
    f"Replacement Key ID: "
    f"{replacement_key_id.hex()}"
)


# --------------------------------------------------
# Modify ONLY the Key ID
# --------------------------------------------------

tampered_data = bytearray(original_data)

tampered_data[8:24] = replacement_key_id

SOURCE_FILE.write_bytes(tampered_data)

print("\nModified ONLY the Key ID in the header.")
print("Ciphertext was not modified.")
print("Nonce was not modified.")
print("Authentication tag was not modified.")


# --------------------------------------------------
# Attempt decryption
# --------------------------------------------------

try:
    if OUTPUT_FILE.exists():
        OUTPUT_FILE.unlink()

    decrypt_file(SOURCE_FILE, OUTPUT_FILE)

    print(
        "\n❌ SECURITY FAILURE: "
        "modified authenticated header was accepted."
    )

except ValueError as error:
    print(
        "\n✅ Rejected by AES-GCM authentication:"
    )
    print(error)

finally:
    reset_test_file()

    if OUTPUT_FILE.exists():
        OUTPUT_FILE.unlink()

    if BACKUP_FILE.exists():
        BACKUP_FILE.unlink()


print("\n===================================")
print("AAD HEADER TEST COMPLETE")
print("===================================")