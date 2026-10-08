from pathlib import Path

from crypto.key_manager import generate_key, save_key
from crypto.key_registry import (
    KeyRegistry,
    generate_key_id,
    ACTIVE,
    RETIRED,
    REVOKED
)


TEST_DIR = Path("data/key_status_test")
REGISTRY_FILE = TEST_DIR / "registry.json"


print("===================================")
print("KEY STATUS TEST")
print("===================================")


def cleanup():
    if TEST_DIR.exists():
        for path in TEST_DIR.iterdir():
            if path.is_file():
                path.unlink()

        TEST_DIR.rmdir()


cleanup()
TEST_DIR.mkdir(parents=True, exist_ok=True)


# --------------------------------------------------
# Create key
# --------------------------------------------------

print("\n[1] Creating test key...")

key = generate_key()
key_id = generate_key_id(key)

key_path = TEST_DIR / f"{key_id.hex()}.key"

save_key(key, key_path)

print(f"Key ID: {key_id.hex()}")


# --------------------------------------------------
# Register as ACTIVE
# --------------------------------------------------

print("\n[2] Registering key as ACTIVE...")

registry = KeyRegistry(REGISTRY_FILE)

registry.register_key(
    key_id,
    key_path,
    status=ACTIVE
)

if registry.get_status(key_id) == ACTIVE:
    print("Initial status: ACTIVE")
else:
    print("❌ Initial status is incorrect")


if registry.can_encrypt(key_id):
    print("ACTIVE encryption: ALLOWED")
else:
    print("❌ ACTIVE encryption incorrectly denied")


if registry.can_decrypt(key_id):
    print("ACTIVE decryption: ALLOWED")
else:
    print("❌ ACTIVE decryption incorrectly denied")


# --------------------------------------------------
# Retire key
# --------------------------------------------------

print("\n[3] Retiring key...")

registry.retire_key(key_id)

status = registry.get_status(key_id)

print(f"Status: {status}")

if status == RETIRED:
    print("Retirement: SUCCESS")
else:
    print("❌ Retirement failed")


if not registry.can_encrypt(key_id):
    print("RETIRED encryption: DENIED")
else:
    print("❌ RETIRED encryption incorrectly allowed")


if registry.can_decrypt(key_id):
    print("RETIRED decryption: ALLOWED")
else:
    print("❌ RETIRED decryption incorrectly denied")


# --------------------------------------------------
# Revoke key
# --------------------------------------------------

print("\n[4] Revoking key...")

registry.revoke_key(key_id)

status = registry.get_status(key_id)

print(f"Status: {status}")

if status == REVOKED:
    print("Revocation: SUCCESS")
else:
    print("❌ Revocation failed")


if not registry.can_encrypt(key_id):
    print("REVOKED encryption: DENIED")
else:
    print("❌ REVOKED encryption incorrectly allowed")


if not registry.can_decrypt(key_id):
    print("REVOKED decryption: DENIED")
else:
    print("❌ REVOKED decryption incorrectly allowed")


# --------------------------------------------------
# Cleanup
# --------------------------------------------------

cleanup()


print("\n===================================")
print("KEY STATUS TEST COMPLETE")
print("===================================")