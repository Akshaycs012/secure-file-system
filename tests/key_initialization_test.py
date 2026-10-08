from pathlib import Path

from crypto.key_manager import (
    initialize_key,
    KEY_SIZE
)


TEST_KEY = Path("keys/init_test.key")


print("===================================")
print("KEY INITIALIZATION TEST")
print("===================================")


# Remove test key if it exists
if TEST_KEY.exists():
    TEST_KEY.unlink()


print("\n[1] Initializing key...")

key1 = initialize_key(TEST_KEY)

print(
    f"Key size: {len(key1)} bytes"
)

assert len(key1) == KEY_SIZE

print("Key generation: SUCCESS")


print("\n[2] Checking key file...")

assert TEST_KEY.exists()

print(
    f"Key exists: {TEST_KEY}"
)

print("Key file: SUCCESS")


print("\n[3] Initializing again...")

key2 = initialize_key(TEST_KEY)

assert key1 == key2

print("Existing key preserved: SUCCESS")


print("\n[4] Checking key permissions...")

permissions = TEST_KEY.stat().st_mode & 0o777

print(
    f"Permissions: {oct(permissions)}"
)

assert permissions == 0o600

print("Key permissions: SUCCESS")


print("\n===================================")
print("KEY INITIALIZATION TEST COMPLETE")
print("===================================")