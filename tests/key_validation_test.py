from pathlib import Path

from crypto.key_manager import (
    generate_key,
    save_key,
    load_key,
    KEY_SIZE
)


TEST_DIR = Path("keys/key_validation_test")
VALID_KEY = TEST_DIR / "valid.key"
INVALID_KEY = TEST_DIR / "invalid.key"
DIRECTORY_KEY = TEST_DIR / "directory.key"


print("===================================")
print("KEY VALIDATION TEST")
print("===================================")


TEST_DIR.mkdir(
    parents=True,
    exist_ok=True
)


# -----------------------------------------
# Test 1: Valid key
# -----------------------------------------

print("\n[1] Testing valid AES-256 key...")

valid_key = generate_key()

save_key(
    valid_key,
    VALID_KEY
)

loaded_key = load_key(VALID_KEY)

assert len(loaded_key) == KEY_SIZE
assert loaded_key == valid_key

print("Valid key: ACCEPTED ✅")


# -----------------------------------------
# Test 2: Wrong key size
# -----------------------------------------

print("\n[2] Testing invalid key size...")

with open(INVALID_KEY, "wb") as file:
    file.write(b"short-key")


try:

    load_key(INVALID_KEY)

    print(
        "SECURITY FAILURE: "
        "Invalid key was accepted."
    )

except ValueError:

    print("Invalid key rejected: SUCCESS ✅")


# -----------------------------------------
# Test 3: Directory instead of key
# -----------------------------------------

print("\n[3] Testing directory as key...")

DIRECTORY_KEY.mkdir(
    parents=True,
    exist_ok=True
)

try:

    load_key(DIRECTORY_KEY)

    print(
        "SECURITY FAILURE: "
        "Directory was accepted as key."
    )

except ValueError:

    print("Directory rejected: SUCCESS ✅")


# -----------------------------------------
# Test 4: Missing key
# -----------------------------------------

print("\n[4] Testing missing key...")

missing_key = TEST_DIR / "does_not_exist.key"

try:

    load_key(missing_key)

    print(
        "SECURITY FAILURE: "
        "Missing key was accepted."
    )

except FileNotFoundError:

    print("Missing key rejected: SUCCESS ✅")


# -----------------------------------------
# Test 5: Key size constant
# -----------------------------------------

print("\n[5] Checking AES-256 key size...")

assert KEY_SIZE == 32

print("AES-256 key size: 32 bytes ✅")


print("\n===================================")
print("KEY VALIDATION TEST COMPLETE")
print("===================================")