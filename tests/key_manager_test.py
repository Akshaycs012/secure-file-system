from crypto.key_manager import (
    generate_key,
    save_key,
    load_key
)


KEY_PATH = "keys/test_secret.key"


# -----------------------------------
# 1. Generate valid key
# -----------------------------------

print("Generating key...")

key = generate_key()

print("Key size:", len(key), "bytes")


# -----------------------------------
# 2. Save valid key
# -----------------------------------

print("\nSaving valid key...")

save_key(key, KEY_PATH)

print("Valid key saved: SUCCESS")


# -----------------------------------
# 3. Load key
# -----------------------------------

print("\nLoading key...")

loaded_key = load_key(KEY_PATH)

if key == loaded_key:
    print("Key verification: SUCCESS")
else:
    print("Key verification: FAILED")


# -----------------------------------
# 4. Test invalid key size
# -----------------------------------

print("\nTesting invalid key...")

try:
    invalid_key = b"1234567890"

    save_key(invalid_key, "keys/invalid.key")

    print("ERROR: Invalid key was accepted!")

except ValueError:
    print("Invalid key rejected: SUCCESS")


# -----------------------------------
# 5. Test invalid key type
# -----------------------------------

print("\nTesting invalid key type...")

try:
    invalid_key = "this is not bytes"

    save_key(invalid_key, "keys/invalid.key")

    print("ERROR: Invalid key type was accepted!")

except TypeError:
    print("Invalid key type rejected: SUCCESS")