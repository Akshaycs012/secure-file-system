from pathlib import Path

from crypto.secure_file import (
    secure_encrypt,
    secure_decrypt
)
from crypto.worm import (
    is_protected,
    unprotect_file
)


INPUT_FILE = Path("data/original.txt")
ENCRYPTED_FILE = Path("data/test_secure_output.bin")
RECOVERED_FILE = Path("data/recovered_secure.txt")


print("===================================")
print("SECURE FILE SYSTEM INTEGRATION TEST")
print("===================================")


# -----------------------------------------
# Cleanup old test files
# -----------------------------------------

if ENCRYPTED_FILE.exists():

    if is_protected(ENCRYPTED_FILE):
        print("\nRemoving old WORM protection...")
        unprotect_file(ENCRYPTED_FILE)

    ENCRYPTED_FILE.unlink()


if RECOVERED_FILE.exists():
    RECOVERED_FILE.unlink()


# -----------------------------------------
# Secure encryption
# -----------------------------------------

print("\nStarting secure encryption...")

secure_encrypt(
    INPUT_FILE,
    ENCRYPTED_FILE
)


# -----------------------------------------
# Verify WORM protection
# -----------------------------------------

print("\nChecking WORM protection...")

if is_protected(ENCRYPTED_FILE):

    print("WORM protection: SUCCESS")

else:

    raise RuntimeError(
        "WORM protection: FAILED"
    )


# -----------------------------------------
# Secure decryption
# -----------------------------------------

print("\nStarting secure decryption...")

secure_decrypt(
    ENCRYPTED_FILE,
    RECOVERED_FILE
)


# -----------------------------------------
# Compare files
# -----------------------------------------

print("\nComparing original and recovered files...")

original_data = INPUT_FILE.read_bytes()
recovered_data = RECOVERED_FILE.read_bytes()


if original_data == recovered_data:

    print("File recovery: SUCCESS")

else:

    raise RuntimeError(
        "File recovery: FAILED"
    )


print("\n===================================")
print("INTEGRATION TEST COMPLETE")
print("===================================")