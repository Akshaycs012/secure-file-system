from pathlib import Path

from crypto.worm import protect_file, unprotect_file
from crypto.file_state import get_file_state
from crypto.security_policy import can_decrypt
from crypto.integrity import verify_file_integrity


TEST_FILE = Path("data/test_secure_output.bin")


print("===================================")
print("SECURITY ATTACK TEST")
print("===================================")


# -----------------------------------------
# Step 1: Check original state
# -----------------------------------------

print("\n[1] Checking original file...")

if not TEST_FILE.exists():
    raise FileNotFoundError(
        f"Test file not found: {TEST_FILE}"
    )

print(
    f"Initial state: "
    f"{get_file_state(TEST_FILE)}"
)


# -----------------------------------------
# Step 2: Remove WORM protection
# -----------------------------------------

print("\n[2] Removing WORM protection...")

if get_file_state(TEST_FILE) == "PROTECTED":
    unprotect_file(TEST_FILE)

print(
    f"State after removing WORM: "
    f"{get_file_state(TEST_FILE)}"
)


# -----------------------------------------
# Step 3: Tamper with file
# -----------------------------------------

print("\n[3] Tampering with encrypted file...")

with open(TEST_FILE, "r+b") as file:

    data = bytearray(file.read())

    if len(data) == 0:
        raise ValueError("Encrypted file is empty.")

    # Modify the last byte
    data[-1] ^= 0xFF

    file.seek(0)
    file.write(data)
    file.truncate()

print("One byte modified.")


# -----------------------------------------
# Step 4: Check file state
# -----------------------------------------

print("\n[4] Checking file state...")

state = get_file_state(TEST_FILE)

print(f"State after tampering: {state}")


# -----------------------------------------
# Step 5: Check security policy
# -----------------------------------------

print("\n[5] Checking security policy...")

if can_decrypt(TEST_FILE):

    print(
        "SECURITY FAILURE: "
        "Tampered file was allowed."
    )

else:

    print(
        "Tampered file: DECRYPTION DENIED ✅"
    )


# -----------------------------------------
# Step 6: Verify integrity
# -----------------------------------------

print("\n[6] Verifying SHA-256 integrity...")

try:

    verify_file_integrity(TEST_FILE)

    print(
        "SECURITY FAILURE: "
        "Tampered file passed integrity check."
    )

except ValueError:

    print(
        "Tampering detected by SHA-256: SUCCESS ✅"
    )


# -----------------------------------------
# Step 7: Restore file
# -----------------------------------------

print("\n[7] Restoring original file...")

print(
    "WARNING: The test file was modified."
)

print(
    "Restore data/test_secure_output.bin "
    "by running the integration test again."
)


print("\n===================================")
print("SECURITY ATTACK TEST COMPLETE")
print("===================================")