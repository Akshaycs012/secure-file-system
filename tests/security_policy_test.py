from pathlib import Path

from crypto.security_policy import can_decrypt
from crypto.worm import protect_file, unprotect_file
from crypto.file_state import get_file_state


TEST_FILE = Path("data/test_secure_output.bin")


print("===================================")
print("SECURITY POLICY TEST")
print("===================================")


# -----------------------------------------
# Test 1: Protected file
# -----------------------------------------

print("\n[TEST 1] Protected file")

if not TEST_FILE.exists():
    raise FileNotFoundError(
        f"Test file not found: {TEST_FILE}"
    )

if not get_file_state(TEST_FILE) == "PROTECTED":
    protect_file(TEST_FILE)

state = get_file_state(TEST_FILE)

print(f"State: {state}")

if can_decrypt(TEST_FILE):
    print("Protected file: ALLOWED ✅")
else:
    print("Protected file: FAILED ❌")


# -----------------------------------------
# Test 2: Unprotected file
# -----------------------------------------

print("\n[TEST 2] Unprotected file")

print("Removing WORM protection...")

unprotect_file(TEST_FILE)

state = get_file_state(TEST_FILE)

print(f"State: {state}")

if not can_decrypt(TEST_FILE):
    print("Unprotected file: DENIED ✅")
else:
    print("Unprotected file: FAILED ❌")


# -----------------------------------------
# Restore protection
# -----------------------------------------

print("\nRestoring WORM protection...")

protect_file(TEST_FILE)

state = get_file_state(TEST_FILE)

print(f"Final state: {state}")


# -----------------------------------------
# Final result
# -----------------------------------------

print("\n===================================")
print("SECURITY POLICY TEST COMPLETE")
print("===================================")