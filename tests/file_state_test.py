from crypto.file_state import get_file_state
from crypto.security_policy import can_decrypt


TEST_FILE = "data/test_secure_output.bin"


print("===================================")
print("FILE STATE MANAGEMENT TEST")
print("===================================")


# -----------------------------------------
# Check file state
# -----------------------------------------

print("\nChecking file state...")

state = get_file_state(TEST_FILE)

print(f"File : {TEST_FILE}")
print(f"State: {state}")


if state == "PROTECTED":

    print("File state: SUCCESS")

else:

    print(
        f"File state: FAILED "
        f"(expected PROTECTED, got {state})"
    )


# -----------------------------------------
# Check decryption permission
# -----------------------------------------

print("\nChecking decryption permission...")

allowed = can_decrypt(TEST_FILE)

if allowed:

    print("Decryption permission: ALLOWED")

else:

    print("Decryption permission: DENIED")


# -----------------------------------------
# Final result
# -----------------------------------------

if state == "PROTECTED" and allowed:

    print("\nState enforcement: SUCCESS")

else:

    print("\nState enforcement: FAILED")


print("\n===================================")
print("FILE STATE TEST COMPLETE")
print("===================================")