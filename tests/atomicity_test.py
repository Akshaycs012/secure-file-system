from pathlib import Path
import json

from crypto.secure_file import secure_encrypt
from crypto.worm import is_protected, unprotect_file


INPUT_FILE = Path("data/original.txt")
TEST_OUTPUT = Path("data/atomic_test_output.bin")
TEST_AUDIT = Path("data/atomic_test_audit.json")

print("===================================")
print("ATOMIC SECURE ENCRYPTION TEST")
print("===================================")


# --------------------------------------------------
# Cleanup
# --------------------------------------------------

def cleanup():
    if TEST_OUTPUT.exists():
        try:
            if is_protected(TEST_OUTPUT):
                unprotect_file(TEST_OUTPUT)
        except Exception:
            pass

        if TEST_OUTPUT.exists():
            TEST_OUTPUT.unlink()

    if TEST_AUDIT.exists():
        TEST_AUDIT.unlink()


# --------------------------------------------------
# Initial cleanup
# --------------------------------------------------

cleanup()


if not INPUT_FILE.exists():
    raise FileNotFoundError(
        f"Input file not found: {INPUT_FILE}"
    )


print(f"\nInput file: {INPUT_FILE}")
print(f"Test output: {TEST_OUTPUT}")


# --------------------------------------------------
# Test 1 — Normal secure encryption
# --------------------------------------------------

print("\n[1. Normal secure encryption]")

try:
    secure_encrypt(
        INPUT_FILE,
        TEST_OUTPUT
    )

    output_exists = TEST_OUTPUT.exists()
    protected = (
        is_protected(TEST_OUTPUT)
        if output_exists
        else False
    )

    print(f"Output exists: {output_exists}")
    print(f"WORM protected: {protected}")

    if output_exists and protected:
        print("✅ Normal secure encryption succeeded.")
    else:
        print("❌ SECURITY FAILURE: output is not securely protected.")

except Exception as error:
    print(f"❌ Unexpected failure: {error}")


# --------------------------------------------------
# Test 2 — Existing protected output
# --------------------------------------------------

print("\n[2. Existing protected output]")

try:
    secure_encrypt(
        INPUT_FILE,
        TEST_OUTPUT
    )

    print(
        "❌ SECURITY FAILURE: "
        "existing protected output was overwritten."
    )

except FileExistsError as error:
    print(f"✅ Operation rejected: {error}")

except Exception as error:
    print(f"⚠️ Unexpected exception: {error}")


# --------------------------------------------------
# Test 3 — Inspect resulting file
# --------------------------------------------------

print("\n[3. Final state inspection]")

if TEST_OUTPUT.exists():
    try:
        protected = is_protected(TEST_OUTPUT)

        print(f"Output exists: True")
        print(f"WORM protected: {protected}")

        if protected:
            print("✅ Final encrypted file is protected.")
        else:
            print(
                "❌ SECURITY FAILURE: "
                "encrypted file exists without WORM protection."
            )

    except Exception as error:
        print(f"❌ Could not inspect output: {error}")
else:
    print("Output exists: False")


# --------------------------------------------------
# Cleanup
# --------------------------------------------------

cleanup()

print("\n===================================")
print("ATOMICITY TEST COMPLETE")
print("===================================")