from pathlib import Path
from unittest.mock import patch

from crypto.secure_file import secure_encrypt
from crypto.worm import is_protected, unprotect_file


INPUT_FILE = Path("data/original.txt")
TEST_OUTPUT = Path("data/atomic_failure_output.bin")

print("===================================")
print("ATOMIC FAILURE INJECTION TEST")
print("===================================")


def cleanup():
    if TEST_OUTPUT.exists():
        try:
            if is_protected(TEST_OUTPUT):
                unprotect_file(TEST_OUTPUT)
        except Exception:
            pass

        if TEST_OUTPUT.exists():
            TEST_OUTPUT.unlink()


cleanup()

if not INPUT_FILE.exists():
    raise FileNotFoundError(
        f"Input file not found: {INPUT_FILE}"
    )


print("\nSimulating WORM protection failure...")

try:
    with patch(
        "crypto.secure_file.protect_file",
        side_effect=RuntimeError("SIMULATED WORM FAILURE")
    ):
        secure_encrypt(
            INPUT_FILE,
            TEST_OUTPUT
        )

    print(
        "❌ SECURITY FAILURE: "
        "encryption unexpectedly succeeded."
    )

except RuntimeError as error:
    print(f"✅ Simulated failure occurred: {error}")


print("\n[State after simulated failure]")

if TEST_OUTPUT.exists():
    print("Encrypted output exists: True")

    try:
        protected = is_protected(TEST_OUTPUT)
        print(f"WORM protected: {protected}")

    except Exception as error:
        print(f"Could not determine WORM state: {error}")

else:
    print("Encrypted output exists: False")


print("\n[Atomicity assessment]")

if TEST_OUTPUT.exists():
    try:
        protected = is_protected(TEST_OUTPUT)
    except Exception:
        protected = False

    if not protected:
        print(
            "⚠️ ATOMICITY PROBLEM DETECTED:"
        )
        print(
            "Encrypted output remains after "
            "the secure operation failed."
        )
    else:
        print(
            "⚠️ Inconsistent state:"
        )
        print(
            "Output exists and is protected despite "
            "the operation reporting failure."
        )
else:
    print(
        "✅ No encrypted output remains."
    )


cleanup()

print("\n===================================")
print("ATOMIC FAILURE TEST COMPLETE")
print("===================================")