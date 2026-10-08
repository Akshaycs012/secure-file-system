from pathlib import Path
from unittest.mock import patch

from crypto.secure_file import secure_encrypt
from crypto.worm import is_protected, unprotect_file


INPUT_FILE = Path("data/original.txt")
TEST_OUTPUT = Path("data/audit_failure_output.bin")


print("===================================")
print("AUDIT FAILURE INJECTION TEST")
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


print("\nSimulating audit-log failure...")


try:
    with patch(
        "crypto.audit.AuditLog.save",
        side_effect=RuntimeError("SIMULATED AUDIT FAILURE")
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
    print(
        f"✅ Simulated failure occurred: {error}"
    )


print("\n[State after simulated audit failure]")


if TEST_OUTPUT.exists():
    print("Encrypted output exists: True")

    try:
        protected = is_protected(TEST_OUTPUT)
        print(f"WORM protected: {protected}")

    except Exception as error:
        print(
            f"Could not determine WORM state: {error}"
        )

else:
    print("Encrypted output exists: False")


print("\n[Atomicity assessment]")


if TEST_OUTPUT.exists():

    try:
        protected = is_protected(TEST_OUTPUT)
    except Exception:
        protected = False

    if protected:
        print(
            "⚠️ AUDIT CONSISTENCY PROBLEM:"
        )
        print(
            "Encrypted file remains WORM protected "
            "even though the audit operation failed."
        )

    else:
        print(
            "⚠️ Inconsistent state:"
        )
        print(
            "Encrypted output exists without WORM protection."
        )

else:

    print(
        "✅ No encrypted output remains."
    )


cleanup()


print("\n===================================")
print("AUDIT FAILURE TEST COMPLETE")
print("===================================")