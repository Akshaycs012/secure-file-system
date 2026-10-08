from pathlib import Path
from unittest.mock import patch
import hashlib


AUDIT_FILE = Path("data/audit_atomicity_test.json")


print("===================================")
print("AUDIT ATOMICITY TEST")
print("===================================")


def file_hash(path):
    data = path.read_bytes()
    return hashlib.sha256(data).hexdigest()


# --------------------------------------------------
# Create initial audit log
# --------------------------------------------------

from crypto.audit import AuditLog


audit = AuditLog()

audit.add_event(
    "ENCRYPT",
    {
        "file": "original.txt"
    }
)

audit.save(AUDIT_FILE)

original_hash = file_hash(AUDIT_FILE)

print("\nOriginal audit log created.")
print(f"Original SHA-256: {original_hash}")


# --------------------------------------------------
# Add another event in memory
# --------------------------------------------------

audit.add_event(
    "DOWNLOAD",
    {
        "file": "encrypted.bin"
    }
)


# --------------------------------------------------
# Simulate atomic replace failure
# --------------------------------------------------

print("\nSimulating atomic replacement failure...")

try:

    with patch(
        "crypto.audit.os.replace",
        side_effect=OSError(
            "SIMULATED ATOMIC REPLACE FAILURE"
        )
    ):

        audit.save(AUDIT_FILE)

    print(
        "❌ SECURITY FAILURE: "
        "audit save unexpectedly succeeded."
    )

except OSError as error:

    print(
        f"✅ Simulated failure occurred: {error}"
    )


# --------------------------------------------------
# Verify original audit file survived
# --------------------------------------------------

print("\nChecking original audit file...")

if not AUDIT_FILE.exists():

    print(
        "❌ SECURITY FAILURE: "
        "original audit file was lost."
    )

else:

    current_hash = file_hash(AUDIT_FILE)

    print(
        f"Current SHA-256:  {current_hash}"
    )

    if current_hash == original_hash:

        print(
            "✅ Original audit log survived unchanged."
        )

    else:

        print(
            "❌ SECURITY FAILURE: "
            "audit file was modified."
        )


# --------------------------------------------------
# Check temporary file cleanup
# --------------------------------------------------

TEMP_FILE = AUDIT_FILE.with_suffix(
    AUDIT_FILE.suffix + ".tmp"
)


print("\nChecking temporary file cleanup...")

if TEMP_FILE.exists():

    print(
        "❌ SECURITY FAILURE: "
        "temporary audit file remains."
    )

else:

    print(
        "✅ Temporary audit file cleaned up."
    )


# --------------------------------------------------
# Verify audit chain
# --------------------------------------------------

print("\nVerifying surviving audit chain...")

loaded_audit = AuditLog()
loaded_audit.load(AUDIT_FILE)

if loaded_audit.verify_chain():

    print(
        "✅ Surviving audit chain is valid."
    )

else:

    print(
        "❌ SECURITY FAILURE: "
        "audit chain is corrupted."
    )


# --------------------------------------------------
# Cleanup
# --------------------------------------------------

if AUDIT_FILE.exists():
    AUDIT_FILE.unlink()

if TEMP_FILE.exists():
    TEMP_FILE.unlink()


print("\n===================================")
print("AUDIT ATOMICITY TEST COMPLETE")
print("===================================")