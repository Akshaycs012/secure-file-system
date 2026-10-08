from pathlib import Path
import json

from crypto.audit import AuditLog


AUDIT_FILE = Path("data/audit.json")
BACKUP_FILE = Path("data/audit_backup.json")


print("===================================")
print("SECURE AUDIT TAMPER TEST")
print("===================================")


# -----------------------------------------
# Backup audit log
# -----------------------------------------

print("\nCreating audit backup...")

BACKUP_FILE.write_bytes(
    AUDIT_FILE.read_bytes()
)

print("Backup created.")


# -----------------------------------------
# Load audit log
# -----------------------------------------

audit = AuditLog()

audit.load(AUDIT_FILE)

print(f"Events found: {len(audit.events)}")


# -----------------------------------------
# Verify before tampering
# -----------------------------------------

print("\nChecking original audit chain...")

if audit.verify_chain():
    print("Original chain: VALID")
else:
    print("Original chain: INVALID")


# -----------------------------------------
# Tamper with an event
# -----------------------------------------

print("\nTampering with audit log...")

with open(
    AUDIT_FILE,
    "r",
    encoding="utf-8"
) as file:

    events = json.load(file)


# Change an existing event
events[0]["action"] = "ATTACKER_MODIFIED_EVENT"


with open(
    AUDIT_FILE,
    "w",
    encoding="utf-8"
) as file:

    json.dump(
        events,
        file,
        indent=4
    )


print("Audit event modified.")


# -----------------------------------------
# Verify after tampering
# -----------------------------------------

tampered_audit = AuditLog()

tampered_audit.load(AUDIT_FILE)

print("\nChecking tampered audit chain...")

if tampered_audit.verify_chain():

    print("ERROR: Tampering was not detected!")

else:

    print("Tampering detected: SUCCESS")


# -----------------------------------------
# Restore audit log
# -----------------------------------------

print("\nRestoring original audit log...")

AUDIT_FILE.write_bytes(
    BACKUP_FILE.read_bytes()
)

BACKUP_FILE.unlink()

print("Original audit log restored.")


print("\n===================================")
print("AUDIT TAMPER TEST COMPLETE")
print("===================================")