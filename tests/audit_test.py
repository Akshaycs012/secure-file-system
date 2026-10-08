from crypto.audit import AuditLog


AUDIT_FILE = "data/audit.json"


# -----------------------------------------
# Create audit log
# -----------------------------------------

audit = AuditLog()


# -----------------------------------------
# Add events
# -----------------------------------------

audit.add_event(
    "ENCRYPT",
    {
        "file": "original.txt"
    }
)

audit.add_event(
    "DOWNLOAD",
    {
        "file": "encrypted.bin"
    }
)

audit.add_event(
    "DECRYPT",
    {
        "file": "encrypted.bin"
    }
)


# -----------------------------------------
# Verify before saving
# -----------------------------------------

print("Before saving:")

if audit.verify_chain():

    print("✓ AUDIT CHAIN VALID")

else:

    print("✗ AUDIT CHAIN INVALID")


# -----------------------------------------
# Save audit log
# -----------------------------------------

audit.save(AUDIT_FILE)

print("\nAudit log saved.")


# -----------------------------------------
# Create a new AuditLog
# -----------------------------------------

loaded_audit = AuditLog()


# -----------------------------------------
# Load existing audit log
# -----------------------------------------

loaded_audit.load(AUDIT_FILE)

print("Audit log loaded.")


# -----------------------------------------
# Verify loaded chain
# -----------------------------------------

print("\nAfter loading:")

if loaded_audit.verify_chain():

    print("✓ AUDIT CHAIN VALID")

else:

    print("✗ AUDIT CHAIN INVALID")


# -----------------------------------------
# Display events
# -----------------------------------------

print("\nAUDIT EVENTS")
print("=" * 60)

for event in loaded_audit.events:

    print(f"\nEvent ID: {event['event_id']}")
    print(f"Action: {event['action']}")
    print(f"Details: {event['details']}")
    print(f"Previous Hash: {event['previous_hash']}")
    print(f"Hash: {event['hash']}")