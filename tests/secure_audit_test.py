from pathlib import Path

from crypto.audit import AuditLog


AUDIT_FILE = Path("data/audit.json")


print("===================================")
print("SECURE AUDIT VERIFICATION")
print("===================================")


audit = AuditLog()

print("\nLoading audit log...")

audit.load(AUDIT_FILE)

print(f"Events found: {len(audit.events)}")


print("\nVerifying hash chain...")

if audit.verify_chain():

    print("Audit chain: VALID")

else:

    print("Audit chain: INVALID")


print("\nAudit events:")

for event in audit.events:

    print(
        f"Event {event['event_id']}: "
        f"{event['action']}"
    )


print("\n===================================")
print("AUDIT VERIFICATION COMPLETE")
print("===================================")