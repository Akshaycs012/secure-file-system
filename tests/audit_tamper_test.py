import copy

from crypto.audit import AuditLog


AUDIT_FILE = "data/audit.json"


def create_test_log():

    audit = AuditLog()

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

    return audit


# -----------------------------------------
# Create original audit log
# -----------------------------------------

audit = create_test_log()

audit.save(AUDIT_FILE)

print("Original audit chain:")
print(audit.verify_chain())


# -----------------------------------------
# TEST 1 — Modify an event
# -----------------------------------------

modified_audit = copy.deepcopy(audit)

modified_audit.events[1]["action"] = "HACKED"

print("\nTEST 1 — Modify Event 2")

if modified_audit.verify_chain():

    print("❌ MODIFICATION NOT DETECTED")

else:

    print("✅ MODIFICATION DETECTED")


# -----------------------------------------
# TEST 2 — Delete an event
# -----------------------------------------

deleted_audit = copy.deepcopy(audit)

del deleted_audit.events[1]

print("\nTEST 2 — Delete Event 2")

if deleted_audit.verify_chain():

    print("❌ DELETION NOT DETECTED")

else:

    print("✅ DELETION DETECTED")


# -----------------------------------------
# TEST 3 — Reorder events
# -----------------------------------------

reordered_audit = copy.deepcopy(audit)

reordered_audit.events[0], reordered_audit.events[1] = (
    reordered_audit.events[1],
    reordered_audit.events[0]
)

print("\nTEST 3 — Reorder Events")

if reordered_audit.verify_chain():

    print("❌ REORDERING NOT DETECTED")

else:

    print("✅ REORDERING DETECTED")