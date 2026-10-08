from pathlib import Path

from crypto.audit import AuditLog, GENESIS_HASH


AUDIT_FILE = Path("data/audit.json")

OLD_PATH = (
    "/home/akshay/secure-file-system/"
    "data/storage/workspace_test.txt.sfs"
)

NEW_PATH = (
    "/home/akshay/secure-file-system/"
    "data/storage/"
    "abc16306-3b02-4eaa-a556-4714fb583f91/"
    "workspace_test.txt.sfs"
)


def rebuild_hash_chain(audit):
    """
    Recalculate previous_hash and hash for every event.
    """

    previous_hash = GENESIS_HASH

    for event in audit.events:

        event["previous_hash"] = previous_hash

        event_without_hash = event.copy()

        event_without_hash.pop("hash", None)

        event["hash"] = audit.calculate_hash(
            event_without_hash
        )

        previous_hash = event["hash"]


def main():

    if not AUDIT_FILE.exists():
        raise SystemExit(
            "Audit file does not exist."
        )

    audit = AuditLog()
    audit.load(AUDIT_FILE)

    print(
        "Audit events loaded:",
        len(audit.events)
    )

    # Verify the existing chain BEFORE modifying anything.
    if not audit.verify_chain():
        raise SystemExit(
            "Audit chain is already invalid. "
            "Migration stopped."
        )

    changed_events = 0

    for event in audit.events:

        details = event.get("details", {})

        if details.get("encrypted_file") == OLD_PATH:

            details["encrypted_file"] = NEW_PATH

            changed_events += 1

            print(
                "Updated event:",
                event["event_id"],
                event["action"]
            )

    if changed_events == 0:
        raise SystemExit(
            "No matching audit events found. "
            "Migration stopped."
        )

    print(
        "Events updated:",
        changed_events
    )

    # Rebuild the complete hash chain.
    rebuild_hash_chain(audit)

    # Verify the rebuilt chain.
    if not audit.verify_chain():
        raise SystemExit(
            "Rebuilt audit chain is invalid."
        )

    # Save atomically using AuditLog.save().
    audit.save(AUDIT_FILE)

    print(
        "Audit log saved successfully."
    )

    # Load again and verify the persisted file.
    verification = AuditLog()
    verification.load(AUDIT_FILE)

    if not verification.verify_chain():
        raise SystemExit(
            "Persisted audit chain verification failed."
        )

    print(
        "Audit chain verification: VALID"
    )


if __name__ == "__main__":
    main()