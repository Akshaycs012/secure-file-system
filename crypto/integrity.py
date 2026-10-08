from pathlib import Path

from crypto.audit import AuditLog
from crypto.hashing import calculate_file_hash


AUDIT_FILE = Path("data/audit.json")


def load_audit_log():
    """
    Load and verify the audit log.
    """

    audit = AuditLog()

    if AUDIT_FILE.exists():

        audit.load(AUDIT_FILE)

        if not audit.verify_chain():
            raise ValueError(
                "Audit log has been tampered with."
            )

    return audit


def verify_file_integrity(file_path):
    file_path = Path(file_path)

    if not file_path.exists():
        raise FileNotFoundError(
            f"File not found: {file_path}"
        )

    audit = load_audit_log()
    expected_hash = None

    # Prefer the newest completed encryption transaction.
    for event in reversed(audit.events):
        if event["action"] == "ENCRYPT_COMPLETED":
            details = event["details"]

            if details.get("encrypted_file") == str(file_path):
                expected_hash = details.get(
                    "encrypted_file_sha256"
                )
                break

    # Support older audit entries created before
    # the transaction-based audit format.
    if expected_hash is None:
        for event in reversed(audit.events):
            if event["action"] != "ENCRYPT":
                continue

            details = event["details"]

            if details.get("encrypted_file") == str(file_path):
                expected_hash = details.get(
                    "encrypted_file_sha256"
                )
                break

    if expected_hash is None:
        raise ValueError(
            "No SHA-256 hash found in audit log "
            f"for: {file_path}"
        )

    actual_hash = calculate_file_hash(file_path)

    if actual_hash != expected_hash:
        raise ValueError(
            "File integrity verification failed.\n"
            f"Expected: {expected_hash}\n"
            f"Actual:   {actual_hash}"
        )

    return True