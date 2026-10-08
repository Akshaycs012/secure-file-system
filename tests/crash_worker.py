import os
import sys
from pathlib import Path

from crypto.audit import (
    AuditLog,
    ENCRYPT_STARTED,
    ENCRYPT_COMMITTED
)
from crypto.encrypt import encrypt_file
from crypto.hashing import calculate_file_hash
from crypto.durability import (
    fsync_file,
    fsync_directory
)


AUDIT_FILE = Path("data/audit.json")
OUTPUT_FILE = Path("data/crash_real_output.bin")
INPUT_FILE = Path("data/original.txt")


def main():

    crash_point = sys.argv[1]

    audit = AuditLog()

    if AUDIT_FILE.exists():
        audit.load(AUDIT_FILE)

    transaction_id = (
        audit.create_transaction_id()
    )

    audit.add_event(
        ENCRYPT_STARTED,
        {
            "input_file": str(INPUT_FILE),
            "encrypted_file": str(OUTPUT_FILE)
        },
        transaction_id
    )

    audit.save(AUDIT_FILE)

    temporary_path = OUTPUT_FILE.with_suffix(
        OUTPUT_FILE.suffix + ".tmp"
    )

    if temporary_path.exists():
        temporary_path.unlink()

    encrypt_file(
        INPUT_FILE,
        temporary_path
    )

    encrypted_hash = calculate_file_hash(
        temporary_path
    )

    fsync_file(
        temporary_path
    )

    temporary_path.rename(
        OUTPUT_FILE
    )

    fsync_directory(
        OUTPUT_FILE.parent
    )

    audit.add_event(
        ENCRYPT_COMMITTED,
        {
            "encrypted_file": str(OUTPUT_FILE),
            "encrypted_file_sha256": encrypted_hash
        },
        transaction_id
    )

    audit.save(AUDIT_FILE)

    if crash_point == "after_commit":

        print(
            "SIMULATING HARD PROCESS CRASH",
            flush=True
        )

        print(
            f"Transaction ID: {transaction_id}",
            flush=True
        )

        os._exit(42)

    print(
        "Worker completed unexpectedly."
    )


if __name__ == "__main__":
    main()