import subprocess
from pathlib import Path

from crypto.audit import AuditLog
from crypto.recovery import RecoveryManager


AUDIT_FILE = Path("data/audit.json")
OUTPUT_FILE = Path(
    "data/crash_real_output.bin"
)


def cleanup():
    """
    Remove the test output file safely.
    """

    if OUTPUT_FILE.exists():

        from crypto.worm import (
            is_protected,
            unprotect_file
        )

        try:
            if is_protected(OUTPUT_FILE):
                unprotect_file(
                    OUTPUT_FILE
                )
        except Exception:
            pass

        OUTPUT_FILE.unlink()


def main():

    print(
        "==================================="
    )

    print(
        "REAL PROCESS CRASH TEST"
    )

    print(
        "==================================="
    )

    # -----------------------------------------
    # Clean previous test output
    # -----------------------------------------

    cleanup()

    # -----------------------------------------
    # Start crash worker
    # -----------------------------------------

    command = [
        "python",
        "-m",
        "tests.crash_worker",
        "after_commit"
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    # -----------------------------------------
    # Display worker result
    # -----------------------------------------

    print(
        "Worker exit code:",
        result.returncode
    )

    print(
        "\n--- WORKER STDOUT ---"
    )

    print(
        result.stdout
    )

    print(
        "\n--- WORKER STDERR ---"
    )

    print(
        result.stderr
    )

    # -----------------------------------------
    # Verify hard crash
    # -----------------------------------------

    assert result.returncode == 42

    print(
        "✓ Worker terminated unexpectedly"
    )

    # -----------------------------------------
    # Extract transaction ID created by worker
    # -----------------------------------------

    worker_transaction_id = None

    for line in result.stdout.splitlines():

        if line.startswith(
            "Transaction ID:"
        ):

            worker_transaction_id = (
                line.split(
                    ":",
                    1
                )[1].strip()
            )

            break

    assert worker_transaction_id is not None

    print(
        "Worker transaction ID:",
        worker_transaction_id
    )

    # -----------------------------------------
    # Verify committed output exists
    # -----------------------------------------

    assert OUTPUT_FILE.exists()

    print(
        "✓ Committed encrypted output exists"
    )

    # -----------------------------------------
    # Load and verify audit log
    # -----------------------------------------

    audit = AuditLog()

    audit.load(
        AUDIT_FILE
    )

    assert audit.verify_chain()

    print(
        "✓ Audit chain remains valid"
    )

    # -----------------------------------------
    # Run recovery scan
    # -----------------------------------------

    manager = RecoveryManager(
        audit
    )

    incomplete = (
        manager.find_incomplete_transactions()
    )

    # -----------------------------------------
    # Find THIS exact crashed transaction
    # -----------------------------------------

    matching = []

    for transaction in incomplete:

        if (
            transaction["transaction_id"]
            == worker_transaction_id
        ):

            matching.append(
                transaction
            )

    assert len(matching) == 1

    # -----------------------------------------
    # Inspect crashed transaction
    # -----------------------------------------

    recovery_result = (
        manager.inspect_transaction(
            matching[0]
        )
    )

    print(
        "Recovery classification:",
        recovery_result["status"]
    )

    # -----------------------------------------
    # Verify expected crash state
    # -----------------------------------------

    assert (
        recovery_result["transaction_id"]
        == worker_transaction_id
    )

    assert (
        recovery_result["encrypted_file"]
        == str(OUTPUT_FILE)
    )

    assert (
        recovery_result["last_action"]
        == "ENCRYPT_COMMITTED"
    )

    assert (
        recovery_result["status"]
        == "COMMITTED_UNPROTECTED"
    )

    print(
        "✓ Crash correctly detected"
    )

    # -----------------------------------------
    # Cleanup
    # -----------------------------------------

    cleanup()

    print(
        "\nREAL CRASH TEST: PASSED"
    )

    print(
        "==================================="
    )


if __name__ == "__main__":
    main()