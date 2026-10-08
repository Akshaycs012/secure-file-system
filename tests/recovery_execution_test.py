import subprocess
from pathlib import Path

from crypto.audit import AuditLog
from crypto.recovery import RecoveryManager
from crypto.worm import (
    is_protected,
    unprotect_file
)


AUDIT_FILE = Path(
    "data/audit.json"
)

OUTPUT_FILE = Path(
    "data/crash_recovery_output.bin"
)


def cleanup():

    if OUTPUT_FILE.exists():

        try:
            if is_protected(
                OUTPUT_FILE
            ):
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
        "RECOVERY EXECUTION TEST"
    )

    print(
        "==================================="
    )

    cleanup()

    # -----------------------------------------
    # Create a real crashed transaction
    # -----------------------------------------

    # Use the existing worker but its output path
    # is fixed to crash_real_output.bin.
    #
    # Therefore we first execute the worker and then
    # use the same recovery mechanism against that
    # transaction.

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

    assert result.returncode == 42

    print(
        "✓ Real crash created"
    )

    crashed_file = Path(
        "data/crash_real_output.bin"
    )

    assert crashed_file.exists()

    print(
        "✓ Committed encrypted file exists"
    )

    # -----------------------------------------
    # Load audit
    # -----------------------------------------

    audit = AuditLog()

    audit.load(
        AUDIT_FILE
    )

    assert audit.verify_chain()

    print(
        "✓ Audit chain valid"
    )

    # -----------------------------------------
    # Extract transaction ID
    # -----------------------------------------

    transaction_id = None

    for line in result.stdout.splitlines():

        if line.startswith(
            "Transaction ID:"
        ):

            transaction_id = (
                line.split(
                    ":",
                    1
                )[1].strip()
            )

            break

    assert transaction_id is not None

    print(
        "Transaction ID:",
        transaction_id
    )

    # -----------------------------------------
    # Find incomplete transaction
    # -----------------------------------------

    manager = RecoveryManager(
        audit
    )

    incomplete = (
        manager.find_incomplete_transactions()
    )

    transaction = None

    for candidate in incomplete:

        if (
            candidate["transaction_id"]
            == transaction_id
        ):
            transaction = candidate
            break

    assert transaction is not None

    # -----------------------------------------
    # Confirm initial state
    # -----------------------------------------

    state = manager.inspect_transaction(
        transaction
    )

    print(
        "Initial recovery state:",
        state["status"]
    )

    assert state["status"] == (
        "COMMITTED_UNPROTECTED"
    )

    # -----------------------------------------
    # Execute recovery
    # -----------------------------------------

    result = manager.recover_transaction(
        transaction
    )

    assert result == "RECOVERED"

    print(
        "✓ Transaction recovered"
    )

    # -----------------------------------------
    # Verify WORM
    # -----------------------------------------

    assert is_protected(
        crashed_file
    )

    print(
        "✓ WORM protection restored"
    )

    # -----------------------------------------
    # Reload audit
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
    # Verify transaction completed
    # -----------------------------------------

    manager = RecoveryManager(
        audit
    )

    incomplete = (
        manager.find_incomplete_transactions()
    )

    for candidate in incomplete:

        assert (
            candidate["transaction_id"]
            != transaction_id
        )

    print(
        "✓ Transaction is no longer incomplete"
    )

    # -----------------------------------------
    # Cleanup
    # -----------------------------------------

    cleanup()

    print(
        "\nRECOVERY EXECUTION TEST: PASSED"
    )

    print(
        "==================================="
    )


if __name__ == "__main__":
    main()