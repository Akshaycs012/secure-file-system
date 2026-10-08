from pathlib import Path
import shutil

from crypto.audit import (
    AuditLog,
    ENCRYPT_STARTED,
    ENCRYPT_COMMITTED,
    ENCRYPT_PROTECTED,
    ENCRYPT_COMPLETED
)

from crypto.recovery import RecoveryManager


TEST_DIR = Path("data/crash_recovery_test")


def clean():
    if TEST_DIR.exists():
        shutil.rmtree(TEST_DIR)

    TEST_DIR.mkdir(
        parents=True,
        exist_ok=True
    )


def create_transaction(
    actions,
    encrypted_file
):
    audit = AuditLog()

    transaction_id = (
        audit.create_transaction_id()
    )

    for action in actions:

        audit.add_event(
            action,
            {
                "encrypted_file":
                    str(encrypted_file)
            },
            transaction_id
        )

    return audit, transaction_id


def test_crash_after_started():

    clean()

    encrypted_file = (
        TEST_DIR / "started.bin"
    )

    encrypted_file.write_bytes(
        b"encrypted data"
    )

    audit, transaction_id = (
        create_transaction(
            [ENCRYPT_STARTED],
            encrypted_file
        )
    )

    manager = RecoveryManager(audit)

    incomplete = (
        manager.find_incomplete_transactions()
    )

    assert len(incomplete) == 1

    result = manager.inspect_transaction(
        incomplete[0]
    )

    assert result["transaction_id"] == (
        transaction_id
    )

    assert result["status"] == (
        "STARTED_UNPROTECTED"
    )

    print(
        "✓ Crash after ENCRYPT_STARTED detected"
    )


def test_crash_after_committed():

    clean()

    encrypted_file = (
        TEST_DIR / "committed.bin"
    )

    encrypted_file.write_bytes(
        b"encrypted data"
    )

    audit, transaction_id = (
        create_transaction(
            [
                ENCRYPT_STARTED,
                ENCRYPT_COMMITTED
            ],
            encrypted_file
        )
    )

    manager = RecoveryManager(audit)

    incomplete = (
        manager.find_incomplete_transactions()
    )

    assert len(incomplete) == 1

    result = manager.inspect_transaction(
        incomplete[0]
    )

    assert result["transaction_id"] == (
        transaction_id
    )

    assert result["status"] == (
        "COMMITTED_UNPROTECTED"
    )

    print(
        "✓ Crash after ENCRYPT_COMMITTED detected"
    )


def test_crash_after_protected():

    clean()

    encrypted_file = (
        TEST_DIR / "protected.bin"
    )

    encrypted_file.write_bytes(
        b"encrypted data"
    )

    # We cannot safely depend on WSL filesystem
    # attributes inside this unit test, so test
    # transaction detection separately.
    audit, transaction_id = (
        create_transaction(
            [
                ENCRYPT_STARTED,
                ENCRYPT_COMMITTED,
                ENCRYPT_PROTECTED
            ],
            encrypted_file
        )
    )

    manager = RecoveryManager(audit)

    incomplete = (
        manager.find_incomplete_transactions()
    )

    assert len(incomplete) == 1

    assert (
        incomplete[0]["last_action"]
        == ENCRYPT_PROTECTED
    )

    print(
        "✓ Crash after ENCRYPT_PROTECTED detected"
    )


def test_completed_transaction():

    clean()

    encrypted_file = (
        TEST_DIR / "completed.bin"
    )

    encrypted_file.write_bytes(
        b"encrypted data"
    )

    audit, transaction_id = (
        create_transaction(
            [
                ENCRYPT_STARTED,
                ENCRYPT_COMMITTED,
                ENCRYPT_PROTECTED,
                ENCRYPT_COMPLETED
            ],
            encrypted_file
        )
    )

    manager = RecoveryManager(audit)

    incomplete = (
        manager.find_incomplete_transactions()
    )

    assert incomplete == []

    print(
        "✓ Completed transaction ignored"
    )


def main():

    print(
        "==================================="
    )

    print(
        "CRASH RECOVERY SIMULATION TEST"
    )

    print(
        "==================================="
    )

    test_crash_after_started()

    test_crash_after_committed()

    test_crash_after_protected()

    test_completed_transaction()

    if TEST_DIR.exists():
        shutil.rmtree(TEST_DIR)

    print(
        "\nCrash recovery simulation: PASSED"
    )

    print(
        "==================================="
    )


if __name__ == "__main__":
    main()