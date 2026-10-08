from pathlib import Path

from crypto.audit import AuditLog
from crypto.recovery import (
    RecoveryManager,
    find_temporary_files
)


TEST_DIR = Path(
    "data/recovery_test"
)


def test_no_incomplete_transactions():

    audit = AuditLog()

    manager = RecoveryManager(
        audit
    )

    result = (
        manager.find_incomplete_transactions()
    )

    assert result == []

    print(
        "✓ No incomplete transactions detected"
    )


def test_stale_tmp_detection():

    TEST_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    temporary_file = (
        TEST_DIR / "example.bin.tmp"
    )

    temporary_file.write_bytes(
        b"temporary data"
    )

    files = find_temporary_files(
        TEST_DIR
    )

    assert temporary_file in files

    temporary_file.unlink()
    TEST_DIR.rmdir()

    print(
        "✓ Stale temporary file detected"
    )


def main():

    print(
        "==================================="
    )

    print(
        "RECOVERY SYSTEM TEST"
    )

    print(
        "==================================="
    )

    test_no_incomplete_transactions()

    test_stale_tmp_detection()

    print(
        "\nRecovery tests: PASSED"
    )


if __name__ == "__main__":
    main()