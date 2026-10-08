from crypto.audit import (
    AuditLog,
    ENCRYPT_STARTED,
    ENCRYPT_COMMITTED,
    ENCRYPT_PROTECTED,
    ENCRYPT_COMPLETED
)


def main():
    audit = AuditLog()

    transaction_id = audit.create_transaction_id()

    audit.add_event(
        ENCRYPT_STARTED,
        {
            "input_file": "data/original.txt",
            "encrypted_file": "data/test.bin"
        },
        transaction_id
    )

    audit.add_event(
        ENCRYPT_COMMITTED,
        {
            "encrypted_file": "data/test.bin"
        },
        transaction_id
    )

    audit.add_event(
        ENCRYPT_PROTECTED,
        {
            "encrypted_file": "data/test.bin"
        },
        transaction_id
    )

    audit.add_event(
        ENCRYPT_COMPLETED,
        {
            "encrypted_file": "data/test.bin"
        },
        transaction_id
    )

    assert len(audit.events) == 4

    for event in audit.events:
        assert event["transaction_id"] == transaction_id

    assert audit.verify_chain()

    print("Audit transaction test: PASSED")
    print(f"Transaction ID: {transaction_id}")


if __name__ == "__main__":
    main()