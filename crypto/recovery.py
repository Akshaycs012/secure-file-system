from pathlib import Path

from crypto.audit import (
    ENCRYPT_STARTED,
    ENCRYPT_COMMITTED,
    ENCRYPT_PROTECTED,
    ENCRYPT_COMPLETED,
    ENCRYPT_FAILED
)

from crypto.worm import (
    is_protected,
    protect_file
)

from crypto.hashing import calculate_file_hash

from crypto.durability import (
    fsync_directory
)


class RecoveryManager:

    def __init__(self, audit_log):
        self.audit = audit_log

    def find_incomplete_transactions(self):
        """
        Find encryption transactions that did not reach
        ENCRYPT_COMPLETED or ENCRYPT_FAILED.
        """

        transactions = {}

        for event in self.audit.events:

            transaction_id = event.get(
                "transaction_id"
            )

            if not transaction_id:
                continue

            if transaction_id not in transactions:
                transactions[transaction_id] = []

            transactions[transaction_id].append(event)

        incomplete = []

        for transaction_id, events in transactions.items():

            actions = [
                event["action"]
                for event in events
            ]

            if ENCRYPT_COMPLETED in actions:
                continue

            if ENCRYPT_FAILED in actions:
                continue

            incomplete.append({
                "transaction_id": transaction_id,
                "events": events,
                "last_action": actions[-1]
            })

        return incomplete

    def _get_event(
        self,
        transaction,
        action
    ):
        """
        Return the event with the specified action
        from a transaction.
        """

        for event in transaction["events"]:

            if event["action"] == action:
                return event

        return None

    def _get_encrypted_file(
        self,
        transaction
    ):
        """
        Determine the encrypted file associated with
        the transaction.
        """

        # Prefer ENCRYPT_COMMITTED because this event
        # represents a durable filesystem commit.
        event = self._get_event(
            transaction,
            ENCRYPT_COMMITTED
        )

        if event is not None:

            encrypted_file = event[
                "details"
            ].get("encrypted_file")

            if encrypted_file:
                return Path(encrypted_file)

        # Fall back to ENCRYPT_STARTED.
        event = self._get_event(
            transaction,
            ENCRYPT_STARTED
        )

        if event is not None:

            encrypted_file = event[
                "details"
            ].get("encrypted_file")

            if encrypted_file:
                return Path(encrypted_file)

        return None

    def _get_expected_hash(
        self,
        transaction
    ):
        """
        Get the SHA-256 hash recorded when the encrypted
        file was durably committed.
        """

        event = self._get_event(
            transaction,
            ENCRYPT_COMMITTED
        )

        if event is None:
            return None

        return event[
            "details"
        ].get("encrypted_file_sha256")

    def _verify_committed_file(
        self,
        transaction
    ):
        """
        Verify that the existing encrypted file matches
        the SHA-256 hash recorded in ENCRYPT_COMMITTED.
        """

        encrypted_path = self._get_encrypted_file(
            transaction
        )

        if encrypted_path is None:
            raise ValueError(
                "Transaction has no encrypted file path."
            )

        if not encrypted_path.exists():
            raise FileNotFoundError(
                "Committed encrypted file does not exist: "
                f"{encrypted_path}"
            )

        if encrypted_path.is_symlink():
            raise ValueError(
                "Refusing to recover a symbolic link: "
                f"{encrypted_path}"
            )

        if not encrypted_path.is_file():
            raise ValueError(
                "Committed encrypted output is not a "
                "regular file: "
                f"{encrypted_path}"
            )

        expected_hash = self._get_expected_hash(
            transaction
        )

        if expected_hash is None:
            raise ValueError(
                "Transaction has no committed SHA-256 hash."
            )

        actual_hash = calculate_file_hash(
            encrypted_path
        )

        if actual_hash != expected_hash:
            raise ValueError(
                "Recovery integrity check failed.\n"
                f"Expected: {expected_hash}\n"
                f"Actual:   {actual_hash}"
            )

        return encrypted_path

    def inspect_transaction(
        self,
        transaction
    ):
        """
        Determine the filesystem state of an incomplete
        encryption transaction.
        """

        transaction_id = transaction[
            "transaction_id"
        ]

        encrypted_path = self._get_encrypted_file(
            transaction
        )

        result = {
            "transaction_id": transaction_id,
            "last_action": transaction[
                "last_action"
            ],
            "encrypted_file": (
                str(encrypted_path)
                if encrypted_path
                else None
            ),
            "status": "UNKNOWN"
        }

        if encrypted_path is None:
            result["status"] = (
                "INVALID_TRANSACTION"
            )
            return result

        if not encrypted_path.exists():
            result["status"] = (
                "MISSING_OUTPUT"
            )
            return result

        try:
            protected = is_protected(
                encrypted_path
            )
        except Exception:
            protected = False

        last_action = transaction[
            "last_action"
        ]

        if last_action == ENCRYPT_STARTED:

            if protected:
                result["status"] = (
                    "STARTED_BUT_PROTECTED"
                )
            else:
                result["status"] = (
                    "STARTED_UNPROTECTED"
                )

        elif last_action == ENCRYPT_COMMITTED:

            if protected:
                result["status"] = (
                    "COMMITTED_AND_PROTECTED"
                )
            else:
                result["status"] = (
                    "COMMITTED_UNPROTECTED"
                )

        elif last_action == ENCRYPT_PROTECTED:

            if protected:
                result["status"] = (
                    "PROTECTED_INCOMPLETE"
                )
            else:
                result["status"] = (
                    "PROTECTION_LOST"
                )

        else:
            result["status"] = (
                "UNKNOWN_TRANSACTION_STATE"
            )

        return result

    def scan(self):
        """
        Scan the audit log for incomplete transactions.
        """

        incomplete = (
            self.find_incomplete_transactions()
        )

        results = []

        for transaction in incomplete:

            results.append(
                self.inspect_transaction(
                    transaction
                )
            )

        return results

    def recover_transaction(
        self,
        transaction
    ):
        """
        Safely recover an incomplete encryption
        transaction.

        Only committed transactions with a valid
        SHA-256 hash may be automatically recovered.
        """

        transaction_id = transaction[
            "transaction_id"
        ]

        state = self.inspect_transaction(
            transaction
        )

        status = state["status"]

        print(
            f"Recovering transaction: "
            f"{transaction_id}"
        )

        print(
            f"Detected state: {status}"
        )

        # -------------------------------------------------
        # CASE 1: COMMITTED_UNPROTECTED
        # -------------------------------------------------

        if status == "COMMITTED_UNPROTECTED":

            print(
                "Verifying committed file integrity..."
            )

            encrypted_path = (
                self._verify_committed_file(
                    transaction
                )
            )

            print(
                "SHA-256 verification: VALID"
            )

            print(
                "Applying WORM protection..."
            )

            protect_file(
                encrypted_path
            )

            if not is_protected(
                encrypted_path
            ):
                raise RuntimeError(
                    "WORM protection verification failed."
                )

            fsync_directory(
                encrypted_path.parent
            )

            print(
                "WORM protection: ENABLED"
            )

            self.audit.add_event(
                ENCRYPT_PROTECTED,
                {
                    "encrypted_file":
                        str(encrypted_path),
                    "recovered": True
                },
                transaction_id
            )

            self.audit.save(
                Path("data/audit.json")
            )

            self.audit.add_event(
                ENCRYPT_COMPLETED,
                {
                    "encrypted_file":
                        str(encrypted_path),
                    "encrypted_file_sha256":
                        calculate_file_hash(
                            encrypted_path
                        ),
                    "recovered": True
                },
                transaction_id
            )

            self.audit.save(
                Path("data/audit.json")
            )

            print(
                "Transaction recovery: COMPLETE"
            )

            return "RECOVERED"

        # -------------------------------------------------
        # CASE 2: COMMITTED_AND_PROTECTED
        # -------------------------------------------------

        if status == "COMMITTED_AND_PROTECTED":

            print(
                "Committed file is already "
                "WORM protected."
            )

            encrypted_path = (
                self._verify_committed_file(
                    transaction
                )
            )

            print(
                "SHA-256 verification: VALID"
            )

            self.audit.add_event(
                ENCRYPT_PROTECTED,
                {
                    "encrypted_file":
                        str(encrypted_path),
                    "recovered": True
                },
                transaction_id
            )

            self.audit.save(
                Path("data/audit.json")
            )

            self.audit.add_event(
                ENCRYPT_COMPLETED,
                {
                    "encrypted_file":
                        str(encrypted_path),
                    "encrypted_file_sha256":
                        calculate_file_hash(
                            encrypted_path
                        ),
                    "recovered": True
                },
                transaction_id
            )

            self.audit.save(
                Path("data/audit.json")
            )

            print(
                "Transaction recovery: COMPLETE"
            )

            return "RECOVERED"

        # -------------------------------------------------
        # CASE 3: PROTECTED_INCOMPLETE
        # -------------------------------------------------

        if status == "PROTECTED_INCOMPLETE":

            print(
                "Encrypted file is already "
                "WORM protected."
            )

            encrypted_path = (
                self._verify_committed_file(
                    transaction
                )
            )

            print(
                "SHA-256 verification: VALID"
            )

            self.audit.add_event(
                ENCRYPT_COMPLETED,
                {
                    "encrypted_file":
                        str(encrypted_path),
                    "encrypted_file_sha256":
                        calculate_file_hash(
                            encrypted_path
                        ),
                    "recovered": True
                },
                transaction_id
            )

            self.audit.save(
                Path("data/audit.json")
            )

            print(
                "Transaction recovery: COMPLETE"
            )

            return "RECOVERED"

        # -------------------------------------------------
        # UNSAFE STATES
        # -------------------------------------------------

        if status == "STARTED_UNPROTECTED":

            raise RuntimeError(
                "Unsafe recovery state: "
                "ENCRYPT_STARTED was recorded, "
                "but no durable committed SHA-256 "
                "hash exists. Automatic recovery "
                "is not permitted."
            )

        if status == "MISSING_OUTPUT":

            raise RuntimeError(
                "Cannot recover transaction: "
                "committed encrypted output is missing."
            )

        if status == "PROTECTION_LOST":

            raise RuntimeError(
                "Cannot automatically recover: "
                "WORM protection was previously recorded "
                "but is no longer active."
            )

        raise RuntimeError(
            "Unsupported recovery state: "
            f"{status}"
        )


def find_temporary_files(directory):
    """
    Find stale .tmp files created by the secure
    encryption workflow.
    """

    directory = Path(directory)

    if not directory.exists():
        return []

    if not directory.is_dir():
        raise ValueError(
            f"Not a directory: {directory}"
        )

    return sorted(
        path
        for path in directory.glob("*.tmp")
        if path.is_file()
        and not path.is_symlink()
    )


def recovery_scan(
    audit_log,
    directory
):
    """
    Perform a complete recovery scan.
    """

    manager = RecoveryManager(
        audit_log
    )

    incomplete_transactions = (
        manager.scan()
    )

    temporary_files = (
        find_temporary_files(directory)
    )

    return {
        "incomplete_transactions":
            incomplete_transactions,

        "temporary_files":
            temporary_files
    }