import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
import uuid



GENESIS_HASH = "0" * 64

ENCRYPT_STARTED = "ENCRYPT_STARTED"
ENCRYPT_COMMITTED = "ENCRYPT_COMMITTED"
ENCRYPT_PROTECTED = "ENCRYPT_PROTECTED"
ENCRYPT_COMPLETED = "ENCRYPT_COMPLETED"
ENCRYPT_FAILED = "ENCRYPT_FAILED"

DECRYPT_STARTED = "DECRYPT_STARTED"
DECRYPT_COMPLETED = "DECRYPT_COMPLETED"
DECRYPT_FAILED = "DECRYPT_FAILED"

DELETE_STARTED = "DELETE_STARTED"
DELETE_COMPLETED = "DELETE_COMPLETED"
DELETE_FAILED = "DELETE_FAILED"


class AuditLog:

    def __init__(self):
        self.events = []

    def create_transaction_id(self):
        return uuid.uuid4().hex


    def calculate_hash(self, event_data):
        data = json.dumps(
            event_data,
            sort_keys=True,
            separators=(",", ":")
        )

        return hashlib.sha256(
            data.encode("utf-8")
        ).hexdigest()

    def add_event(
        self,
        action,
        details,
        transaction_id=None
    ):
        previous_hash = (
            self.events[-1]["hash"]
            if self.events
            else GENESIS_HASH
        )

        event = {
            "event_id": len(self.events) + 1,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "details": details,
            "previous_hash": previous_hash
        }

        if transaction_id is not None:
            event["transaction_id"] = transaction_id

        event["hash"] = self.calculate_hash(event)

        self.events.append(event)

        return event

    def verify_chain(self):

        if not self.events:
            return True

        for index, event in enumerate(self.events):

            if index == 0:
                expected_previous_hash = GENESIS_HASH
            else:
                expected_previous_hash = (
                    self.events[index - 1]["hash"]
                )

            if event["previous_hash"] != expected_previous_hash:
                return False

            stored_hash = event["hash"]

            event_without_hash = event.copy()

            del event_without_hash["hash"]

            calculated_hash = self.calculate_hash(
                event_without_hash
            )

            if stored_hash != calculated_hash:
                return False

        return True

    def find_events(self, action):
        return [
            event
            for event in self.events
            if event["action"] == action
        ]

    def get_last_event(self, action):
        events = self.find_events(action)

        if not events:
            return None

        return events[-1]


    def save(self, file_path):

        file_path = Path(file_path)

        file_path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        temporary_path = file_path.with_suffix(
            file_path.suffix + ".tmp"
        )

        try:

            # Write the complete audit log to a
            # temporary file first.
            with open(
                temporary_path,
                "w",
                encoding="utf-8"
            ) as file:

                json.dump(
                    self.events,
                    file,
                    indent=4
                )

                file.flush()

                os.fsync(
                    file.fileno()
                )

            # Atomically replace the old audit log.
            os.replace(
                temporary_path,
                file_path
            )

        except Exception:

            # Remove incomplete temporary file.
            if temporary_path.exists():
                try:
                    temporary_path.unlink()
                except OSError:
                    pass

            raise

    def load(self, file_path):

        file_path = Path(file_path)

        with open(
            file_path,
            "r",
            encoding="utf-8"
        ) as file:

            self.events = json.load(file)