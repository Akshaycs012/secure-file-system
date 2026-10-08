import hashlib
import json
from pathlib import Path


REGISTRY_FILE = Path("keys/registry.json")

KEY_ID_SIZE = 16

ACTIVE = "ACTIVE"
RETIRED = "RETIRED"
REVOKED = "REVOKED"

VALID_STATUSES = {
    ACTIVE,
    RETIRED,
    REVOKED
}


def generate_key_id(key):
    if not isinstance(key, bytes):
        raise TypeError("key must be bytes.")

    if len(key) != 32:
        raise ValueError(
            "AES-256 key must be exactly 32 bytes."
        )

    return hashlib.sha256(key).digest()[:KEY_ID_SIZE]


class KeyRegistry:

    def __init__(self, registry_path=REGISTRY_FILE):
        self.registry_path = Path(registry_path)

    # --------------------------------------------------
    # Internal helpers
    # --------------------------------------------------

    def _load(self):

        if not self.registry_path.exists():
            return {}

        with open(
            self.registry_path,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    def _save(self, registry):

        self.registry_path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        temporary_path = self.registry_path.with_suffix(
            self.registry_path.suffix + ".tmp"
        )

        try:

            with open(
                temporary_path,
                "w",
                encoding="utf-8"
            ) as file:

                json.dump(
                    registry,
                    file,
                    indent=4
                )

                file.flush()

                import os
                os.fsync(file.fileno())

            import os
            os.replace(
                temporary_path,
                self.registry_path
            )

        except Exception:

            if temporary_path.exists():
                try:
                    temporary_path.unlink()
                except OSError:
                    pass

            raise

    def _validate_key_id(self, key_id):

        if not isinstance(key_id, bytes):
            raise TypeError(
                "key_id must be bytes."
            )

        if len(key_id) != KEY_ID_SIZE:
            raise ValueError(
                "Key ID must be exactly 16 bytes."
            )

    def _get_entry(self, key_id):

        self._validate_key_id(key_id)

        registry = self._load()

        key_id_hex = key_id.hex()

        if key_id_hex not in registry:
            raise KeyError(
                f"Unknown key ID: {key_id_hex}"
            )

        entry = registry[key_id_hex]

        # --------------------------------------------------
        # Backward compatibility
        # --------------------------------------------------

        # Old format:
        #
        # "key_id": "keys/file.key"
        #
        if isinstance(entry, str):

            return {
                "path": entry,
                "status": RETIRED
            }

        # New format:
        #
        # "key_id": {
        #     "path": "...",
        #     "status": "ACTIVE"
        # }

        if not isinstance(entry, dict):
            raise ValueError(
                f"Invalid registry entry for Key ID: "
                f"{key_id_hex}"
            )

        if "path" not in entry:
            raise ValueError(
                f"Registry entry has no key path: "
                f"{key_id_hex}"
            )

        status = entry.get(
            "status",
            RETIRED
        )

        if status not in VALID_STATUSES:
            raise ValueError(
                f"Invalid key status '{status}' "
                f"for Key ID {key_id_hex}"
            )

        return {
            "path": entry["path"],
            "status": status
        }

    # --------------------------------------------------
    # Registration
    # --------------------------------------------------

    def register_key(
        self,
        key_id,
        key_path,
        status=ACTIVE
    ):

        self._validate_key_id(key_id)

        if status not in VALID_STATUSES:
            raise ValueError(
                f"Invalid key status: {status}"
            )

        key_path = Path(key_path)

        if not key_path.exists():
            raise FileNotFoundError(
                f"Key file not found: {key_path}"
            )

        registry = self._load()

        key_id_hex = key_id.hex()

        if key_id_hex in registry:

            existing = registry[key_id_hex]

            if isinstance(existing, str):
                existing_path = existing
            else:
                existing_path = existing.get(
                    "path"
                )

            if existing_path != str(key_path):
                raise ValueError(
                    "Key ID is already registered "
                    "with another key."
                )

            return

        registry[key_id_hex] = {
            "path": str(key_path),
            "status": status
        }

        self._save(registry)

    # --------------------------------------------------
    # Key path
    # --------------------------------------------------

    def get_key_path(self, key_id):

        entry = self._get_entry(key_id)

        return Path(entry["path"])

    # --------------------------------------------------
    # Key status
    # --------------------------------------------------

    def get_status(self, key_id):

        entry = self._get_entry(key_id)

        return entry["status"]

    # --------------------------------------------------
    # Change status
    # --------------------------------------------------

    def set_status(self, key_id, status):

        self._validate_key_id(key_id)

        if status not in VALID_STATUSES:
            raise ValueError(
                f"Invalid key status: {status}"
            )

        registry = self._load()

        key_id_hex = key_id.hex()

        if key_id_hex not in registry:
            raise KeyError(
                f"Unknown key ID: {key_id_hex}"
            )

        entry = registry[key_id_hex]

        # Convert old format into new format.
        if isinstance(entry, str):

            entry = {
                "path": entry,
                "status": RETIRED
            }

        entry["status"] = status

        registry[key_id_hex] = entry

        self._save(registry)

    # --------------------------------------------------
    # Lifecycle operations
    # --------------------------------------------------

    def retire_key(self, key_id):

        self.set_status(
            key_id,
            RETIRED
        )

    def revoke_key(self, key_id):

        self.set_status(
            key_id,
            REVOKED
        )

    # --------------------------------------------------
    # Encryption / decryption permissions
    # --------------------------------------------------

    def can_encrypt(self, key_id):

        return self.get_status(key_id) == ACTIVE

    def can_decrypt(self, key_id):

        status = self.get_status(key_id)

        return status in {
            ACTIVE,
            RETIRED
        }

    # --------------------------------------------------
    # Registry membership
    # --------------------------------------------------

    def contains(self, key_id):

        self._validate_key_id(key_id)

        registry = self._load()

        return key_id.hex() in registry