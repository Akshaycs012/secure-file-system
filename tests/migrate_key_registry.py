from pathlib import Path
import json

from crypto.key_rotation import get_current_key_id


REGISTRY_FILE = Path("keys/registry.json")


print("===================================")
print("KEY REGISTRY MIGRATION")
print("===================================")


# --------------------------------------------------
# Load current key
# --------------------------------------------------

current_key_id = get_current_key_id()
current_key_hex = current_key_id.hex()

print(
    f"\nCurrent Key ID: {current_key_hex}"
)


# --------------------------------------------------
# Load registry
# --------------------------------------------------

with open(
    REGISTRY_FILE,
    "r",
    encoding="utf-8"
) as file:

    registry = json.load(file)


# --------------------------------------------------
# Validate and migrate entries
# --------------------------------------------------

migrated_registry = {}

for key_id, entry in registry.items():

    # Existing format:
    #
    # "key_id": "keys/example.key"

    if isinstance(entry, str):

        path = entry

        if key_id == current_key_hex:
            status = "ACTIVE"
        else:
            status = "RETIRED"

        migrated_registry[key_id] = {
            "path": path,
            "status": status
        }

    # Already migrated format.
    elif isinstance(entry, dict):

        if "path" not in entry:
            raise ValueError(
                f"Missing path for Key ID: {key_id}"
            )

        status = entry.get(
            "status",
            "RETIRED"
        )

        # The key referenced by current_key_id
        # must be ACTIVE.
        if key_id == current_key_hex:
            status = "ACTIVE"

        migrated_registry[key_id] = {
            "path": entry["path"],
            "status": status
        }

    else:

        raise ValueError(
            f"Invalid registry entry for Key ID: {key_id}"
        )


# --------------------------------------------------
# Display proposed migration
# --------------------------------------------------

print("\nProposed registry:")

print(
    json.dumps(
        migrated_registry,
        indent=4
    )
)


# --------------------------------------------------
# Write migrated registry
# --------------------------------------------------

temporary_file = REGISTRY_FILE.with_suffix(
    REGISTRY_FILE.suffix + ".tmp"
)

with open(
    temporary_file,
    "w",
    encoding="utf-8"
) as file:

    json.dump(
        migrated_registry,
        file,
        indent=4
    )

    file.flush()


temporary_file.replace(
    REGISTRY_FILE
)


print("\nMigration completed successfully.")

print(
    f"Current key {current_key_hex}: ACTIVE"
)


print("\n===================================")
print("REGISTRY MIGRATION COMPLETE")
print("===================================")