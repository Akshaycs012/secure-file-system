from pathlib import Path
import json

from crypto.key_manager import generate_key, save_key
from crypto.key_registry import generate_key_id, KeyRegistry


TEST_DIR = Path("data/key_lifecycle_test")
REGISTRY_FILE = TEST_DIR / "registry.json"


print("===================================")
print("KEY LIFECYCLE TEST")
print("===================================")


# --------------------------------------------------
# Cleanup
# --------------------------------------------------

def cleanup():
    if TEST_DIR.exists():
        for path in TEST_DIR.iterdir():
            if path.is_file():
                path.unlink()

        TEST_DIR.rmdir()


cleanup()
TEST_DIR.mkdir(parents=True, exist_ok=True)


# --------------------------------------------------
# Create test keys
# --------------------------------------------------

print("\n[1] Creating test keys...")

key_a = generate_key()
key_b = generate_key()

key_a_id = generate_key_id(key_a)
key_b_id = generate_key_id(key_b)

key_a_path = TEST_DIR / f"{key_a_id.hex()}.key"
key_b_path = TEST_DIR / f"{key_b_id.hex()}.key"

save_key(key_a, key_a_path)
save_key(key_b, key_b_path)

print(f"Key A: {key_a_id.hex()}")
print(f"Key B: {key_b_id.hex()}")


# --------------------------------------------------
# Register keys
# --------------------------------------------------

print("\n[2] Registering keys...")

registry = KeyRegistry(REGISTRY_FILE)

registry.register_key(
    key_a_id,
    key_a_path
)

registry.register_key(
    key_b_id,
    key_b_path
)

print("Key registration: SUCCESS")


# --------------------------------------------------
# Verify current registry format
# --------------------------------------------------

print("\n[3] Inspecting registry...")

with open(
    REGISTRY_FILE,
    "r",
    encoding="utf-8"
) as file:
    data = json.load(file)

print(json.dumps(data, indent=4))


# --------------------------------------------------
# Verify lookup
# --------------------------------------------------

print("\n[4] Testing key lookup...")

path_a = registry.get_key_path(key_a_id)
path_b = registry.get_key_path(key_b_id)

if path_a == key_a_path and path_b == key_b_path:
    print("Key lookup: SUCCESS")
else:
    print("❌ Key lookup failed")


# --------------------------------------------------
# Verify contains()
# --------------------------------------------------

print("\n[5] Testing registry membership...")

if (
    registry.contains(key_a_id)
    and registry.contains(key_b_id)
):
    print("Registry membership: SUCCESS")
else:
    print("❌ Registry membership failed")


# --------------------------------------------------
# Cleanup
# --------------------------------------------------

cleanup()

print("\n===================================")
print("KEY LIFECYCLE TEST COMPLETE")
print("===================================")