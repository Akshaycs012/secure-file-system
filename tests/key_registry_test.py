from pathlib import Path

from crypto.key_registry import KeyRegistry


REGISTRY_FILE = Path("keys/test_registry.json")
KEY_FILE = Path("keys/test_registry.key")


print("===================================")
print("KEY REGISTRY TEST")
print("===================================")


print("\n[1] Creating test key...")

KEY_FILE.parent.mkdir(
    parents=True,
    exist_ok=True
)

KEY_FILE.write_bytes(b"X" * 32)

print("Test key created.")


print("\n[2] Registering key...")

key_id = bytes.fromhex(
    "00112233445566778899aabbccddeeff"
)

registry = KeyRegistry(REGISTRY_FILE)

registry.register_key(
    key_id,
    KEY_FILE
)

print("Key registration: SUCCESS")


print("\n[3] Checking key ID...")

if not registry.contains(key_id):
    raise RuntimeError(
        "Key ID was not registered."
    )

print("Key ID found: SUCCESS")


print("\n[4] Looking up key path...")

key_path = registry.get_key_path(key_id)

print(f"Key path: {key_path}")


if key_path != KEY_FILE:
    raise RuntimeError(
        "Key path does not match."
    )

print("Key lookup: SUCCESS")


print("\n===================================")
print("KEY REGISTRY TEST COMPLETE")
print("===================================")