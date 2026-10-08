from crypto.file_format import (
    create_header,
    parse_header,
    HEADER_SIZE,
    KEY_ID_SIZE
)


print("===================================")
print("FILE FORMAT KEY ID TEST")
print("===================================")


print("\n[1] Creating key ID...")

key_id = bytes.fromhex(
    "00112233445566778899aabbccddeeff"
)

print(f"Key ID size: {len(key_id)} bytes")


print("\n[2] Creating header...")

header = create_header(key_id)

print(f"Header size: {len(header)} bytes")
print(f"Expected size: {HEADER_SIZE} bytes")


if len(header) != HEADER_SIZE:
    raise RuntimeError(
        "Header size is incorrect."
    )

print("Header creation: SUCCESS")


print("\n[3] Parsing header...")

metadata = parse_header(header)

print(
    f"Version: {metadata['version']}"
)

print(
    f"Algorithm: {metadata['algorithm']}"
)

print(
    f"Nonce size: {metadata['nonce_size']}"
)

print(
    f"Tag size: {metadata['tag_size']}"
)

print(
    f"Key ID: {metadata['key_id'].hex()}"
)


print("\n[4] Verifying key ID...")

if metadata["key_id"] != key_id:
    raise RuntimeError(
        "Key ID mismatch."
    )

print("Key ID verification: SUCCESS")


print("\n===================================")
print("FILE FORMAT TEST COMPLETE")
print("===================================")