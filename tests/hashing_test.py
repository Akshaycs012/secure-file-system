from pathlib import Path

from crypto.hashing import calculate_file_hash


TEST_FILE = Path("data/original.txt")


print("===================================")
print("SHA-256 FILE HASH TEST")
print("===================================")


print("\nCalculating SHA-256...")

file_hash = calculate_file_hash(TEST_FILE)


print(f"\nFile : {TEST_FILE}")
print(f"SHA-256: {file_hash}")


if len(file_hash) == 64:
    print("\nHash generation: SUCCESS")
else:
    print("\nHash generation: FAILED")


print("\n===================================")
print("HASH TEST COMPLETE")
print("===================================")