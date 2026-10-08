from pathlib import Path

from crypto.decrypt import decrypt_file
from crypto.file_format import (
    HEADER_SIZE,
    NONCE_SIZE,
    TAG_SIZE
)


SOURCE_FILE = Path("data/encrypted.bin")
TEST_DIR = Path("data/corruption_tests")
BACKUP_FILE = TEST_DIR / "original.bin"
OUTPUT_FILE = TEST_DIR / "recovered.txt"


print("===================================")
print("ENCRYPTED FILE CORRUPTION TEST")
print("===================================")


def reset_test_file():
    """Restore the encrypted file from the original backup."""
    SOURCE_FILE.write_bytes(
        BACKUP_FILE.read_bytes()
    )


def expect_failure(test_name, modify_function):
    """Run a corruption test and expect decryption to fail."""

    print(f"\n[{test_name}]")

    reset_test_file()

    try:
        modify_function()

        if OUTPUT_FILE.exists():
            OUTPUT_FILE.unlink()

        decrypt_file(
            SOURCE_FILE,
            OUTPUT_FILE
        )

        print(
            "❌ SECURITY FAILURE: "
            "corrupted file was accepted."
        )

    except (ValueError, FileNotFoundError, KeyError) as error:
        print(f"✅ Rejected: {error}")

    finally:
        reset_test_file()

        if OUTPUT_FILE.exists():
            OUTPUT_FILE.unlink()

        temporary_output = OUTPUT_FILE.with_suffix(
            OUTPUT_FILE.suffix + ".tmp"
        )

        if temporary_output.exists():
            temporary_output.unlink()


# --------------------------------------------------
# Step 0: Validate test environment
# --------------------------------------------------

if not SOURCE_FILE.exists():
    raise FileNotFoundError(
        f"Encrypted file not found: {SOURCE_FILE}\n"
        "Run the normal encryption process first."
    )


# --------------------------------------------------
# Prepare test directory
# --------------------------------------------------

TEST_DIR.mkdir(
    parents=True,
    exist_ok=True
)

BACKUP_FILE.write_bytes(
    SOURCE_FILE.read_bytes()
)

print("\nOriginal encrypted file backed up.")


# --------------------------------------------------
# Test 1 — Empty file
# --------------------------------------------------

def make_empty():
    SOURCE_FILE.write_bytes(b"")


expect_failure(
    "1. Empty encrypted file",
    make_empty
)


# --------------------------------------------------
# Test 2 — Truncated header
# --------------------------------------------------

def truncate_header():
    data = SOURCE_FILE.read_bytes()

    SOURCE_FILE.write_bytes(
        data[:10]
    )


expect_failure(
    "2. Truncated header",
    truncate_header
)


# --------------------------------------------------
# Test 3 — Invalid magic
# --------------------------------------------------

def corrupt_magic():
    data = bytearray(
        SOURCE_FILE.read_bytes()
    )

    data[0:4] = b"XXXX"

    SOURCE_FILE.write_bytes(data)


expect_failure(
    "3. Invalid magic number",
    corrupt_magic
)


# --------------------------------------------------
# Test 4 — Invalid version
# --------------------------------------------------

def corrupt_version():
    data = bytearray(
        SOURCE_FILE.read_bytes()
    )

    data[4] = 99

    SOURCE_FILE.write_bytes(data)


expect_failure(
    "4. Invalid file version",
    corrupt_version
)


# --------------------------------------------------
# Test 5 — Invalid algorithm
# --------------------------------------------------

def corrupt_algorithm():
    data = bytearray(
        SOURCE_FILE.read_bytes()
    )

    data[5] = 99

    SOURCE_FILE.write_bytes(data)


expect_failure(
    "5. Invalid encryption algorithm",
    corrupt_algorithm
)


# --------------------------------------------------
# Test 6 — Invalid nonce size
# --------------------------------------------------

def corrupt_nonce_size():
    data = bytearray(
        SOURCE_FILE.read_bytes()
    )

    data[6] = 11

    SOURCE_FILE.write_bytes(data)


expect_failure(
    "6. Invalid nonce size",
    corrupt_nonce_size
)


# --------------------------------------------------
# Test 7 — Invalid authentication tag size
# --------------------------------------------------

def corrupt_tag_size():
    data = bytearray(
        SOURCE_FILE.read_bytes()
    )

    data[7] = 15

    SOURCE_FILE.write_bytes(data)


expect_failure(
    "7. Invalid authentication tag size",
    corrupt_tag_size
)


# --------------------------------------------------
# Test 8 — Truncated nonce
# --------------------------------------------------

def truncate_nonce():
    data = SOURCE_FILE.read_bytes()

    truncated = (
        data[:HEADER_SIZE]
        + data[HEADER_SIZE:HEADER_SIZE + 6]
    )

    SOURCE_FILE.write_bytes(
        truncated
    )


expect_failure(
    "8. Truncated nonce",
    truncate_nonce
)


# --------------------------------------------------
# Test 9 — Truncated authentication tag
# --------------------------------------------------

def truncate_tag():
    data = SOURCE_FILE.read_bytes()

    # Keep header + nonce + only 8 bytes
    # from the final authentication tag.
    truncated = (
        data[
            :HEADER_SIZE
            + NONCE_SIZE
            + 8
        ]
    )

    SOURCE_FILE.write_bytes(
        truncated
    )


expect_failure(
    "9. Truncated authentication tag",
    truncate_tag
)


# --------------------------------------------------
# Test 10 — Empty ciphertext
# --------------------------------------------------

def remove_ciphertext():
    data = SOURCE_FILE.read_bytes()

    # Keep header + nonce + tag.
    #
    # In the new format the tag is at the END,
    # so extract the original final 16 bytes.
    tag = data[-TAG_SIZE:]

    truncated = (
        data[:HEADER_SIZE + NONCE_SIZE]
        + tag
    )

    SOURCE_FILE.write_bytes(
        truncated
    )


expect_failure(
    "10. Empty ciphertext",
    remove_ciphertext
)


# --------------------------------------------------
# Test 11 — Modified ciphertext
# --------------------------------------------------

def modify_ciphertext():
    data = bytearray(
        SOURCE_FILE.read_bytes()
    )

    ciphertext_start = (
        HEADER_SIZE + NONCE_SIZE
    )

    # Modify the first ciphertext byte.
    data[ciphertext_start] ^= 0x01

    SOURCE_FILE.write_bytes(data)


expect_failure(
    "11. Modified ciphertext",
    modify_ciphertext
)


# --------------------------------------------------
# Test 12 — Modified authentication tag
# --------------------------------------------------

def modify_tag():
    data = bytearray(
        SOURCE_FILE.read_bytes()
    )

    tag_start = len(data) - TAG_SIZE

    data[tag_start] ^= 0x01

    SOURCE_FILE.write_bytes(data)


expect_failure(
    "12. Modified authentication tag",
    modify_tag
)


# --------------------------------------------------
# Test 13 — Modified nonce
# --------------------------------------------------

def modify_nonce():
    data = bytearray(
        SOURCE_FILE.read_bytes()
    )

    nonce_start = HEADER_SIZE

    data[nonce_start] ^= 0x01

    SOURCE_FILE.write_bytes(data)


expect_failure(
    "13. Modified nonce",
    modify_nonce
)


# --------------------------------------------------
# Test 14 — Modified header
# --------------------------------------------------

def modify_header():
    data = bytearray(
        SOURCE_FILE.read_bytes()
    )

    # Key ID begins after:
    #
    # MAGIC       = 4 bytes
    # VERSION     = 1 byte
    # ALGORITHM   = 1 byte
    # NONCE SIZE  = 1 byte
    # TAG SIZE    = 1 byte
    #
    # Therefore Key ID starts at byte 8.

    key_id_start = 8

    data[key_id_start] ^= 0x01

    SOURCE_FILE.write_bytes(data)


expect_failure(
    "14. Modified header / Key ID",
    modify_header
)


# --------------------------------------------------
# Cleanup
# --------------------------------------------------

if BACKUP_FILE.exists():
    BACKUP_FILE.unlink()

if OUTPUT_FILE.exists():
    OUTPUT_FILE.unlink()

temporary_output = OUTPUT_FILE.with_suffix(
    OUTPUT_FILE.suffix + ".tmp"
)

if temporary_output.exists():
    temporary_output.unlink()


print("\n===================================")
print("CORRUPTION TEST COMPLETE")
print("===================================")