from pathlib import Path

from crypto.decrypt import decrypt_file
from crypto.file_format import (
    HEADER_SIZE,
    NONCE_SIZE,
    TAG_SIZE
)


SOURCE_FILE = Path("data/encrypted.bin")
TEST_DIR = Path("data/structure_tests")
BACKUP_FILE = TEST_DIR / "original.bin"
OUTPUT_FILE = TEST_DIR / "recovered.txt"


print("===================================")
print("ENCRYPTED FILE STRUCTURE TEST")
print("===================================")


def reset_test_file():
    SOURCE_FILE.write_bytes(
        BACKUP_FILE.read_bytes()
    )


def expect_failure(test_name, modify_function):
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
            "malformed file was accepted."
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


if not SOURCE_FILE.exists():
    raise FileNotFoundError(
        f"Encrypted file not found: {SOURCE_FILE}\n"
        "Run the normal encryption process first."
    )


TEST_DIR.mkdir(
    parents=True,
    exist_ok=True
)

BACKUP_FILE.write_bytes(
    SOURCE_FILE.read_bytes()
)

print("\nOriginal encrypted file backed up.")


# --------------------------------------------------
# TEST 1: Extra byte after TAG
# --------------------------------------------------

def append_extra_byte():
    data = bytearray(
        SOURCE_FILE.read_bytes()
    )

    data.append(0xAA)

    SOURCE_FILE.write_bytes(data)


expect_failure(
    "1. Extra byte after authentication tag",
    append_extra_byte
)


# --------------------------------------------------
# TEST 2: Extra garbage data
# --------------------------------------------------

def append_garbage():
    data = bytearray(
        SOURCE_FILE.read_bytes()
    )

    data.extend(
        b"EXTRA_GARBAGE_DATA"
    )

    SOURCE_FILE.write_bytes(data)


expect_failure(
    "2. Extra garbage after authentication tag",
    append_garbage
)


# --------------------------------------------------
# TEST 3: Remove last ciphertext byte
# --------------------------------------------------

def remove_last_ciphertext_byte():
    data = bytearray(
        SOURCE_FILE.read_bytes()
    )

    tag = data[-TAG_SIZE:]

    ciphertext_start = (
        HEADER_SIZE + NONCE_SIZE
    )

    ciphertext = data[
        ciphertext_start:-TAG_SIZE
    ]

    if len(ciphertext) == 0:
        raise RuntimeError(
            "Test file contains no ciphertext."
        )

    modified_ciphertext = ciphertext[:-1]

    new_data = (
        data[:ciphertext_start]
        + modified_ciphertext
        + tag
    )

    SOURCE_FILE.write_bytes(
        new_data
    )


expect_failure(
    "3. Remove last ciphertext byte",
    remove_last_ciphertext_byte
)


# --------------------------------------------------
# TEST 4: Duplicate last ciphertext byte
# --------------------------------------------------

def duplicate_last_ciphertext_byte():
    data = bytearray(
        SOURCE_FILE.read_bytes()
    )

    tag = data[-TAG_SIZE:]

    ciphertext_start = (
        HEADER_SIZE + NONCE_SIZE
    )

    ciphertext = data[
        ciphertext_start:-TAG_SIZE
    ]

    if len(ciphertext) == 0:
        raise RuntimeError(
            "Test file contains no ciphertext."
        )

    modified_ciphertext = (
        ciphertext
        + ciphertext[-1:]
    )

    new_data = (
        data[:ciphertext_start]
        + modified_ciphertext
        + tag
    )

    SOURCE_FILE.write_bytes(
        new_data
    )


expect_failure(
    "4. Duplicate last ciphertext byte",
    duplicate_last_ciphertext_byte
)


# --------------------------------------------------
# TEST 5: Completely invalid file
# --------------------------------------------------

def replace_with_random_data():
    SOURCE_FILE.write_bytes(
        bytes(
            [
                0xAA, 0xBB, 0xCC, 0xDD,
                0x11, 0x22, 0x33, 0x44,
                0x55, 0x66, 0x77, 0x88
            ]
        )
    )


expect_failure(
    "5. Completely invalid file",
    replace_with_random_data
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
print("FILE STRUCTURE TEST COMPLETE")
print("===================================")