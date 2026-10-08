from pathlib import Path

from crypto.secure_file import verify_file_integrity


TEST_FILE = Path("data/secure_output.bin")
BACKUP_FILE = Path("data/secure_output_backup.bin")


print("===================================")
print("SHA-256 TAMPER TEST")
print("===================================")


# -----------------------------------------
# Backup encrypted file
# -----------------------------------------

print("\nCreating backup...")

BACKUP_FILE.write_bytes(
    TEST_FILE.read_bytes()
)

print("Backup created.")


# -----------------------------------------
# Verify original file
# -----------------------------------------

print("\nChecking original file...")

try:

    verify_file_integrity(TEST_FILE)

    print("Original integrity: VALID")

except Exception as error:

    print(f"Original integrity check failed: {error}")
    raise


# -----------------------------------------
# Remove WORM protection
# -----------------------------------------

print("\nTemporarily removing WORM protection...")

import subprocess

subprocess.run(
    ["sudo", "chattr", "-i", str(TEST_FILE)],
    check=True
)


# -----------------------------------------
# Tamper with file
# -----------------------------------------

print("\nTampering with encrypted file...")

with open(TEST_FILE, "r+b") as file:

    file.seek(0)

    original_byte = file.read(1)

    file.seek(0)

    file.write(
        bytes([original_byte[0] ^ 0xFF])
    )


print("One byte modified.")


# -----------------------------------------
# Test integrity verification
# -----------------------------------------

print("\nChecking tampered file...")

try:

    verify_file_integrity(TEST_FILE)

    print("ERROR: Tampering was NOT detected!")

except ValueError:

    print("Tampering detected: SUCCESS")


# -----------------------------------------
# Restore original file
# -----------------------------------------

print("\nRestoring original file...")

TEST_FILE.write_bytes(
    BACKUP_FILE.read_bytes()
)

BACKUP_FILE.unlink()


# -----------------------------------------
# Restore WORM protection
# -----------------------------------------

print("Restoring WORM protection...")

subprocess.run(
    ["sudo", "chattr", "+i", str(TEST_FILE)],
    check=True
)


print("\n===================================")
print("SHA-256 TAMPER TEST COMPLETE")
print("===================================")