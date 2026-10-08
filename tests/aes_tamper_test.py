from pathlib import Path

from Crypto.Cipher import AES

from crypto.file_format import HEADER_SIZE, parse_header
from crypto.key_manager import load_key


ENCRYPTED_FILE = Path("data/encrypted.bin")
KEY_FILE = Path("keys/secret.key")


print("Creating backup of encrypted file...")

backup_file = Path("data/encrypted_backup.bin")

backup_file.write_bytes(
    ENCRYPTED_FILE.read_bytes()
)

print("Backup created.")


# -----------------------------------------
# Read encrypted file
# -----------------------------------------

data = bytearray(
    ENCRYPTED_FILE.read_bytes()
)


# -----------------------------------------
# Find ciphertext position
# -----------------------------------------

header = bytes(data[:HEADER_SIZE])

metadata = parse_header(header)

nonce_size = metadata["nonce_size"]
tag_size = metadata["tag_size"]

ciphertext_start = (
    HEADER_SIZE
    + nonce_size
    + tag_size
)


# -----------------------------------------
# Tamper with ciphertext
# -----------------------------------------

print("Tampering with encrypted file...")

data[ciphertext_start] ^= 1

ENCRYPTED_FILE.write_bytes(data)

print("One byte modified.")


# -----------------------------------------
# Try to decrypt
# -----------------------------------------

print("Attempting decryption...")

key = load_key(KEY_FILE)

nonce_start = HEADER_SIZE
nonce_end = nonce_start + nonce_size

tag_start = nonce_end
tag_end = tag_start + tag_size

nonce = bytes(data[nonce_start:nonce_end])
tag = bytes(data[tag_start:tag_end])
ciphertext = bytes(data[tag_end:])


cipher = AES.new(
    key,
    AES.MODE_GCM,
    nonce=nonce
)

cipher.update(header)


try:

    cipher.decrypt_and_verify(
        ciphertext,
        tag
    )

    print("ERROR: Tampered file was accepted!")

except ValueError:

    print("Tampered file rejected: SUCCESS")


# -----------------------------------------
# Restore original encrypted file
# -----------------------------------------

print("Restoring original encrypted file...")

ENCRYPTED_FILE.write_bytes(
    backup_file.read_bytes()
)

backup_file.unlink()

print("Original encrypted file restored.")