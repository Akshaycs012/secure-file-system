from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from crypto.file_format import HEADER_SIZE, parse_header


ENCRYPTED_FILE = Path("data/encrypted.bin")
CORRECT_KEY_FILE = Path("keys/secret.key")


print("Loading encrypted file...")

with open(ENCRYPTED_FILE, "rb") as file:

    # Read header
    header = file.read(HEADER_SIZE)

    # Validate header
    metadata = parse_header(header)

    nonce_size = metadata["nonce_size"]
    tag_size = metadata["tag_size"]

    # Read nonce
    nonce = file.read(nonce_size)

    # Read authentication tag
    tag = file.read(tag_size)

    # Read ciphertext
    ciphertext = file.read()


print("Generating wrong AES-256 key...")

wrong_key = get_random_bytes(32)


print("Attempting decryption with wrong key...")

cipher = AES.new(
    wrong_key,
    AES.MODE_GCM,
    nonce=nonce
)

# Authenticate header
cipher.update(header)


try:

    cipher.decrypt_and_verify(
        ciphertext,
        tag
    )

    print("ERROR: Wrong key was accepted!")

except ValueError:

    print("Wrong key rejected: SUCCESS")