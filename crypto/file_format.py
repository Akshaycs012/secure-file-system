import struct


# --------------------------------------------------
# File format constants
# --------------------------------------------------

MAGIC = b"SFS1"

VERSION = 2

# Algorithm identifier
AES_256_GCM = 1

NONCE_SIZE = 12
TAG_SIZE = 16

# Key ID
KEY_ID_SIZE = 16


# --------------------------------------------------
# Header format
# --------------------------------------------------
#
# 4 bytes   -> MAGIC
# 1 byte    -> VERSION
# 1 byte    -> ALGORITHM
# 1 byte    -> NONCE SIZE
# 1 byte    -> TAG SIZE
# 16 bytes  -> KEY ID
#
# Total = 24 bytes
# --------------------------------------------------

HEADER_FORMAT = "!4sBBBB16s"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)


def create_header(key_id):
    """
    Create the header for an encrypted file.

    key_id must be exactly 16 bytes.
    """

    if not isinstance(key_id, bytes):
        raise TypeError("Key ID must be bytes.")

    if len(key_id) != KEY_ID_SIZE:
        raise ValueError(
            f"Key ID must be exactly {KEY_ID_SIZE} bytes."
        )

    header = struct.pack(
        HEADER_FORMAT,
        MAGIC,
        VERSION,
        AES_256_GCM,
        NONCE_SIZE,
        TAG_SIZE,
        key_id
    )

    return header


def parse_header(header):
    """
    Read and validate an encrypted file header.
    """

    if len(header) != HEADER_SIZE:
        raise ValueError(
            "Invalid file header size."
        )

    (
        magic,
        version,
        algorithm,
        nonce_size,
        tag_size,
        key_id
    ) = struct.unpack(
        HEADER_FORMAT,
        header
    )

    # Validate magic
    if magic != MAGIC:
        raise ValueError(
            "Invalid file: magic number does not match."
        )

    # Validate version
    if version != VERSION:
        raise ValueError(
            f"Unsupported file format version: {version}"
        )

    # Validate algorithm
    if algorithm != AES_256_GCM:
        raise ValueError(
            "Unsupported encryption algorithm."
        )

    # Validate nonce size
    if nonce_size != NONCE_SIZE:
        raise ValueError(
            "Invalid nonce size."
        )

    # Validate authentication tag size
    if tag_size != TAG_SIZE:
        raise ValueError(
            "Invalid authentication tag size."
        )

    # Validate key ID
    if len(key_id) != KEY_ID_SIZE:
        raise ValueError(
            "Invalid key ID size."
        )

    return {
        "version": version,
        "algorithm": algorithm,
        "nonce_size": nonce_size,
        "tag_size": tag_size,
        "key_id": key_id
    }