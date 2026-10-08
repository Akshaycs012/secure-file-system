from pathlib import Path

from crypto.encrypt import encrypt_file
from crypto.decrypt import decrypt_file
from crypto.worm import protect_file, unprotect_file, is_protected
from crypto.hashing import calculate_file_hash
from crypto.integrity import (
    load_audit_log,
    verify_file_integrity
)
from crypto.security_policy import can_decrypt

from crypto.durability import (
    fsync_file,
    fsync_directory
)

from crypto.audit import (
    ENCRYPT_STARTED,
    ENCRYPT_COMMITTED,
    ENCRYPT_PROTECTED,
    ENCRYPT_COMPLETED,
    ENCRYPT_FAILED
)



ENCRYPTED_FILE = Path("data/secure_output.bin")
AUDIT_FILE = Path("data/audit.json")


def secure_encrypt(input_path, output_path=ENCRYPTED_FILE):
    input_path = Path(input_path)
    output_path = Path(output_path)

    if output_path.exists():
        if is_protected(output_path):
            raise FileExistsError(
                "Encrypted file already exists and "
                "is WORM protected: "
                f"{output_path}"
            )

        raise FileExistsError(
            "Output file already exists: "
            f"{output_path}"
        )

    temporary_path = output_path.with_suffix(
        output_path.suffix + ".tmp"
    )

    if temporary_path.exists():
        try:
            if is_protected(temporary_path):
                unprotect_file(temporary_path)
        except Exception:
            pass

        if temporary_path.exists():
            temporary_path.unlink()

    audit = load_audit_log()

    transaction_id = audit.create_transaction_id()

    print(
        f"\nTransaction ID: {transaction_id}"
    )

    try:
        # -------------------------------------------------
        # 1. START TRANSACTION
        # -------------------------------------------------

        print("\n[1/8] Starting encryption transaction...")

        audit.add_event(
            ENCRYPT_STARTED,
            {
                "input_file": str(input_path),
                "encrypted_file": str(output_path)
            },
            transaction_id
        )

        audit.save(AUDIT_FILE)

        print("Transaction started.")

        # -------------------------------------------------
        # 2. ENCRYPT TO TEMPORARY FILE
        # -------------------------------------------------

        print("\n[2/8] Encrypting file...")

        encrypt_file(
            input_path,
            temporary_path
        )

        if not temporary_path.exists():
            raise RuntimeError(
                "Temporary encrypted file was not created."
            )

        # -------------------------------------------------
        # 3. CALCULATE HASH
        # -------------------------------------------------

        print("\n[3/8] Calculating SHA-256...")

        encrypted_hash = calculate_file_hash(
            temporary_path
        )

        print(
            f"SHA-256: {encrypted_hash}"
        )

        # -------------------------------------------------
        # 4. VALIDATE + FSYNC TEMPORARY FILE
        # -------------------------------------------------

        print(
            "\n[4/8] Flushing encrypted file "
            "to stable storage..."
        )

        fsync_file(temporary_path)

        print(
            "Temporary encrypted file: DURABLE"
        )

        # -------------------------------------------------
        # 5. ATOMIC COMMIT
        # -------------------------------------------------

        print(
            "\n[5/8] Atomically committing "
            "encrypted file..."
        )

        temporary_path.rename(output_path)

        fsync_directory(
            output_path.parent
        )

        audit.add_event(
            ENCRYPT_COMMITTED,
            {
                "encrypted_file": str(output_path),
                "encrypted_file_sha256": encrypted_hash
            },
            transaction_id
        )

        audit.save(AUDIT_FILE)

        print(
            f"Committed: {output_path}"
        )

        # -------------------------------------------------
        # 6. WORM PROTECTION
        # -------------------------------------------------

        print(
            "\n[6/8] Applying WORM protection..."
        )

        protect_file(output_path)

        if not is_protected(output_path):
            raise RuntimeError(
                "WORM protection verification failed."
            )

        fsync_directory(
            output_path.parent
        )

        audit.add_event(
            ENCRYPT_PROTECTED,
            {
                "encrypted_file": str(output_path)
            },
            transaction_id
        )

        audit.save(AUDIT_FILE)

        print(
            "WORM protection: ENABLED"
        )

        # -------------------------------------------------
        # 7. FINAL TRANSACTION STATE
        # -------------------------------------------------

        print(
            "\n[7/8] Finalizing transaction..."
        )

        audit.add_event(
            ENCRYPT_COMPLETED,
            {
                "input_file": str(input_path),
                "encrypted_file": str(output_path),
                "encrypted_file_sha256": encrypted_hash
            },
            transaction_id
        )

        audit.save(AUDIT_FILE)

        # -------------------------------------------------
        # 8. SUCCESS
        # -------------------------------------------------

        print(
            "\n[8/8] Secure encryption completed."
        )

        return output_path

    except Exception as error:

        print(
            "\nEncryption failed."
        )

        print(
            f"Reason: {error}"
        )

        # ---------------------------------------------
        # Record transaction failure
        # ---------------------------------------------

        try:
            audit.add_event(
                ENCRYPT_FAILED,
                {
                    "input_file": str(input_path),
                    "encrypted_file": str(output_path),
                    "error": str(error)
                },
                transaction_id
            )

            audit.save(AUDIT_FILE)

        except Exception as audit_error:

            print(
                "WARNING: Could not record "
                "ENCRYPT_FAILED event:"
            )

            print(audit_error)

        # ---------------------------------------------
        # Rollback temporary file
        # ---------------------------------------------

        print(
            "Rolling back changes..."
        )

        if temporary_path.exists():

            try:
                if is_protected(temporary_path):
                    unprotect_file(
                        temporary_path
                    )
            except Exception:
                pass

            try:
                temporary_path.unlink()
            except Exception:
                pass

        # ---------------------------------------------
        # Rollback committed output
        # ---------------------------------------------

        if output_path.exists():

            try:
                if is_protected(output_path):
                    unprotect_file(
                        output_path
                    )
            except Exception:
                pass

            try:
                output_path.unlink()
            except Exception:
                pass

        print(
            "Rollback completed."
        )

        raise


def secure_decrypt(
    input_path=ENCRYPTED_FILE,
    output_path="data/recovered_secure.txt"
):
    input_path = Path(input_path)
    output_path = Path(output_path)

    # --------------------------------------------------
    # Validate input
    # --------------------------------------------------

    if not input_path.exists():
        raise FileNotFoundError(
            f"Encrypted file not found: {input_path}"
        )

    if input_path.is_symlink():
        raise ValueError(
            "Refusing to decrypt a symbolic link."
        )

    if not input_path.is_file():
        raise ValueError(
            f"Encrypted input is not a regular file: "
            f"{input_path}"
        )

    # --------------------------------------------------
    # Validate output
    # --------------------------------------------------

    if output_path.exists():

        if output_path.is_symlink():
            raise ValueError(
                "Refusing to overwrite a symbolic link: "
                f"{output_path}"
            )

        raise FileExistsError(
            "Decryption output already exists: "
            f"{output_path}"
        )

    temporary_path = output_path.with_suffix(
        output_path.suffix + ".tmp"
    )

    # Remove stale temporary plaintext.
    if temporary_path.exists():

        if temporary_path.is_symlink():
            raise ValueError(
                "Refusing to remove symbolic-link "
                "temporary output."
            )

        temporary_path.unlink()

    try:

        # --------------------------------------------------
        # 1. Verify encrypted file integrity
        # --------------------------------------------------

        print("\n[1/5] Verifying file integrity...")

        verify_file_integrity(
            input_path
        )

        print("SHA-256 integrity: VALID")

        # --------------------------------------------------
        # 2. Check security policy
        # --------------------------------------------------

        print("\n[2/5] Checking security policy...")

        if not can_decrypt(input_path):
            raise PermissionError(
                "Decryption denied: encrypted file "
                "is not in a trusted PROTECTED state."
            )

        print("Security policy: DECRYPTION ALLOWED")

        # --------------------------------------------------
        # 3. Verify WORM protection
        # --------------------------------------------------

        print("\n[3/5] Checking encrypted file...")

        if not is_protected(input_path):
            raise PermissionError(
                "Decryption denied: encrypted file "
                "is not WORM protected."
            )

        print("Encrypted file is WORM protected.")

        # --------------------------------------------------
        # 4. Streaming decryption
        # --------------------------------------------------

        print("\n[4/5] Decrypting file...")

        decrypt_file(
            input_path,
            output_path
        )

        # Verify final output exists.
        if not output_path.exists():
            raise RuntimeError(
                "Decryption completed but output "
                "file was not created."
            )

        print("Streaming decryption: SUCCESS")

        # --------------------------------------------------
        # 5. Update audit log
        # --------------------------------------------------

        print("\n[5/5] Updating audit log...")

        audit = load_audit_log()

        audit.add_event(
            "DECRYPT",
            {
                "encrypted_file": str(input_path),
                "output_file": str(output_path)
            }
        )

        audit.save(
            AUDIT_FILE
        )

        print(
            "\nSecure decryption completed successfully."
        )

        return output_path

    except Exception:

        # --------------------------------------------------
        # ROLLBACK
        # --------------------------------------------------

        print("\nDecryption failed.")
        print("Rolling back plaintext output...")

        # The low-level decryptor normally cleans its
        # temporary file itself. This is defense in depth.
        if temporary_path.exists():

            try:
                if not temporary_path.is_symlink():
                    temporary_path.unlink()
            except Exception:
                pass

        # If an output somehow exists because a failure
        # happened after the atomic rename, remove it.
        if output_path.exists():

            try:
                if not output_path.is_symlink():
                    output_path.unlink()
            except Exception:
                pass

        print("Plaintext rollback completed.")

        raise