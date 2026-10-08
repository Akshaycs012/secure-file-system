import os
import re
import subprocess
import sys
import time
from pathlib import Path


DATA_DIR = Path("data/performance")

DATA_DIR.mkdir(
    parents=True,
    exist_ok=True
)

SIZES_MB = [
    10,
    100,
    500,
    1024
]


def generate_test_file(
    file_path,
    size_mb
):
    """
    Generate a deterministic test file.
    """

    chunk_size = 1024 * 1024

    chunk = os.urandom(
        chunk_size
    )

    total_bytes = (
        size_mb * 1024 * 1024
    )

    with open(
        file_path,
        "wb"
    ) as file:

        remaining = total_bytes

        while remaining > 0:

            current_size = min(
                chunk_size,
                remaining
            )

            file.write(
                chunk[:current_size]
            )

            remaining -= current_size


def parse_peak_memory(output):
    """
    Extract maximum resident set size from
    /usr/bin/time -v output.

    Returns memory in MB.
    """

    pattern = (
        r"Maximum resident set size "
        r"\(kbytes\):\s*(\d+)"
    )

    match = re.search(
        pattern,
        output
    )

    if match is None:
        raise RuntimeError(
            "Could not determine peak memory."
        )

    memory_kb = int(
        match.group(1)
    )

    return memory_kb / 1024


def run_timed_command(
    command
):
    """
    Run command through /usr/bin/time -v.

    Returns:
        elapsed_seconds
        peak_memory_mb
        stdout
        stderr
    """

    full_command = [
        "/usr/bin/time",
        "-v"
    ] + command

    start = time.perf_counter()

    result = subprocess.run(
        full_command,
        capture_output=True,
        text=True
    )

    elapsed = (
        time.perf_counter()
        - start
    )

    if result.returncode != 0:

        print(
            result.stdout
        )

        print(
            result.stderr
        )

        raise RuntimeError(
            "Command failed."
        )

    # /usr/bin/time writes its report to stderr.
    peak_memory = parse_peak_memory(
        result.stderr
    )

    return (
        elapsed,
        peak_memory,
        result.stdout,
        result.stderr
    )


def main():

    print(
        "==================================="
    )

    print(
        "SECURE FILE SYSTEM PERFORMANCE TEST"
    )

    print(
        "==================================="
    )

    results = []

    for size_mb in SIZES_MB:

        print(
            f"\n{'=' * 70}"
        )

        print(
            f"Testing {size_mb} MB"
        )

        print(
            f"{'=' * 70}"
        )

        input_file = (
            DATA_DIR
            / f"input_{size_mb}mb.bin"
        )

        encrypted_file = (
            DATA_DIR
            / f"encrypted_{size_mb}mb.bin"
        )

        decrypted_file = (
            DATA_DIR
            / f"decrypted_{size_mb}mb.bin"
        )

        # -----------------------------------------
        # Generate input
        # -----------------------------------------

        print(
            "Generating test file..."
        )

        generate_test_file(
            input_file,
            size_mb
        )

        actual_size = (
            input_file.stat().st_size
        )

        print(
            f"Input size: "
            f"{actual_size / (1024 * 1024):.2f} MB"
        )

        # -----------------------------------------
        # Encryption
        # -----------------------------------------

        print(
            "Encrypting..."
        )

        (
            encryption_time,
            encryption_memory,
            encryption_stdout,
            encryption_stderr
        ) = run_timed_command(
            [
                sys.executable,
                "-m",
                "crypto.encrypt_runner",
                str(input_file),
                str(encrypted_file)
            ]
        )

        encryption_speed = (
            size_mb
            / encryption_time
        )

        print(
            f"Encryption time: "
            f"{encryption_time:.3f} s"
        )

        print(
            f"Encryption throughput: "
            f"{encryption_speed:.2f} MB/s"
        )

        print(
            f"Encryption peak memory: "
            f"{encryption_memory:.2f} MB"
        )

        # -----------------------------------------
        # Decryption
        # -----------------------------------------

        print(
            "Decrypting..."
        )

        (
            decryption_time,
            decryption_memory,
            decryption_stdout,
            decryption_stderr
        ) = run_timed_command(
            [
                sys.executable,
                "-m",
                "crypto.decrypt_runner",
                str(encrypted_file),
                str(decrypted_file)
            ]
        )

        decryption_speed = (
            size_mb
            / decryption_time
        )

        print(
            f"Decryption time: "
            f"{decryption_time:.3f} s"
        )

        print(
            f"Decryption throughput: "
            f"{decryption_speed:.2f} MB/s"
        )

        print(
            f"Decryption peak memory: "
            f"{decryption_memory:.2f} MB"
        )

        # -----------------------------------------
        # Verify decrypted size
        # -----------------------------------------

        decrypted_size = (
            decrypted_file.stat().st_size
        )

        if decrypted_size != actual_size:

            raise RuntimeError(
                "Decrypted file size mismatch."
            )

        print(
            "Size verification: PASS"
        )

        # -----------------------------------------
        # Store results
        # -----------------------------------------

        results.append(
            {
                "size_mb":
                    size_mb,

                "encryption_time":
                    encryption_time,

                "encryption_speed":
                    encryption_speed,

                "encryption_memory":
                    encryption_memory,

                "decryption_time":
                    decryption_time,

                "decryption_speed":
                    decryption_speed,

                "decryption_memory":
                    decryption_memory
            }
        )

        # -----------------------------------------
        # Cleanup
        # -----------------------------------------

        input_file.unlink(
            missing_ok=True
        )

        encrypted_file.unlink(
            missing_ok=True
        )

        decrypted_file.unlink(
            missing_ok=True
        )

    # -----------------------------------------
    # Final report
    # -----------------------------------------

    print(
        "\n\n==================================="
    )

    print(
        "PERFORMANCE SUMMARY"
    )

    print(
        "==================================="
    )

    print(
        f"{'Size':>8} "
        f"{'Enc(s)':>10} "
        f"{'Enc MB/s':>12} "
        f"{'Enc RAM':>12} "
        f"{'Dec(s)':>10} "
        f"{'Dec MB/s':>12} "
        f"{'Dec RAM':>12}"
    )

    print(
        "-" * 82
    )

    for result in results:

        print(
            f"{result['size_mb']:>8} "
            f"{result['encryption_time']:>10.3f} "
            f"{result['encryption_speed']:>12.2f} "
            f"{result['encryption_memory']:>11.2f}M "
            f"{result['decryption_time']:>10.3f} "
            f"{result['decryption_speed']:>12.2f} "
            f"{result['decryption_memory']:>11.2f}M"
        )

    print(
        "\nMemory scaling analysis:"
    )

    encryption_memories = [
        result["encryption_memory"]
        for result in results
    ]

    decryption_memories = [
        result["decryption_memory"]
        for result in results
    ]

    print(
        "Encryption peak memory range: "
        f"{min(encryption_memories):.2f} - "
        f"{max(encryption_memories):.2f} MB"
    )

    print(
        "Decryption peak memory range: "
        f"{min(decryption_memories):.2f} - "
        f"{max(decryption_memories):.2f} MB"
    )

    print(
        "\nPerformance test complete."
    )


if __name__ == "__main__":
    main()