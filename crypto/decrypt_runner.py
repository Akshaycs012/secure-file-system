import sys

from crypto.decrypt import decrypt_file


def main():

    if len(sys.argv) != 3:

        print(
            "Usage:"
        )

        print(
            "python -m crypto.decrypt_runner "
            "<input> <output>"
        )

        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]

    decrypt_file(
        input_path,
        output_path
    )


if __name__ == "__main__":
    main()