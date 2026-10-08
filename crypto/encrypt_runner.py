import sys

from crypto.encrypt import encrypt_file


def main():

    if len(sys.argv) != 3:

        print(
            "Usage:"
        )

        print(
            "python -m crypto.encrypt_runner "
            "<input> <output>"
        )

        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]

    encrypt_file(
        input_path,
        output_path
    )


if __name__ == "__main__":
    main()