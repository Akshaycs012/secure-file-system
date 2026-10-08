with open("encrypted.bin", "r+b") as file:
    file.seek(30)

    original_byte = file.read(1)

    file.seek(30)

    modified_byte = bytes([original_byte[0] ^ 1])

    file.write(modified_byte)

print("Encrypted file has been modified.")