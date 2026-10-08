import hashlib


def calculate_hash(data):

    return hashlib.sha256(
        data.encode()
    ).hexdigest()


# Event 1

event1 = "User created encrypted file"

hash1 = calculate_hash(event1)


# Event 2

event2 = (
    "User downloaded encrypted file"
    + hash1
)

hash2 = calculate_hash(event2)


# Event 3

event3 = (
    "User decrypted encrypted file"
    + hash2
)

hash3 = calculate_hash(event3)


print("Event 1")
print(event1)
print("Hash:", hash1)

print("\nEvent 2")
print(event2)
print("Hash:", hash2)

print("\nEvent 3")
print(event3)
print("Hash:", hash3)