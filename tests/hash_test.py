import hashlib


data = "hello World"

hash_value = hashlib.sha256(
    data.encode()
).hexdigest()

print("Original data:")
print(data)

print("\nSHA-256 hash:")
print(hash_value)