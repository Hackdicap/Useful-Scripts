import hashlib

file_path = 'kvloop.exe'

with open(file_path, 'rb') as file:
    data = file.read()
    sha256_hash = hashlib.sha256(data).hexdigest()

print(f"SHA256 Hash: {sha256_hash}")
