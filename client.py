import socket
import ssl
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet

HOST, PORT = '127.0.0.1', 8443
context = ssl._create_unverified_context()

with socket.create_connection((HOST, PORT)) as sock:
    with context.wrap_socket(sock, server_hostname=HOST) as ssock:
        # 1. Receive the codeword
        codeword = ssock.recv(1024)
        print(f"Received codeword: {codeword.decode()}")

        # 2. Turn codeword into a real AES Key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'static_salt_123', # Must be the same on both sides
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(codeword))
        cipher = Fernet(key)

        # 3. Encrypt a message with AES
        message = b"Top Secret Data"
        encrypted = cipher.encrypt(message)
        print(f"AES Encrypted Message: {encrypted}")