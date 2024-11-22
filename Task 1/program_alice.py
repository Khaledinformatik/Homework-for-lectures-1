

# Task 1 : : Consider implementing DHKE to enable two programs on your PC to perform a
# key exchange (using sockets, etc.)

# program_alice.py


import socket
import secrets
import threading
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from main import parameters, calculate_shared_key


def alice_program():
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Verbindung zu Bob herstellen
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect(('localhost', 65432))
            s.sendall(public_bytes)
            bob_public_bytes = s.recv(1024)

        bob_public_key = serialization.load_pem_public_key(bob_public_bytes)
        shared_key = calculate_shared_key(private_key, bob_public_key)
        print("Alice's shared key:", shared_key.hex())

    except Exception as e:
        print(f"Alice encountered an error: {e}")


if __name__ == "__main__":
    alice_program()