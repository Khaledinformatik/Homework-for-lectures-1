
# Task 1 : : Consider implementing DHKE to enable two programs on your PC to perform a
# key exchange (using sockets, etc.)

# program_bob.py
import socket
import secrets
import threading
import main
import program_alice
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes


# Bob's Programm def
def bob_program():
    private_key = main.parameters.generate_private_key()
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Verbindung zu Alice herstellen
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('localhost', 65432))
            s.listen()
            conn, addr = s.accept()
            with conn:
                alice_public_bytes = conn.recv(1024)
                conn.sendall(public_bytes)

        alice_public_key = serialization.load_pem_public_key(alice_public_bytes)
        shared_key = main.calculate_shared_key(private_key, alice_public_key)
        print("Bob's shared key:", shared_key.hex())

    except Exception as e:
        print(f"Bob encountered an error: {e}")

# Starte die Programme
if __name__ == "__main__":
   bob_program()
