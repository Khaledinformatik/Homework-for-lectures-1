import socket
import random
import sys
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

def bob_program(host='localhost', port=65432):
    # Diffie-Hellman parameters 
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((host, port))
            print(f"Connected to {host}:{port}")

            # Receive Alice's public key
            alice_public_bytes = sock.recv(4096)
            alice_public_key = serialization.load_pem_public_key(alice_public_bytes)
            print("Received Alice's public key")

            # Serialize and send Bob's public key
            public_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            sock.sendall(public_bytes)
            print("Sent public key")

            # Generate shared secret
            shared_key = private_key.exchange(alice_public_key)
            print(f"Shared secret generated: {shared_key.hex()[:10]}...")  # Print only first 10 chars for security

    except ConnectionRefusedError:
        print("Connection failed. Make sure the server is running.")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    bob_program()