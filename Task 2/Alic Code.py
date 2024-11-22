import socket
import random
import sys
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

def alice_program(host='localhost', port=65432):
    # Diffie-Hellman parameters 
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((host, port))
            print(f"Connected to {host}:{port}")

            # Serialize and send Alice's public key
            public_bytes = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            sock.sendall(public_bytes)
            print("Sent public key")

            # Receive Bob's public key
            bob_public_bytes = sock.recv(4096)
            bob_public_key = serialization.load_pem_public_key(bob_public_bytes)
            print("Received Bob's public key")

            # Generate shared secret
            shared_key = private_key.exchange(bob_public_key)
            print(f"Shared secret generated: {shared_key.hex()[:10]}...")  # Print only first 10 chars for security

    except ConnectionRefusedError:
        print("Connection failed. Make sure the server is running.")
        sys.exit(1)
    except Exception as e:
        print(f"An error occurred: {e}")
        sys.exit(1)

if __name__ == "__main__":
    alice_program()