
import socket
import secrets
import threading
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from program_alice import alice_program
from program_bob import bob_program


# Generate the DH parameters
parameters = dh.generate_parameters(generator=2, key_size=2048)

def calculate_shared_key(private_key, public_key, key_length=32):
   
    try:
        # Berechne den gemeinsamen Geheimnis
        shared_secret = private_key.exchange(public_key)

        # Use HKDF to derive a secure key
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=None,
            info=b'handshake data',
        ).derive(shared_secret)

        return derived_key
    except Exception as e:
        # error handling
        print(f"Fehler bei der Berechnung des gemeinsamen Schlüssels: {e}")
        return None

    # Start the Program


if __name__ == "__main__":
    alice_thread = threading.Thread(target=alice_program)
    bob_thread = threading.Thread(target=bob_program)
    bob_thread.start()
    alice_thread.start()
    bob_thread.join()
    alice_thread.join()