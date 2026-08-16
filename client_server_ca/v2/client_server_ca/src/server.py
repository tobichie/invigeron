# bind to a port
# receive a connection
# receive the public key
# use nonce, tag and the AES key to encrypt the file
# use the public key to encrypt random AES key
# send the File metadata, encrypted AES key, nonce and tag
# send ciphertext
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import socket
from cryptography.x509.oid import NameOID
from cryptography import x509
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import click
from pathlib import Path
import os
from Crypto.Cipher import PKCS1_OAEP
from hashlib import sha256
from Crypto.PublicKey import RSA
import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from ca import CA

def encrypt_public_key(public_key, aes_key):
    return public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def recv_exact(s, length):
    data = b''
    while len(data) < length:
        chunk = s.recv(length - len(data))
        if not chunk:
            raise ConnectionResetError("Connection closed")
        data += chunk
    return data

def sign_challenge(challenge, private_key):
    signature = private_key.sign(
        challenge,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature
def handle_conn(client_socket, key, file_path, nonce, ciphertext_sha256, ciphertext):
    # First send your own certificate signed by the CA
    ca = CA()
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "EU"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Niederrhein"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "HSNR"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Krefeld"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Server-HSNR"),
    ])
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()  # this uses the openssl backend
    )
    public_key = private_key.public_key()
    signed_cert = ca.csr(subject, public_key) # send certificate signing request and receive a signed cert
    cert_bytes = signed_cert.public_bytes(serialization.Encoding.PEM)
    length_prefix = len(cert_bytes).to_bytes(4, byteorder="big")    # The client has to read the first 4 bytes to know how much data to receive
    client_socket.sendall(length_prefix + signed_cert.public_bytes(serialization.Encoding.PEM))
    # Once the client verifies its correct it responds with a challenge
    challenge_prefix =  client_socket.recv(4)
    challenge_prefix_int = int.from_bytes(challenge_prefix, byteorder='big')
    challenge = recv_exact(client_socket, challenge_prefix_int)
    print("Received challenge:", challenge)
    # now that we have the challenge, sign it with private key
    signed_challenge = sign_challenge(challenge, private_key)
    print("Signed the challenge")
    # next send the challenge prefix + challenge
    print("Sending length prefix and signed challenge")
    client_socket.sendall(len(signed_challenge).to_bytes(4, byteorder='big') + signed_challenge)
    print("Sent the signed challenge:", signed_challenge)

    # instead of receiving the public key, receive the certificate
    # Then use the public key in the cert to encrypt a challenge
    # The decrypted challenge will be used as a key for further communication
    prefix = int.from_bytes(client_socket.recv(4), "big")
    client_certificate = recv_exact(client_socket, int(prefix))
    print("Received the Certificate:", client_certificate)
    print("Verifying the certificate...")
    print("Using public key to encrypt")
    X509_cert = x509.load_pem_x509_certificate(client_certificate)
    cert_bytes = X509_cert.public_bytes(serialization.Encoding.PEM)
    client_public_key = X509_cert.public_key()
    # next send the metadata along with the aes key
    encrypted_aes_key = encrypt_public_key(client_public_key, key)
    metadata = {
        "original_name": file_path.name,
        "encrypted_key_hex": encrypted_aes_key.hex(),  # is decrypted using the users private key
        "nonce_hex": nonce.hex(),
        "ciphertext_sha256_hex": ciphertext_sha256.hex(),
        "ciphertext_size": len(ciphertext),
    }
    print("Created metadata containing the encrypted key")
    # the client then received the metadata, extracts the key and the metadata
    # and received the ciphertext using the length from the metadata
    # he can then decrypt the ciphertext using the aes key
    json_bytes = json.dumps(metadata).encode('utf-8')

    # Prefix with 4-byte length header so receiver knows how much to read
    length_prefix = len(json_bytes).to_bytes(4, byteorder='big')

    with client_socket:
        client_socket.sendall(length_prefix + json_bytes)
        client_socket.sendall(ciphertext)
        client_socket.close()
    return

def create_ciphertext(data):
    key = AESGCM.generate_key(bit_length=128)
    aesgcm = AESGCM(key)
    print("Created AESGCM cipher")
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    # print("Ciphertext:", ciphertext)
    print("Encrypted the data")
    ciphertext_sha256 = sha256(ciphertext).digest()
    print("Created sha256 for client")
    return key, nonce, ciphertext, ciphertext_sha256

@click.command()
@click.option('--port', default=4444, help='Number of greetings.')
@click.option('--file_path', prompt="Whats the filepath?", help='File to be served')
def main(port, file_path):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('0.0.0.0', port))
    file_path = Path(file_path)
    # get the data

    with open(file_path, "rb") as f:
        data = f.read()
        print("Got the data")
        # print("Data:", data)
    # encrypt the data using AESGCM

    # listen until
    print("Listening...")
    s.listen(5)

    while True:
        client_socket, _ = s.accept()
        key, nonce, ciphertext, ciphertext_sha256 = create_ciphertext(data)

        # after accepting a connection, start a thread that handles it
        # once we receive a connection, receive the 2048 byte puclic key key
        handle_conn(client_socket, key, file_path, nonce, ciphertext_sha256, ciphertext)

if __name__ == "__main__":
    main()