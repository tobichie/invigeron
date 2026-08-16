# bind to a port
# receive a connection
# receive the public key
# use nonce, tag and the AES key to encrypt the file
# use the public key to encrypt random AES key
# send the File metadata, encrypted AES key, nonce and tag
# send ciphertext
import socket
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import click
from pathlib import Path
import os
from Crypto.Cipher import PKCS1_OAEP
from hashlib import sha256
from Crypto.PublicKey import RSA
import json

def encrypt_aes_key(key_bytes, key):
    public_key = RSA.import_key(key_bytes)
    # use the public key to encrypt the AES key
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_aes_key = cipher_rsa.encrypt(key)
    return encrypted_aes_key

def create_and_sign_server_cert():
    return

def handle_conn(client_socket, key, file_path, nonce, ciphertext_sha256, ciphertext):
    public_key = client_socket.recv(2048)
    # instead of just receiving the public key, the client will send a cert signed by own CA
    # check if the client certificate is legitimate by using the CA public key
    # and use the public key derived from that to encrypt the aes key

    print("Received the public key:", public_key)
    print("Creating encrypted key")
    print("Unencrypted key:", key)
    encrypted_aes_key = encrypt_aes_key(public_key, key)
    metadata = {
        "original_name": file_path.name,
        "encrypted_key_hex": encrypted_aes_key.hex(),  # is decrypted using the users private key
        "nonce_hex": nonce.hex(),
        "ciphertext_sha256_hex": ciphertext_sha256.hex(),
        "ciphertext_size": len(ciphertext),
    }

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
@click.option('--port', default=4444, help='The port to listen on')
@click.option('--file_path', prompt="What's the filepath?", help='File to be served')
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