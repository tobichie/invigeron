# The server listens for connections
# The client establishes a connection

# The client sends its public key to the server

# The server generates a random AES key
# The server encrypts the file with AES-GCM using the AES key

# The server encrypts the AES key using the client's public key

# The server sends:
#   metadata
#   encrypted AES key
#   nonce
#   tag (is added by the AESGCM module, not sent seperately. Client side decrypt checks the tag)
#   plaintext SHA256 hash (optional)
#   ciphertext

# The client decrypts the AES key using its private key

# The client decrypts the ciphertext using:
#   AES key
#   nonce
#   tag (automatically added anc checked using cryptography's AESGCM)

# AES-GCM verifies the tag automatically

# The client computes the SHA256 hash of the plaintext
# and compares it to the transmitted hash (optional)

# If verification succeeds, save the file
# Otherwise discard it
from Crypto.PublicKey import RSA
import socket
import click
import json
from pathlib import Path
import os
from Crypto.Cipher import PKCS1_OAEP
from hashlib import sha256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# from Crypto.SelfTest.Protocol.test_ecdh import public_key

# create a socket to send and receive data
# create a connection to the server and return the socket option

def connect_to_server(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", port))
    return s
# next we have to send the server the public key
def make_and_send_key(s):
#     # create a public/private RSA key pair
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    with open("private.pem", "wb") as f:
        f.write(private_key)
        print("Wrote private key")
    # with open("public.pem", "wb") as f:
    #     f.write(public_key)
    #     print("Wrote public key")
    # next we send it to the server
    s.sendall(public_key)

# send the key to the server
def send_key(s):
    with open("public.pem", "rb") as f:
        public_key = f.read()
    print("Sending public key to server:", public_key)
    s.sendall(public_key)

def receive_metadata(s):
    length_bytes = s.recv(4)
    length = int.from_bytes(length_bytes, 'big')
    print("The data is", length, "bytes long")
    data = b''
    while len(data) < length:
        # data is the data that was reaceived
        chunk = s.recv(length - len(data))
        # we receive data with the amount of the total length the server told us about - the amount of data we already received
        # if were meant to receive 1000 bytes, but only got 300, then on the next iteration we receive an
        if not chunk:
            raise ConnectionResetError("Connection closed")
        data += chunk
    print("Received all the data")
    return data

def receive_ciphertext(s, ciphertext_length):
    ciphertext = b''
    while len(ciphertext) < ciphertext_length:
        chunk = s.recv(ciphertext_length - len(ciphertext))
        if not chunk:
            raise ConnectionResetError("Connection closed")
        ciphertext += chunk
    return ciphertext

def write_to_file(data, file_path):
    print("Writing to", file_path)
    output = Path(file_path).name
    with open(output, "wb") as f:
        f.write(data)
def extract_data(json_data):
    try:
        original_name = json_data["original_name"]
        output = Path(original_name)
        encrypted_key_hex = json_data["encrypted_key_hex"]
        nonce_hex = json_data["nonce_hex"]
        ciphertext_sha256_hex = json_data["ciphertext_sha256_hex"]
        ciphertext_size = json_data["ciphertext_size"]
        return original_name, output, encrypted_key_hex, nonce_hex, ciphertext_sha256_hex, ciphertext_size
    except:
        raise ValueError("Missing data")

def send_key_receive_data(port):
    sock = connect_to_server(port)
    make_and_send_key(sock)
    # send_key(sock) # send the key to the server
    data = receive_metadata(sock)
    return data, sock

def create_and_sign_client_cert():
    # create a client certificate and have it signed by the ca
    return
@click.command()
@click.option("-p", "--port", default=4444, help="Port to connect to")
@click.option("-o", "--output", default="", help="The filepath to the destination file")
def main(port, output):
    data, sock = send_key_receive_data(port)
    # print(data)
    stuff = json.loads(data)
    json_bytes = json.dumps(stuff).encode('utf-8')
    # print("Json:", json_bytes)
    user_output = Path(output)
    original_name, output, encrypted_key_hex, nonce_hex, ciphertext_sha256_hex, ciphertext_size = extract_data(stuff)
    if user_output:
        output = user_output

    # next we turn the hex into normal bytes in order to decrypt
    encrypted_key_bytes = bytes.fromhex(encrypted_key_hex)
    nonce_bytes = bytes.fromhex(nonce_hex)
    ciphertext_sha256_bytes = bytes.fromhex(ciphertext_sha256_hex)
    # next we use the ciphertext size to receive the ciphertext
    ciphertext = receive_ciphertext(sock, ciphertext_size)
    # print("Ciphertext:", ciphertext)
    # we now have to get the unencrypted aes key using the clients private key
    with open("private.pem", "rb") as f:
        key_bytes = f.read()
    private_key = RSA.import_key(key_bytes)
    # use the private key to decrypt the AES key that was encrypted using the users public key
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_aes_key = cipher_rsa.decrypt(encrypted_key_bytes)
    print("Decrypted AES key:", decrypted_aes_key)
    # now that we have the aes key we can use it to decrypt the ciphertext using AESGCM
    aesgcm = AESGCM(decrypted_aes_key)
    plaintext = aesgcm.decrypt(nonce_bytes, ciphertext, None)
    print("First 10 bytes of Plaintext:", plaintext[:10])
    write_to_file(plaintext, output)
    os.remove("private.pem")
if __name__ == "__main__":
    main()
