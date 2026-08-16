# The server listens for connections
# The client establishes a connection
import sys

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
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
import socket
import click
import json
from pathlib import Path
import os
from Crypto.Cipher import PKCS1_OAEP
from hashlib import sha256
from Crypto.PublicKey import RSA
from OpenSSL import crypto
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from ca import CA
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timezone, timedelta
from cryptography.hazmat.primitives import serialization
import uuid

# from Crypto.SelfTest.Protocol.test_ecdh import public_key

# create a socket to send and receive data
# create a connection to the server and return the socket option

def connect_to_server(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", port))
    return s


def sign_and_recv_client_cert():
    # create key pair, then send subject and public key to CA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=4096,
        backend=default_backend()  # this uses the openssl backend
    )
    public_key = private_key.public_key()
    ca = CA()
    # create proper subject for the creation of a cert
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "EU"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Am Rhein"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MVZ"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Nordrhein"),
        x509.NameAttribute(NameOID.COMMON_NAME, "Deb-Client"),
    ])
    signed_client_cert = ca.csr(subject, public_key) # send certificate signing request and get a signed cert
    with open("client_certificate.pem", "wb") as f:
        f.write(signed_client_cert.public_bytes(encoding=serialization.Encoding.PEM))
    with open("client_private.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    return signed_client_cert, private_key

# next we have to send the server the signed certificate
# the server will verify that the certificate was signed by a trusted ca extrac pub.pem
# the server checks the certificate by using the ca's public key

def verify_server_certificate(server_cert):
    # verify wether the server certificate was actually signed by a trusted CA
    trusted_certs = ["./ca/certificate.pem"]
    # make a store and add the trusted certs
    store = crypto.X509Store()
    try:
        for _cert in trusted_certs:
            f = open(_cert, "rb")
            # load f as a x509 certificate
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
            print("Loaded the certificate")
            d = open(_cert, "rb")
            cert_crypto = x509.load_pem_x509_certificate(d.read())
            # add the certificates to a trusted store
            store.add_cert(cert)
            print("Added certificate to store")
        store_ctx = crypto.X509StoreContext(store, cert)
        store_ctx.verify_certificate()
        return True
    except Exception as e:
        print(e)
        return False
# once the server certificate is verified the server must prove it owns it
# send a random 32byte nonce to the server, the server signs it using private key
# the client verifies the signature using the public key

def receive_exact(s, ciphertext_length):
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

def create_send_challenge(s):
    nonce = os.urandom(32)
    # the server signs nonce with private key
    # client verifies the signature with the private key
    length_prefix = len(nonce).to_bytes(4, byteorder='big')
    s.sendall(length_prefix + nonce)
    print("Sent the nonce")
    # once its been sent we can expect to receive
    return nonce

def signature_verification(sock, cert_crypto):
    print("Sending challenge")
    challenge = create_send_challenge(sock)
    # then receive the response and its length prefix
    length_prefix = int.from_bytes(sock.recv(4), "big")
    signature = receive_exact(sock, length_prefix)
    print("Received the signature:", signature)
    public_key = cert_crypto.public_key()
    print(cert_crypto.subject)
    print(cert_crypto.public_key().public_numbers())
    try:
        public_key.verify(
            signature,
            challenge,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Server authenticated!")
        return True
    except InvalidSignature:
        print("Invalid signature!")
        return False

@click.command()
@click.option("-p", "--port", default=4444, help="Port to connect to")
@click.option("-o", "--output", default="", help="The filepath to the destination file")
def main(port, output):
    client_certificate, private_key = sign_and_recv_client_cert()
    # create socket and connect to the localhost server with the standard port 4444
    sock = connect_to_server(port)
    # next receive the servers certificate
    try:
        length_prefix = int.from_bytes(sock.recv(4), "big")
        print("Received the length_prefix:", length_prefix)
        server_certificate = receive_exact(sock, length_prefix)
        server_cert = crypto.load_certificate(
            crypto.FILETYPE_PEM,
            server_certificate
        )
        server_cert_crypto = x509.load_pem_x509_certificate(server_certificate)
        print("Received server certificate")
        verify_server_certificate(server_cert)
        print("Verified Server certificate")
    except Exception as e:
        print(e)
        sys.exit(1)
    # once the certificate is verified send a challenge
    print("Sending challenge and verifying it")
    if signature_verification(sock,  server_cert_crypto):
        print("Valid Signature!")
        # if the signature is valid, send client certificate
        print("Getting client certificate")
        with open("client_certificate.pem", "rb") as f:
            client_cert = x509.load_pem_x509_certificate(f.read())

        cert_bytes = client_cert.public_bytes(serialization.Encoding.PEM)
        length_prefix = len(cert_bytes).to_bytes(4, byteorder="big")  # The client has to read the first 4 bytes to know how much data to receive
        sock.sendall(length_prefix + client_cert.public_bytes(serialization.Encoding.PEM))
        print("Sent the client certificate")
        print("Receiving metadata")
        length_prefix = int.from_bytes(sock.recv(4), "big")
        data = receive_exact(sock, length_prefix)
        plain_data = data.decode("utf-8")
        data = json.loads(plain_data)
        original_name, output, encrypted_key_hex, nonce_hex, ciphertext_sha256_hex, ciphertext_size = extract_data(data)
        encrypted_aes_key = bytes.fromhex(encrypted_key_hex)
        print("Created json object")
        print("Original name:", original_name)
        print("Encrypted Key:", encrypted_aes_key)
        # next, use own private key to decrypt
        aes_key = private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        ciphertext = receive_exact(sock, ciphertext_size)
        print("Received the ciphertext:", ciphertext)
        print("Decrypting the ciphertext")
        aesgcm = AESGCM(aes_key)
        nonce = bytes.fromhex(nonce_hex)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        print("Got the Plaintext:", plaintext)
        print("Writing the Plaintext to file")
        path = os.path.join("./client_output/", output)
        with open(Path(path), "wb") as f:
            f.write(plaintext)
if __name__ == "__main__":
    main()
    # client_certificate = sign_and_recv_client_cert()
    # print("Subject:", client_certificate.subject)
    # print("Issuer:", client_certificate.issuer)
    # print("Serial Number:", client_certificate.serial_number)
    # print("Valid From:", client_certificate.not_valid_before_utc)
    # print("Valid Until:", client_certificate.not_valid_after_utc)
    # print("Public Key:", client_certificate.public_key())
    # print("Signature Algorithm:", client_certificate.signature_algorithm_oid)