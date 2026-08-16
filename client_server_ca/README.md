This directory contains a python client, and server, which serves a file chosen by the user. 

This version derives a shared secret from the aes key, implements the serverside verification of the client, 
and uses a public key from ECDH to encrypt the aes key instead of using the key pair used for the certificate to encrypt the data

Before testing, the Certificate Authorities key pair needs to be created, do so by running the ca.py file. \
The ca directory will then contain the public and private keys.\
The client and server each create a keypair and a subject and 'send' the subject containing information 
about the requested certificate and their public key to the ca.py file.\
They then each receive a signed certificate that can be used to verify if you are the person you claim to be.\
Before verifying the challenge, we verify if the server certificate is even signed by a trusted certificate authority. \
We do so by loading our trusted certificate (ca/certificate.pem) into a 'trusted store'.\
We then load the trusted certificate, and if the server certificate was signed by any of the trusted certfificates, we continue with our authentication of the server. \

The crypto.X509StoreContext(store, cert).verify_certificate() function includes checks such as:\

- Certificate is signed by a trusted CA \
- Signature is valid \
- Certificate is within its validity period (notBefore / notAfter) \
- Certificate chain is valid \
- Basic X.509 constraints relevant to chain validation \

The client then verifies the server certificate came from the correct server, by sending a challenge which the Server will
send back signed, after which the server sends its signature in order for the client to verify it using public_key.verify(). \

If it is verified that the certificate came from the same person that created it, the client sends its certificate to the server. \
The server then repeats that entire process. \

Once the Server accepts the connection, it derives a secret from its AES key using HKDF, which is then used to encrypt the file being served. \
The server then sends metadata including the original filename, public key and nonce.\
The client can then decrypt the AES key, from which the shared secret will be derived using HKDF which is then, along with the nonce (and built in tag) used to decrypt the ciphertext.\
The Plaintext is then written to either the file that the user specified, or a file by the same name of the original.

Test Usage:\
In order to use the scripts, start the server. 
If no file is specified using --file_path, the user is prompted for a file.\
For tests, you can use a test file in /client_server/server/test_files.\
Server Usage:\
Usage: server.py [OPTIONS]

Options:\
  --port INTEGER    Number of greetings.\
  --file_path TEXT  File to be served\
  --help            Show this message and exit.\

Client Usage:\
Usage: client.py [OPTIONS]

Options:\
  -p, --port INTEGER  Port to connect to \
  -o, --output TEXT   The filepath to the destination file \
  --help              Show this message and exit.