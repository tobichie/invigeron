This directory contains a python client, and server, which serves a file chosen by the user. 
\
Once the client connects, it sends its public key over to the Server.\
Once the Server accepts the connection, it creates a AES key and AESGCM cipher. \
The server uses the AES key to encrypt the file being served, and encrypts the AES key using the received public key \
The server then sends metadata including the nonce, encrypted AES key and length of the ciphertext.\
The client uses the metadata to start receiving the ciphertext and no more.\
The client can then decrypt the AES key, which is then, along with the nonce (and built in tag) used to decrypt the ciphertext.\
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