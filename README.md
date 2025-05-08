# udp-chat-py
by Gokul Swaminathan (Graduate Student)

This was for a homework assignment for COMPE 560 @ San Diego State University.

## Description
> You will implement a **server** and multiple **clients** that communicate over **UDP sockets**. The
server handles message broadcasting between clients and performs the **initial secure key
exchange**. Each client generates an RSA public/private key pair and sends the public key to the
server. The server, in turn, generates a unique symmetric key (e.g., AES) for the client, encrypts
it with the client’s public key, and sends it back.
Once the key exchange is complete, all subsequent messages between the client and server will
be **encrypted using the symmetric key**, ensuring confidentiality over the connectionless UDP
protocol.

## Requirements

### Server
* Accept public RSA keys from multiple clients.
* Generate a random AES key per client.
* Encrypt each AES key using the corresponding client’s RSA public key.
* Send the encrypted AES key back to the client.
* Receive encrypted chat messages from clients.
* Decrypt and broadcast each message (after re-encryption) to all other connected
clients.

### Client
* Generate an RSA key pair (public/private) at startup.
* Send the public key to the server.
* Receive and decrypt the AES symmetric key using the private key.
* Use the AES key to encrypt outgoing messages and decrypt incoming ones.
* Display chat messages in real time.

### Encryption Features
* Use RSA (2048-bit or higher) for key exchange.
* Use AES (128-bit or higher) for symmetric encryption.
* Base64-encode encrypted messages for safe transmission over UDP.
* Ensure proper padding and IV handling (e.g., CBC or GCM mode). ( You will need to
generate a fresh random Initial Vector for each encryption and use padding if needed to
ensure that the plaintext is a multiple of block size)

## Special Requirements for Graduate Students
* Implement message authentication using HMAC.
* Build a terminal-based UI with curses or a simple GUI
* Add logging or error handling for packet loss and retransmissions (simulating reliable
UDP).
