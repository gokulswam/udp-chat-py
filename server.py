# server.py
import base64
import json  # For packet structure
import logging  # For logging
import socket
import threading
from collections import defaultdict  # For client sequence numbers

from crypto_utils import (
    decode_message,
    encode_message,
    encrypt_with_rsa,
    generate_aes_key,
)

# --- Logging Setup ---

logging.basicConfig(
    level=logging.INFO,  # DEBUG for more detail
    format="%(asctime)s - %(threadName)s - %(levelname)s - %(message)s",
)

# --- Server State ---

clients = {}  # address -> aes_key mapping
client_keys = {}  # address -> rsa_public_key_pem mapping
# Track expected sequence number for reliable messages *from* each client
client_expected_seq = defaultdict(lambda: 0)  # Default next expected seq is 0

client_lock = (
    threading.Lock()
)  # Lock for shared dictionaries. Necessary for multithreading

MAX_MSG_SIZE = 4096
HOST = "0.0.0.0"
PORT = 12345

# --- Packet Types ---

TYPE_DATA = "DATA"
TYPE_ACK = "ACK"
TYPE_KEY_REQUEST = "KEY_REQ"
TYPE_KEY_REPLY = "KEY_REP"

# --- Functions ---

def send_packet(sock, addr, packet_data):
    """Helper to send a JSON packet"""
    try:
        json_str = json.dumps(packet_data)
        sock.sendto(json_str.encode("utf-8"), addr)
    except Exception as e:
        logging.error(f"Error sending packet to {addr}: {e}")


def send_to_others(plaintext_message, sender_addr, server_socket):
    """
    Broadcasts best-effort UDP plaintext message to other clients.
    This also encrypts/HMACs individually
    """
    if not plaintext_message:
        return

    recipients_to_send = {}
    with client_lock:
        for addr, key in clients.items():
            if addr != sender_addr:
                recipients_to_send[addr] = key

    for addr, key in recipients_to_send.items():
        try:
            # Encode message for this specific recipient
            encoded_payload = encode_message(key, plaintext_message)
            # Package as simple DATA packet (no seq/ack needed for broadcast here)
            packet = {"type": TYPE_DATA, "payload": encoded_payload}
            send_packet(server_socket, addr, packet)
            # No reliability for broadcast in this version
        except Exception as e:
            logging.error(f"Failed broadcast encoding/sending to {addr}: {e}")


def process_client_packet(data, addr, server_socket):
    """
    Handles incoming packet, runs in a thread.
    """
    global clients, client_keys, client_expected_seq

    try:
        packet = json.loads(data.decode("utf-8"))
        packet_type = packet.get("type")
        logging.debug(
            f"Received from {addr}: Type={packet_type} Seq={packet.get('seq', 'N/A')}"
        )

    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        logging.warning(
            f"Received invalid packet from {addr}: {e} - Data: {data[:100]}"
        )
        return

    # handle key request (client's first message)
    if packet_type == TYPE_KEY_REQUEST:
        payload = packet.get("payload")  # Should contain Base64 encoded public key
        if not payload:
            logging.warning(f"KEY_REQ from {addr} missing payload.")
            return

        # Check if already processed this client
        with client_lock:
            if addr in clients:
                logging.info(f"Client {addr} sent KEY_REQ again, ignoring.")
                return

        logging.info(f"Processing KEY_REQ from {addr}")
        try:
            pub_key_pem = base64.b64decode(payload)
            session_key = generate_aes_key()
            encrypted_session_key = encrypt_with_rsa(pub_key_pem, session_key)
            b64_encrypted_key = base64.b64encode(encrypted_session_key).decode("utf-8")

            # Store client state under lock
            with client_lock:
                clients[addr] = session_key
                client_keys[addr] = pub_key_pem
                client_expected_seq[addr] = 0  # Initialize sequence number tracking

            logging.info(f"Key exchange done for {addr}. Stored AES key.")

            # Send KEY_REPLY back (Best Effort UDP)
            reply_packet = {"type": TYPE_KEY_REPLY, "payload": b64_encrypted_key}
            send_packet(server_socket, addr, reply_packet)
            logging.info(f"Sent KEY_REPLY to {addr}")

        except (base64.binascii.Error, ValueError, TypeError) as e:
            logging.error(f"Key exchange crypto/decode error for {addr}: {e}")
        except Exception as e:
            logging.error(f"Key exchange processing failed for {addr}: {e}")

    # Handle reliable DATA (client's chat messages)
    elif packet_type == TYPE_DATA:
        with client_lock:  # Need lock to access client state
            if addr not in clients:
                logging.warning(f"Received DATA from unknown client {addr}, ignoring.")
                return  # Ignore data if key exchange not done

            sender_key = clients.get(addr)
            expected_seq = client_expected_seq[addr]

        # Check sequence number for reliability
        seq = packet.get("seq")
        if seq is None:
            logging.warning(
                f"DATA packet from {addr} missing sequence number, ignoring."
            )
            return

        # Send ACK packet
        ack_packet = {"type": TYPE_ACK, "ack_seq": seq}
        send_packet(server_socket, addr, ack_packet)

        # Process if it's the next expected sequence number
        if seq == expected_seq:
            logging.info(f"Received expected DATA Seq={seq} from {addr}. ACKing.")
            payload = packet.get("payload")
            if payload and sender_key:
                plaintext = decode_message(sender_key, payload)
                if plaintext is not None:
                    # Update expected sequence number only after successful processing
                    with client_lock:
                        client_expected_seq[addr] += 1

                    # Broadcast to others (best effort)
                    full_msg = f"<{addr[0]}:{addr[1]}> {plaintext}"
                    send_to_others(full_msg, addr, server_socket)
                # else, decode failed, error logged by decode_message
            else:
                logging.warning(
                    f"DATA packet Seq={seq} from {addr} missing payload or sender key."
                )

        elif seq < expected_seq:
            # Duplicate packet, already processed. ACK was resent above.
            logging.info(
                f"Received duplicate DATA Seq={seq} from {addr} (expected {expected_seq}). ACK already sent."
            )
        else:
            # Future sequence number, out of order. Ignore.
            logging.warning(
                f"Received out-of-order DATA Seq={seq} from {addr} (expected {expected_seq}). Ignoring."
            )

    # Handle ACK
    elif packet_type == TYPE_ACK:
        logging.warning(f"Server received unexpected ACK packet from {addr}. Ignored.")

    else:
        logging.warning(f"Received unknown packet type '{packet_type}' from {addr}.")


# Main func
def main():
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        udp_socket.bind((HOST, PORT))
        logging.info(f"Server listening on {HOST}:{PORT}...")
    except OSError as e:
        logging.critical(f"Failed to bind port {PORT}: {e}. Check if already in use.")
        return

    logging.info("Ready to receive packets (using threads)...")
    try:
        while True:
            try:
                client_data, client_addr = udp_socket.recvfrom(MAX_MSG_SIZE)
                if client_data:
                    # Start thread to process the packet
                    thread = threading.Thread(
                        target=process_client_packet,
                        args=(client_data, client_addr, udp_socket),
                        daemon=True,
                        name=f"Client-{client_addr}",
                    )
                    thread.start()

            except ConnectionResetError:
                logging.warning(f"Client {client_addr} connection reset.")
                # Clean up client state
                with client_lock:
                    if client_addr in clients:
                        del clients[client_addr]
                    if client_addr in client_keys:
                        del client_keys[client_addr]
                    if client_addr in client_expected_seq:
                        del client_expected_seq[client_addr]
            except OSError as e:
                # Handle socket being closed during shutdown
                logging.info(f"Server socket error/closed: {e}")
                break  # Exit loop

    except KeyboardInterrupt:
        logging.info("\nCtrl+C detected. Shutting down server...")
    except Exception as e:
        logging.exception(f"Unexpected error in server main loop: {e}")
    finally:
        if udp_socket:
            udp_socket.close()
        logging.info("Server stopped.")


if __name__ == "__main__":
    main()
