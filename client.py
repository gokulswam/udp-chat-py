# client.py
import base64
import curses
import curses.ascii
import json  # For packet structure
import logging  # For logging
import socket
import sys
import threading
import time
from collections import deque  # For send queue

from crypto_utils import (
    decode_message,
    decrypt_with_rsa,
    encode_message,
    generate_rsa_keypair,
)

# --- Logging Setup ---

# Log to a file to avoid interfering with curses UI
logging.basicConfig(
    level=logging.INFO,  # DEBUG for more detail
    format="%(asctime)s - %(threadName)s - %(levelname)s - %(message)s",
    filename="client.log",
    filemode="w",
)  # Overwrite log each run

# --- Client State ---

aes_key = None
sock = None
server_addr = None
running = True
private_key_pem = None

# Reliability State
send_seq = 0
recv_seq = 0  # Expected seq num from server
unacked_packets = {}  # {seq: {'packet': packet_dict, 'time_sent': timestamp, 'retries': count}}
send_queue = deque()  # Queue of plaintext messages to send reliably
unacked_lock = threading.Lock()  # Lock for unacked_packets and send_seq
send_queue_lock = threading.Lock()  # Lock for send_queue
can_send_event = threading.Event()  # Signal that we can send the next packet

# Reliability parameters
RETRANSMIT_TIMEOUT = 2.0  # seconds
MAX_RETRIES = 5

# Packet Types (match server)
TYPE_DATA = "DATA"
TYPE_ACK = "ACK"
TYPE_KEY_REQUEST = "KEY_REQ"
TYPE_KEY_REPLY = "KEY_REP"

# Curses elements
stdscr = None
messages_win = None
input_win = None
input_pad = None
messages = []
MAX_MESSAGES = 100
PAD_HEIGHT = 5
PAD_WIDTH_MARGIN = 2

COLOR_PAIR_SYSTEM = 1
COLOR_PAIR_ERROR = 2
COLOR_PAIR_INPUT_HINT = 3
COLOR_PAIR_DEBUG = 4
COLOR_PAIR_RECEIVED = 5
COLOR_PAIR_SENT = 6


# --- Curses UI Functions ---


def setup_curses():
    """Initialize curses screen and windows"""
    global stdscr, messages_win, input_win, input_pad
    try:
        stdscr = curses.initscr()
        curses.noecho()
        curses.cbreak()
        stdscr.keypad(True)
        if curses.has_colors():
            curses.start_color()
            curses.use_default_colors()
            curses.init_pair(COLOR_PAIR_SYSTEM, curses.COLOR_GREEN, -1)
            curses.init_pair(COLOR_PAIR_ERROR, curses.COLOR_RED, -1)
            curses.init_pair(COLOR_PAIR_INPUT_HINT, curses.COLOR_CYAN, -1)
            curses.init_pair(COLOR_PAIR_DEBUG, curses.COLOR_YELLOW, -1)
            curses.init_pair(COLOR_PAIR_RECEIVED, -1, -1)
            curses.init_pair(COLOR_PAIR_SENT, curses.COLOR_BLUE, -1)
        else:
            for i in range(1, 7):
                curses.init_pair(i, -1, -1)
        height, width = stdscr.getmaxyx()
        msg_win_height = max(1, height - PAD_HEIGHT - 1)
        messages_win = curses.newwin(msg_win_height, width, 0, 0)
        messages_win.scrollok(True)
        messages_win.idlok(True)
        input_win_height = max(1, PAD_HEIGHT)
        input_win_y = max(0, height - input_win_height)
        input_win = curses.newwin(input_win_height, width, input_win_y, 0)
        input_win.keypad(True)
        pad_height = max(1, input_win_height - 2)
        pad_width = max(1, width - PAD_WIDTH_MARGIN * 2)
        input_pad = curses.newpad(pad_height, pad_width)
        input_pad.keypad(True)
        input_pad.scrollok(True)
        messages_win.box()
        input_win.box()
        stdscr.refresh()
        messages_win.refresh()
        try:
            input_win.addstr(
                0,
                1,
                "Enter msg (Ctrl+C quit):",
                curses.color_pair(COLOR_PAIR_INPUT_HINT) | curses.A_BOLD,
            )
        except curses.error:
            pass
        input_win.refresh()
        update_message_display()
    except curses.error as e:
        restore_terminal()
        raise Exception(f"Curses setup failed: {e}")
    except Exception as e:
        restore_terminal()
        raise Exception(f"Setup error: {e}")


def restore_terminal():
    """Try to restore terminal state"""
    global running, stdscr
    running = False
    if stdscr and not curses.isendwin():
        try:
            stdscr.keypad(False)
            curses.nocbreak()
            curses.echo()
            curses.endwin()
        except Exception:
            pass
    stdscr = None


def update_message_display():
    """Redraw messages in the message window"""
    global messages_win, running, stdscr, messages
    if not messages_win or not running or not stdscr or curses.isendwin():
        return
    try:
        messages_win.clear()
        messages_win.box()
        h, w = messages_win.getmaxyx()
        max_lines = max(1, h - 2)
        start_idx = max(0, len(messages) - max_lines)
        for i, (msg_text, msg_type) in enumerate(messages[start_idx:]):
            if i >= max_lines:
                break
            attr = curses.A_NORMAL
            pair_num = 0
            if curses.has_colors():
                if msg_type == "system":
                    pair_num = COLOR_PAIR_SYSTEM
                elif msg_type == "error":
                    pair_num = COLOR_PAIR_ERROR
                    attr |= curses.A_BOLD
                elif msg_type == "recv":
                    pair_num = COLOR_PAIR_RECEIVED
                elif msg_type == "debug":
                    pair_num = COLOR_PAIR_DEBUG
                elif msg_type == "sent":
                    pair_num = COLOR_PAIR_SENT
            if curses.has_colors() and pair_num > 0:
                attr |= curses.color_pair(pair_num)
            line_to_display = msg_text[: max(1, w - 2)]
            messages_win.addstr(i + 1, 1, line_to_display, attr)
        messages_win.refresh()
    except curses.error:
        pass


def log_message(msg, msg_type="recv"):
    """Add message to log and refresh screen"""
    global messages
    # Log to curses UI
    messages.append((str(msg), msg_type))
    if len(messages) > MAX_MESSAGES:
        messages.pop(0)
    # Log important messages to file also
    if msg_type in ["system", "error"]:
        logging.log(
            logging.ERROR if msg_type == "error" else logging.INFO, f"UI: {msg}"
        )
    update_message_display()


# --- Network/Crypto/Reliability Logic ---


def send_packet(sock, addr, packet_data):
    """Helper to send a JSON packet"""
    try:
        json_str = json.dumps(packet_data)
        sock.sendto(json_str.encode("utf-8"), addr)
    except Exception as e:
        logging.error(f"Error sending packet to {addr}: {e}")
        log_message(
            f"Network send error: {e}", "error"
        )  # Also show critical errors in UI


def reliable_sender(udp_sock, target_addr):
    """Thread function to manage reliable sending of messages from queue"""
    global running, send_seq, unacked_packets, send_queue
    logging.info("Reliable sender thread started.")

    while running:
        # Wait until we are allowed to send
        can_send_event.wait(timeout=0.1)

        if (
            not can_send_event.is_set()
        ):  # If woken by timeout, check for retransmissions
            check_retransmissions(udp_sock, target_addr)
            continue  # Go back to waiting/checking

        # Check if there's anything in the queue to send
        next_message_payload = None
        with send_queue_lock:
            if send_queue:
                next_message_payload = send_queue.popleft()

        if next_message_payload:
            current_seq = -1  # Placeholder
            packet_to_send = None
            with unacked_lock:
                current_seq = send_seq
                packet_to_send = {
                    "type": TYPE_DATA,
                    "seq": current_seq,
                    "payload": next_message_payload,  # Already encoded payload
                }
                unacked_packets[current_seq] = {
                    "packet": packet_to_send,
                    "time_sent": time.monotonic(),
                    "retries": 0,
                }
                send_seq += 1  # Increment after assigning current_seq

            logging.info(f"Sending reliable DATA Seq={current_seq} to {target_addr}")
            send_packet(udp_sock, target_addr, packet_to_send)
            can_send_event.clear()  # Block sending until ACK received or timeout

        else:
            # Queue is empty, just check retransmits before waiting again
            check_retransmissions(udp_sock, target_addr)

    logging.info("Reliable sender thread stopped.")


def check_retransmissions(udp_sock, target_addr):
    """Check for packets needing retransmission"""
    global running, unacked_packets
    now = time.monotonic()
    packets_to_remove = []  # Collect seq nums to remove after iteration

    with unacked_lock:
        for seq, info in unacked_packets.items():
            if now - info["time_sent"] > RETRANSMIT_TIMEOUT:
                info["retries"] += 1
                if info["retries"] <= MAX_RETRIES:
                    logging.warning(
                        f"Timeout for DATA Seq={seq}. Retransmitting (Attempt {info['retries']})."
                    )
                    log_message(f"[System] Retransmitting msg {seq}...", "debug")
                    send_packet(udp_sock, target_addr, info["packet"])
                    info["time_sent"] = now  # Reset timer
                else:
                    logging.error(
                        f"Max retries exceeded for DATA Seq={seq}. Giving up."
                    )
                    log_message(
                        f"[Error] Failed to send msg {seq} after {MAX_RETRIES} retries.",
                        "error",
                    )
                    packets_to_remove.append(seq)
                    can_send_event.set()  # Allow next message to be sent

        # Remove packets that exceeded max retries
        for seq in packets_to_remove:
            if seq in unacked_packets:
                del unacked_packets[seq]


def network_receiver(udp_sock, rsa_priv_key):
    """Thread function to listen and process incoming packets"""
    global aes_key, running, unacked_packets
    logging.info("Network receiver thread started.")

    key_request_sent = False  # Flag to control initial key request

    while running:
        # Send initial key request if needed
        # This is basic. It doesn't handle server not responding properly
        if aes_key is None and not key_request_sent:
            try:
                b64_public_key = base64.b64encode(public_key_pem).decode("utf-8")
                req_packet = {"type": TYPE_KEY_REQUEST, "payload": b64_public_key}
                logging.info("Sending initial KEY_REQ to server.")
                send_packet(udp_sock, server_addr, req_packet)
                key_request_sent = True
            except Exception as e:
                logging.exception("Failed to send initial KEY_REQ")
                log_message(f"Error sending key request: {e}", "error")

        # receive loop
        try:
            if udp_sock.fileno() == -1:
                break  # Exit if socket closed

            data, sender = udp_sock.recvfrom(4096)
            if not data:
                continue

            # Process received packet
            packet = json.loads(data.decode("utf-8"))
            packet_type = packet.get("type")
            logging.debug(
                f"Received from {sender}: Type={packet_type} Seq/AckSeq={packet.get('seq') or packet.get('ack_seq')}"
            )

            # handle key reply best effort
            if packet_type == TYPE_KEY_REPLY:
                if aes_key is None:  # Process only if we don't have a key yet
                    payload = packet.get("payload")
                    if payload:
                        try:
                            log_message("Received AES key reply...", "system")
                            encrypted_key_bytes = base64.b64decode(payload)
                            key_bytes = decrypt_with_rsa(
                                rsa_priv_key, encrypted_key_bytes
                            )
                            aes_key = key_bytes  # Store session key
                            log_message("Session key established.", "system")
                            logging.info(
                                "Successfully processed KEY_REPLY and stored AES key."
                            )
                            # Signal sender thread that it can start
                            can_send_event.set()
                        except (base64.binascii.Error, ValueError) as e:
                            log_message(f"AES key decode/decrypt error: {e}", "error")
                            logging.error(f"Failed to process KEY_REPLY: {e}")
                        except Exception as e:
                            log_message(f"AES key processing error: {e}", "error")
                            logging.exception("Unexpected error processing KEY_REPLY")
                    else:
                        logging.warning("Received KEY_REPLY with no payload.")
                else:
                    logging.info("Ignoring KEY_REPLY, AES key already set.")

            # Handle DATA broadcasts (best effort)
            # Note: In this project, only KEY_REPLY comes reliably from server
            # All other DATA are broadcasts handled best-effort
            elif packet_type == TYPE_DATA:
                if aes_key:  # Need key to decrypt
                    payload = packet.get("payload")
                    if payload:
                        plaintext = decode_message(aes_key, payload)
                        if plaintext is not None:
                            log_message(f"{plaintext}", "recv")  # Display broadcast
                    # else, decode failed, error logged by decode_message
                    else:
                        logging.warning(
                            "Received broadcast DATA packet with no payload."
                        )
                else:
                    logging.warning(
                        "Received broadcast DATA before AES key established."
                    )

            # Handle ACK for our reliable messages
            elif packet_type == TYPE_ACK:
                ack_seq = packet.get("ack_seq")
                if ack_seq is not None:
                    ack_processed = False
                    with unacked_lock:
                        if ack_seq in unacked_packets:
                            del unacked_packets[ack_seq]  # Remove acknowledged packet
                            ack_processed = True
                            logging.info(
                                f"Received ACK for Seq={ack_seq}. Message delivered."
                            )
                            log_message(
                                f"[System] Msg {ack_seq} acknowledged.", "debug"
                            )  # UI feedback

                    if ack_processed:
                        can_send_event.set()  # Signal sender thread it can send next packet
                    else:
                        logging.warning(
                            f"Received duplicate/unexpected ACK for Seq={ack_seq}. Ignored."
                        )
                else:
                    logging.warning("Received ACK packet missing ack_seq.")

            else:
                logging.warning(
                    f"Received unknown packet type '{packet_type}' from {sender}"
                )

        except socket.timeout:
            # Timeout, check for retransmissions elsewhere periodically
            continue
        except (json.JSONDecodeError, UnicodeDecodeError):
            logging.warning(f"Received invalid packet from {sender}. Not JSON/UTF8.")
        except OSError as e:
            if running:
                logging.error(f"Network receiver error: {e}. Closing thread.")
            running = False
            break  # Exit thread
        except Exception as e:
            if running:
                logging.exception(f"Unexpected error in receiver thread: {e}")
            running = False
            break

    logging.info("Network receiver thread stopped.")


def queue_message_for_sending(message_str):
    """Encodes message and adds it to the reliable send queue"""
    global aes_key, running, send_queue
    if not running or not aes_key or not message_str:
        if not aes_key:
            log_message("Cannot queue message: No session key.", "error")
        return False

    try:
        # Encode message payload (Encrypt+HMAC+Base64)
        encoded_payload = encode_message(aes_key, message_str)
        # Add payload to queue (sender thread will package it)
        with send_queue_lock:
            send_queue.append(encoded_payload)
        logging.info(f"Queued message for sending: {message_str[:20]}...")
        return True
    except Exception as e:
        logging.exception("Failed to encode message for queueing.")
        log_message(f"Error preparing message: {e}", "error")
        return False


# main func
def main_app():
    global sock, server_addr, running, private_key_pem, public_key_pem  # Need public key for KEY_REQ
    global stdscr, messages_win, input_win, input_pad

    if len(sys.argv) != 3:
        print("Usage: python client.py <server_host> <server_port>")
        return
    host = sys.argv[1]
    try:
        port = int(sys.argv[2])
    except ValueError:
        print("Port must be a number.")
        return
    server_addr = (host, port)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)  # Use timeout for recvfrom

    # Thread handles
    recv_thread = None
    sender_thread = None

    try:
        setup_curses()  # Init UI

        log_message("Generating RSA keys...", "system")
        private_key_pem, public_key_pem = generate_rsa_keypair()  # Generate keys

        # Key Request is sent by receiver thread initially

        # Start receiver thread
        recv_thread = threading.Thread(
            target=network_receiver,
            args=(sock, private_key_pem),
            daemon=True,
            name="ReceiverThread",
        )
        recv_thread.start()

        # Start reliable sender thread
        sender_thread = threading.Thread(
            target=reliable_sender,
            args=(sock, server_addr),
            daemon=True,
            name="SenderThread",
        )
        sender_thread.start()

        # curses input handling loop
        input_buffer = ""
        pad_scroll_pos = 0
        while running:
            if not stdscr or curses.isendwin():
                running = False
                break  # Exit if UI closed

            # Input loop logic and UI refresh
            input_win.clear()
            input_win.box()
            try:
                input_win.addstr(
                    0,
                    1,
                    "Enter msg (Ctrl+C quit):",
                    curses.color_pair(COLOR_PAIR_INPUT_HINT) | curses.A_BOLD,
                )
            except:
                pass
            # Pad refresh logic
            in_h, in_w = input_win.getmaxyx()
            pad_h_vis = max(1, in_h - 2)
            pad_w_vis = max(1, in_w - PAD_WIDTH_MARGIN * 2)
            win_y, win_x = input_win.getbegyx()
            pad_y_screen = win_y + 1
            pad_x_screen = win_x + PAD_WIDTH_MARGIN
            pad_y_screen_max = win_y + pad_h_vis
            pad_x_screen_max = win_x + in_w - PAD_WIDTH_MARGIN - 1
            buf_len = len(input_buffer)
            cursor_row = buf_len // pad_w_vis
            cursor_col = buf_len % pad_w_vis
            if cursor_row >= pad_h_vis + pad_scroll_pos:
                pad_scroll_pos = cursor_row - pad_h_vis + 1
            elif cursor_row < pad_scroll_pos:
                pad_scroll_pos = cursor_row
            try:
                input_pad.refresh(
                    pad_scroll_pos,
                    0,
                    pad_y_screen,
                    pad_x_screen,
                    pad_y_screen_max,
                    pad_x_screen_max,
                )
            except curses.error:
                time.sleep(0.1)
                continue

            # Get input
            try:
                input_pad.move(cursor_row, cursor_col)
                kb_char = input_pad.getch()
            except curses.error:
                time.sleep(0.1)
                continue

            # Process input key
            if kb_char == curses.KEY_RESIZE:
                # Resize logic
                try:
                    h_new, w_new = stdscr.getmaxyx()
                    curses.resizeterm(h_new, w_new)
                    msg_win_height = max(1, h_new - PAD_HEIGHT - 1)
                    messages_win.resize(msg_win_height, w_new)
                    input_win_height = max(1, PAD_HEIGHT)
                    input_win_y_new = max(0, h_new - input_win_height)
                    input_win.resize(input_win_height, w_new)
                    input_win.mvwin(input_win_y_new, 0)
                    pad_height_new = max(1, input_win_height - 2)
                    pad_width_new = max(1, w_new - PAD_WIDTH_MARGIN * 2)
                    if pad_height_new > 0 and pad_width_new > 0:
                        input_pad.resize(pad_height_new, pad_width_new)
                    else:
                        input_pad.clear()
                    stdscr.clear()
                    stdscr.refresh()
                    messages_win.clear()
                    messages_win.box()
                    update_message_display()
                    messages_win.refresh()
                    input_win.clear()
                    input_win.box()
                    input_win.refresh()
                    try:
                        input_win.addstr(
                            0,
                            1,
                            "Enter msg (Ctrl+C quit):",
                            curses.color_pair(COLOR_PAIR_INPUT_HINT) | curses.A_BOLD,
                        )
                    except curses.error:
                        pass
                    input_pad.clear()
                    if input_buffer:
                        input_pad.addstr(0, 0, input_buffer)
                except Exception as e:
                    log_message(f"Resize error: {e}", "error")

            elif (
                kb_char == curses.KEY_BACKSPACE or kb_char == 127 or kb_char == 8
            ):  # Backspace
                if input_buffer:
                    input_buffer = input_buffer[:-1]
                    input_pad.clear()
                    if input_buffer:
                        input_pad.addstr(0, 0, input_buffer)

            elif kb_char == 10 or kb_char == curses.KEY_ENTER:  # Enter key
                if input_buffer:
                    msg_to_queue = input_buffer  # Save text
                    # Queue message for reliable sending
                    queued_ok = queue_message_for_sending(msg_to_queue)
                    if queued_ok:
                        # Show message in UI immediately (optimistic)
                        log_message(f"Me: {msg_to_queue}", "sent")
                    # Clear input buffer
                    input_buffer = ""
                    input_pad.clear()
                    pad_scroll_pos = 0

            elif (
                kb_char > 0 and kb_char < 256 and curses.ascii.isprint(kb_char)
            ):  # Regular char
                input_buffer += chr(kb_char)
                try:
                    input_pad.addstr(chr(kb_char))
                except curses.error:
                    pass

            elif kb_char == -1:  # No input
                time.sleep(0.02)

    except KeyboardInterrupt:
        if stdscr and not curses.isendwin():
            log_message("Ctrl+C pressed, exiting.", "system")
            time.sleep(0.1)
        else:
            print("\nExiting...")
        logging.info("Ctrl+C detected by user.")
    except Exception as e:
        logging.exception("Unexpected error in main client loop.")  # Log full traceback
        if stdscr and not curses.isendwin():
            log_message(f"[FATAL] {e}", "error")
            time.sleep(2)
        else:
            print(f"\nRuntime Error: {e}\n", file=sys.stderr)

    finally:
        running = False  # Signal threads to stop
        if can_send_event:
            can_send_event.set()  # Wake up sender thread so it can exit check
        restore_terminal()  # Close curses screen

        # Wait briefly for threads
        threads = [t for t in [recv_thread, sender_thread] if t and t.is_alive()]
        if threads:
            logging.info("Waiting for background threads...")
            for t in threads:
                t.join(timeout=0.5)
                if t.is_alive():
                    logging.warning(f"{t.name} did not finish cleanly.")

        if sock:
            try:
                sock.close()
                logging.info("Socket closed.")
            except:
                pass

        logging.info("Client stopped.")
        print("Client stopped. Log saved to client.log")


if __name__ == "__main__":
    try:
        main_app()
    except Exception as e:
        restore_terminal()
        logging.exception("Client execution failed.")  # Log error before exit
        print(f"\nClient Error: {e}", file=sys.stderr)
        print("Check client.log for details.")
        sys.exit(1)
