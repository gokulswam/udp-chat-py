# crypto_utils.py
# This file is based off of the given crypto_utils.py from the prompt
import base64

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256  # Need this for HMAC
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

# --- RSA Operations ---


def generate_rsa_keypair():
    key = RSA.generate(2048)
    private_key_pem = key.export_key()
    public_key_pem = key.publickey().export_key()
    return private_key_pem, public_key_pem


def encrypt_with_rsa(public_key_pem, message_bytes):
    pub_key = RSA.import_key(public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(pub_key)
    return cipher_rsa.encrypt(message_bytes)


def decrypt_with_rsa(private_key_pem, encrypted_bytes):
    priv_key = RSA.import_key(private_key_pem)
    cipher_rsa = PKCS1_OAEP.new(priv_key)
    return cipher_rsa.decrypt(encrypted_bytes)


# --- AES Operations
# modified to work with HMAC easily


def generate_aes_key():
    return get_random_bytes(16)  # 128-bit key


def _encrypt_aes_raw(aes_key, plain_bytes):
    iv = get_random_bytes(AES.block_size)  # Generate random IV
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    padded_data = pad(plain_bytes, AES.block_size)  # Pad data to block size
    ciphertext = cipher.encrypt(padded_data)
    return iv + ciphertext  # Prepend IV to ciphertext


def _decrypt_aes_raw(aes_key, iv_plus_ciphertext):
    if len(iv_plus_ciphertext) < AES.block_size:
        # Not enough data for an IV
        raise ValueError("Ciphertext too short.")
    iv = iv_plus_ciphertext[: AES.block_size]
    ciphertext = iv_plus_ciphertext[AES.block_size :]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    try:
        decrypted_padded = cipher.decrypt(ciphertext)
        # Remove padding
        original_data = unpad(decrypted_padded, AES.block_size)
        return original_data
    except (ValueError, KeyError):
        # Error during decrypt or unpad
        # print(f"Unpad/decrypt error: {e}") # optional debug print
        raise ValueError("Decryption failed (likely bad key or padding)")


# --- HMAC Operations


def create_hmac(key, data_payload):
    hmac_obj = HMAC.new(key, msg=data_payload, digestmod=SHA256)
    return hmac_obj.digest()  # Get the tag bytes


def check_hmac(key, data_payload, tag_to_check):
    hmac_obj = HMAC.new(key, msg=data_payload, digestmod=SHA256)
    # verify() will raise ValueError automatically if tags don't match
    hmac_obj.verify(tag_to_check)


# --- Combined Encode/Decode

HMAC_LEN = SHA256.digest_size  # 32 bytes for SHA256


def encode_message(aes_key, msg_text):
    plain_bytes = msg_text.encode("utf-8")

    # Encrypt first (AES-CBC) -> returns iv + ciphertext bytes
    encrypted_data = _encrypt_aes_raw(aes_key, plain_bytes)

    # Create HMAC for the encrypted part (iv + ciphertext)
    hmac_tag = create_hmac(aes_key, encrypted_data)

    # Prepend HMAC tag: HMAC | IV | Ciphertext
    full_payload = hmac_tag + encrypted_data

    # Encode final payload as Base64 string for sending
    return base64.b64encode(full_payload).decode("utf-8")


def decode_message(aes_key, b64_string):
    try:
        # Decode base64
        full_payload = base64.b64decode(b64_string)

        # Check length - need at least HMAC len + IV len (block size)
        if len(full_payload) < HMAC_LEN + AES.block_size:
            # print("Received message too short.") # Optional debug
            return None

        # Split HMAC tag from the actual encrypted data (IV + ciphertext)
        received_tag = full_payload[:HMAC_LEN]
        encrypted_part = full_payload[HMAC_LEN:]

        # Check integrity
        check_hmac(aes_key, encrypted_part, received_tag)

        # HMAC OK, let's decrypt
        plain_bytes = _decrypt_aes_raw(aes_key, encrypted_part)

        # Convert back to string
        return plain_bytes.decode("utf-8")

    except (ValueError, base64.binascii.Error, TypeError):
        # Catch HMAC fail, decrypt/unpad fail, base64 fail, etc.
        # print(f"Decode/verify failed: {e}") # Optional debug
        return None  # Indicate failure
