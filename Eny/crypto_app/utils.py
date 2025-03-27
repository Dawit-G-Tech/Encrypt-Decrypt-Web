
from Crypto.Cipher import AES, DES3
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64

class CryptoUtils:
    @staticmethod
    def otp_encrypt(plain_text, key):
        if len(key) < len(plain_text):
            raise ValueError("Key must be at least as long as the message for OTP")
        cipher_text = ''.join(chr(ord(p) ^ ord(k)) for p, k in zip(plain_text, key))
        return base64.b64encode(cipher_text.encode()).decode()

    @staticmethod
    def otp_decrypt(cipher_text, key):
        decoded_cipher = base64.b64decode(cipher_text).decode()
        plain_text = ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(decoded_cipher, key))
        return plain_text

    @staticmethod
    def aes_encrypt(plain_text, key):
        key = key.ljust(16)[:16].encode()  # Ensure 16 bytes for AES-128
        cipher = AES.new(key, AES.MODE_ECB)
        padded_text = pad(plain_text.encode(), AES.block_size)
        cipher_text = cipher.encrypt(padded_text)
        return base64.b64encode(cipher_text).decode()

    @staticmethod
    def aes_decrypt(cipher_text, key):
        key = key.ljust(16)[:16].encode()
        cipher = AES.new(key, AES.MODE_ECB)
        padded_text = cipher.decrypt(base64.b64decode(cipher_text))
        return unpad(padded_text, AES.block_size).decode()

    @staticmethod
    def des3_encrypt(plain_text, key):
        key = key.ljust(24)[:24].encode()  # Ensure 24 bytes for 3DES
        cipher = DES3.new(key, DES3.MODE_ECB)
        padded_text = pad(plain_text.encode(), DES3.block_size)
        cipher_text = cipher.encrypt(padded_text)
        return base64.b64encode(cipher_text).decode()

    @staticmethod
    def des3_decrypt(cipher_text, key):
        key = key.ljust(24)[:24].encode()
        cipher = DES3.new(key, DES3.MODE_ECB)
        padded_text = cipher.decrypt(base64.b64decode(cipher_text))
        return unpad(padded_text, DES3.block_size).decode()