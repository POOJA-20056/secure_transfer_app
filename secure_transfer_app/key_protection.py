from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import base64

def protect_key(data, password):
    key = SHA256.new(password.encode()).digest()
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return base64.b64encode(cipher.nonce + ciphertext)

def unprotect_key(enc_data, password):
    raw = base64.b64decode(enc_data)
    nonce = raw[:16]
    ciphertext = raw[16:]
    key = SHA256.new(password.encode()).digest()
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt(ciphertext)
