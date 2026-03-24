from Crypto.Cipher import AES, PKCS1_OAEP, Blowfish
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA512
from Crypto.Signature import pkcs1_15
import base64
import os

KEY_DIR = "keys"

def generate_rsa_keys(name):
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open(f"{KEY_DIR}/{name}_private.pem", "wb") as f:
        f.write(private_key)

    with open(f"{KEY_DIR}/{name}_public.pem", "wb") as f:
        f.write(public_key)


def load_key(path):
    with open(path, "rb") as f:
        return RSA.import_key(f.read())


def generate_aes_key(bits: int) -> bytes:
    if bits not in (128, 192, 256):
        raise ValueError("AES key size must be 128, 192, or 256 bits")
    return get_random_bytes(bits // 8)


def aes_encrypt_with_key(key: bytes, data: bytes):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce, ciphertext, tag


def aes_decrypt_with_key(key: bytes, nonce: bytes, ciphertext: bytes):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt(ciphertext)


def rsa_encrypt_key(aes_key, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(aes_key)


def rsa_decrypt_key(enc_key, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(enc_key)


def sign_data(data, private_key):
    h = SHA512.new(data)
    signature = pkcs1_15.new(private_key).sign(h)
    return signature


def verify_signature(data, signature, public_key):
    h = SHA512.new(data)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except:
        return False


def sha512_hash(data: bytes) -> bytes:
    return SHA512.new(data).digest()


def blowfish_encrypt(key: bytes, data: bytes):
    # Blowfish block size is 8 bytes; pad with PKCS7-style padding
    from math import ceil

    cipher = Blowfish.new(key, Blowfish.MODE_CBC)
    bs = Blowfish.block_size
    pad_len = bs - (len(data) % bs)
    padded = data + bytes([pad_len]) * pad_len
    ciphertext = cipher.encrypt(padded)
    return cipher.iv, ciphertext


def blowfish_decrypt(key: bytes, iv: bytes, ciphertext: bytes):
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv=iv)
    padded = cipher.decrypt(ciphertext)
    pad_len = padded[-1]
    return padded[:-pad_len]
