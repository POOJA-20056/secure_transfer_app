import sys
import os
import pytest
from Crypto.PublicKey import RSA

# Add the parent directory to sys.path so we can import crypto_utils
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import crypto_utils

def test_aes_encryption_decryption():
    key = crypto_utils.generate_aes_key(256)
    data = b"Hello, this is a secret message!"
    nonce, ciphertext, tag = crypto_utils.aes_encrypt_with_key(key, data)
    decrypted_data = crypto_utils.aes_decrypt_with_key(key, nonce, ciphertext)
    assert data == decrypted_data

def test_rsa_key_generation_and_encryption():
    # We'll use a temporary key name for testing
    name = "test_user"
    if not os.path.exists("keys"):
        os.makedirs("keys")
    
    crypto_utils.generate_rsa_keys(name)
    
    assert os.path.exists(f"keys/{name}_private.pem")
    assert os.path.exists(f"keys/{name}_public.pem")
    
    private_key = crypto_utils.load_key(f"keys/{name}_private.pem")
    public_key = crypto_utils.load_key(f"keys/{name}_public.pem")
    
    aes_key = crypto_utils.generate_aes_key(256)
    enc_key = crypto_utils.rsa_encrypt_key(aes_key, public_key)
    dec_key = crypto_utils.rsa_decrypt_key(enc_key, private_key)
    
    assert aes_key == dec_key
    
    # Cleanup
    os.remove(f"keys/{name}_private.pem")
    os.remove(f"keys/{name}_public.pem")

def test_blowfish_encryption_decryption():
    key = crypto_utils.generate_aes_key(128) # Blowfish can use AES-like keys
    data = b"Blowfish test message with padding"
    iv, ciphertext = crypto_utils.blowfish_encrypt(key, data)
    decrypted_data = crypto_utils.blowfish_decrypt(key, iv, ciphertext)
    assert data == decrypted_data

def test_signature_verification():
    name = "signer"
    if not os.path.exists("keys"):
        os.makedirs("keys")
    crypto_utils.generate_rsa_keys(name)
    
    private_key = crypto_utils.load_key(f"keys/{name}_private.pem")
    public_key = crypto_utils.load_key(f"keys/{name}_public.pem")
    
    data = b"Important data to sign"
    signature = crypto_utils.sign_data(data, private_key)
    
    assert crypto_utils.verify_signature(data, signature, public_key) is True
    assert crypto_utils.verify_signature(data + b"corrupted", signature, public_key) is False

    # Cleanup
    os.remove(f"keys/{name}_private.pem")
    os.remove(f"keys/{name}_public.pem")
