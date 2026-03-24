from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional
import base64
import json
import os
import time

from crypto_utils import (
    generate_rsa_keys,
    load_key,
    generate_aes_key,
    aes_encrypt_with_key,
    aes_decrypt_with_key,
    rsa_encrypt_key,
    rsa_decrypt_key,
    sign_data,
    verify_signature,
    sha512_hash,
    blowfish_encrypt,
    blowfish_decrypt,
)
from performance_utils import measure_time


KEY_DIR = "keys"
ENCRYPTED_DIR = "encrypted"
SYSTEM_ID = "SECURE_TRANSFER_V1"


def setup_keys() -> None:
    if not os.path.exists(KEY_DIR):
        os.mkdir(KEY_DIR)
    if not os.path.exists(ENCRYPTED_DIR):
        os.mkdir(ENCRYPTED_DIR)

    if not os.path.exists(f"{KEY_DIR}/sender_private.pem"):
        generate_rsa_keys("sender")
    if not os.path.exists(f"{KEY_DIR}/receiver_private.pem"):
        generate_rsa_keys("receiver")


setup_keys()

app = FastAPI(title="Secure File & Message Transfer API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _sensitivity_to_bits(level: str) -> int:
    level = (level or "").lower()
    if level == "highly confidential":
        return 256
    # Treat normal/confidential as 128-bit by default
    return 128


@app.post("/api/encrypt")
async def encrypt(
    sensitivity: str = Form("Normal"),
    message: Optional[str] = Form(None),
    file: Optional[UploadFile] = File(None),
):
    if not file and not message:
        raise HTTPException(status_code=400, detail="Provide a message or a file.")

    if file is not None:
        data = await file.read()
    else:
        data = (message or "").encode()

    size = len(data)

    sender_private = load_key(f"{KEY_DIR}/sender_private.pem")
    receiver_public = load_key(f"{KEY_DIR}/receiver_public.pem")

    bits = _sensitivity_to_bits(sensitivity)
    aes_key = generate_aes_key(bits)

    (nonce, ciphertext, tag), enc_time = measure_time(aes_encrypt_with_key, aes_key, data)

    enc_key = rsa_encrypt_key(aes_key, receiver_public)

    data_hash = sha512_hash(data)
    signature = sign_data(data_hash, sender_private)

    envelope = {
        "system_id": SYSTEM_ID,
        "sensitivity": sensitivity,
        "size": size,
        "aes_bits": bits,
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "tag": base64.b64encode(tag).decode(),
        "enc_key": base64.b64encode(enc_key).decode(),
        "hash": base64.b64encode(data_hash).decode(),
        "signature": base64.b64encode(signature).decode(),
        "hash_algo": "SHA-512",
        "created_at": time.time(),
    }

    filename = f"encrypted_{int(time.time())}.dat"
    path = os.path.join(ENCRYPTED_DIR, filename)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(envelope, f)

    with open(path, "rb") as f:
        file_bytes = f.read()

    return {
        "status": "success",
        "message": "Encryption Successful",
        "encrypted_file_name": filename,
        "encrypted_file_content": base64.b64encode(file_bytes).decode(),
        "meta": {
            "size": size,
            "encryption_time": enc_time,
            "sensitivity": sensitivity,
            "aes_bits": bits,
        },
    }


@app.post("/api/decrypt")
async def decrypt(file: UploadFile = File(...)):
    try:
        raw = await file.read()
        content = raw.decode()
        envelope = json.loads(content)
    except Exception:
        return {
            "status": "error",
            "message": "Invalid File Format – Not Encrypted",
        }

    if envelope.get("system_id") != SYSTEM_ID:
        return {
            "status": "error",
            "message": "Key Mismatch – Unauthorized File",
        }

    try:
        ciphertext = base64.b64decode(envelope["ciphertext"])
        nonce = base64.b64decode(envelope["nonce"])
        enc_key = base64.b64decode(envelope["enc_key"])
        stored_hash = base64.b64decode(envelope["hash"])
        signature = base64.b64decode(envelope["signature"])
    except Exception:
        return {
            "status": "error",
            "message": "Invalid File Format – Not Encrypted",
        }

    receiver_private = load_key(f"{KEY_DIR}/receiver_private.pem")
    sender_public = load_key(f"{KEY_DIR}/sender_public.pem")

    try:
        aes_key = rsa_decrypt_key(enc_key, receiver_private)
    except Exception:
        return {
            "status": "error",
            "message": "AES Key Decryption Failed – Access Denied",
        }

    (plaintext, dec_time) = measure_time(aes_decrypt_with_key, aes_key, nonce, ciphertext)

    computed_hash = sha512_hash(plaintext)
    hash_match = computed_hash == stored_hash
    signature_valid = verify_signature(stored_hash, signature, sender_public)

    if not hash_match or not signature_valid:
        return {
            "status": "error",
            "message": "Signature INVALID – Data Tampered",
        }

    trust_score = 100
    is_text = True
    try:
        decoded = plaintext.decode()
    except Exception:
        decoded = base64.b64encode(plaintext).decode()
        is_text = False

    return {
        "status": "success",
        "message": "Decryption Successful",
        "signature": "VALID",
        "trust_score": trust_score,
        "is_text": is_text,
        "data": decoded,
        "meta": {
            "decryption_time": dec_time,
            "sensitivity": envelope.get("sensitivity"),
            "size": envelope.get("size"),
        },
    }


@app.get("/api/compare")
async def compare_algorithms(size: int = 128 * 1024):
    # Use a random payload with the same size (in bytes)
    # as the encrypted file, so comparison reflects that file.
    if size <= 0:
        size = 128 * 1024
    sample = os.urandom(size)

    aes_key = generate_aes_key(256)
    (aes_enc, aes_enc_time) = measure_time(aes_encrypt_with_key, aes_key, sample)
    nonce, aes_cipher, tag = aes_enc
    (_, aes_dec_time) = measure_time(aes_decrypt_with_key, aes_key, nonce, aes_cipher)

    blowfish_key = os.urandom(16)
    (bf_enc, bf_enc_time) = measure_time(blowfish_encrypt, blowfish_key, sample)
    iv, bf_cipher = bf_enc
    (_, bf_dec_time) = measure_time(blowfish_decrypt, blowfish_key, iv, bf_cipher)

    rsa_key = load_key(f"{KEY_DIR}/receiver_private.pem")
    rsa_pub = rsa_key.publickey()
    from Crypto.Cipher import PKCS1_OAEP as RSA_OAEP

    rsa_cipher = RSA_OAEP.new(rsa_pub)
    chunk_size = rsa_pub.size_in_bytes() - 42
    chunks = [sample[i : i + chunk_size] for i in range(0, len(sample), chunk_size)]

    def rsa_enc_all():
        return b"".join(rsa_cipher.encrypt(c) for c in chunks)

    (rsa_ciphertext, rsa_enc_time) = measure_time(rsa_enc_all)

    rsa_dec_cipher = RSA_OAEP.new(rsa_key)

    def rsa_dec_all():
        csize = rsa_key.size_in_bytes()
        return b"".join(
            rsa_dec_cipher.decrypt(rsa_ciphertext[i : i + csize])
            for i in range(0, len(rsa_ciphertext), csize)
        )

    (_, rsa_dec_time) = measure_time(rsa_dec_all)

    algorithms = ["AES", "Blowfish", "RSA"]
    encryption_time = [aes_enc_time, bf_enc_time, rsa_enc_time]
    decryption_time = [aes_dec_time, bf_dec_time, rsa_dec_time]
    security_strength = [9.5, 7.5, 8.5]

    # Pick the algorithm with the lowest total (enc + dec) time
    totals = [
        encryption_time[i] + decryption_time[i] for i in range(len(algorithms))
    ]
    best_index = min(range(len(algorithms)), key=lambda i: totals[i])
    best_algorithm = algorithms[best_index]
    reason = (
        f"{best_algorithm} had the lowest combined encryption and decryption "
        "time for the test payload in this run."
    )

    return {
        "algorithms": algorithms,
        "encryption_time": encryption_time,
        "decryption_time": decryption_time,
        "security_strength": security_strength,
        "best_algorithm": best_algorithm,
        "reason": reason,
    }

