import time
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import ECC
from Crypto.Protocol.DH import key_agreement
from Crypto.Cipher import AES

def benchmark_pbkdf2(iterations=600000):
    password = b"MasterPassword123"
    salt = get_random_bytes(16)
    start = time.time()
    PBKDF2(password, salt, 32, count=iterations, hmac_hash_module=SHA256)
    end = time.time()
    return end - start

def benchmark_ecdh():
    priv = ECC.generate(curve='curve25519')
    pub = priv.public_key()
    start = time.time()
    key_agreement(static_priv=priv, static_pub=pub, kdf=lambda x: x)
    end = time.time()
    return end - start

def benchmark_aes_gcm(size_kb=1000):
    data = get_random_bytes(size_kb * 1024)
    key = get_random_bytes(32)
    start = time.time()
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    end = time.time()
    return end - start

if __name__ == "__main__":
    print("--- AT-WALLET SECURITY PERFORMANCE BENCHMARK ---")
    
    it_600k = benchmark_pbkdf2(600000)
    print(f"PBKDF2 (600,000 iterations): {it_600k:.4f}s")
    
    ecdh_time = benchmark_ecdh()
    print(f"ECDH Key Agreement (X25519): {ecdh_time:.4f}s")
    
    aes_1mb = benchmark_aes_gcm(1000)
    print(f"AES-256-GCM Encryption (1 MB): {aes_1mb:.4f}s")
    
    print("------------------------------------------------")
