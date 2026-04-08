import os
from Crypto.PublicKey import ECC
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

def generate_ecc_keys(output_dir="keys", passphrase=None):
    """
    Graduation Thesis Level: Using Elliptic Curve Cryptography (ECC)
    - Ed25519 for Digital Signatures
    - Curve25519 for ECDH Key Exchange
    - Master Key Encryption (KEK) using PBKDF2 (600k rounds)
    """
    os.makedirs(output_dir, exist_ok=True)
    
    salt = get_random_bytes(16)
    with open(os.path.join(output_dir, "salt.bin"), "wb") as f:
        f.write(salt)

    # Derive Master Key if passphrase is provided
    kek = None
    if passphrase:
        kek = PBKDF2(passphrase, salt, 32, count=600000, hmac_hash_module=SHA256)

    def save_key(key, name, is_private):
        if is_private and kek:
            # Encrypt Private Key at rest
            raw_pem = key.export_key(format='PEM').encode('utf-8')
            cipher = AES.new(kek, AES.MODE_GCM)
            ciphertext, tag = cipher.encrypt_and_digest(raw_pem)
            with open(os.path.join(output_dir, f"{name}_private.enc"), "wb") as f:
                f.write(cipher.nonce + tag + ciphertext)
        else:
            ext = "private.pem" if is_private else "public.pem"
            with open(os.path.join(output_dir, f"{name}_{ext}"), "wt") as f:
                f.write(key.export_key(format='PEM'))

    # 1. Sinh cap khoa Ed25519 cho Signature
    for name in ("sender_sig", "receiver_sig"):
        key = ECC.generate(curve='ed25519')
        save_key(key, name, True)
        save_key(key.public_key(), name, False)
            
    # 2. Sinh cap khoa Curve25519 cho Key Exchange (ECDH)
    for name in ("sender_kex", "receiver_kex"):
        key = ECC.generate(curve='curve25519')
        save_key(key, name, True)
        save_key(key.public_key(), name, False)
            
    status = "có mật mã bảo vệ (Encrypted)" if passphrase else "không mã hóa (Plaintext)"
    print(f"Da tao hạ tầng khóa ECC {status} tại '{output_dir}'")

if __name__ == "__main__":
    pwd = input("Nhap MK Master de bao ve Private Keys (bo trong neu muon plaintext): ")
    generate_ecc_keys(passphrase=pwd if pwd else None)