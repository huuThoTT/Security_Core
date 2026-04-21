import time
import os
import json
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Signature import eddsa
from Crypto.Protocol.KDF import HKDF, PBKDF2
from Crypto.Random import get_random_bytes

class AdvancedSecurityEncryptor:
    def __init__(self, log_file="advanced_audit.log"):
        self.log_file = log_file

    def _log_event(self, event_type, message):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with open(self.log_file, "a") as f:
            f.write(f"[{timestamp}] {event_type}: {message}\n")

    def _load_private_key(self, key_path, passphrase=None, salt_path="keys/salt.bin"):
        """Helper to load either plaintext PEM or encrypted .enc private keys"""
        if key_path.endswith(".enc"):
            if not passphrase:
                raise ValueError("Mật mã (Passphrase) là bắt buộc để giải mã khóa bí mật này.")
            
            with open(salt_path, "rb") as f:
                salt = f.read()
            
            # Derive KEK (100,000 iterations for performance balance)
            kek = PBKDF2(passphrase, salt, 32, count=100000, hmac_hash_module=SHA256)
            
            with open(key_path, "rb") as f:
                data = f.read()
                nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
            
            cipher = AES.new(kek, AES.MODE_GCM, nonce=nonce)
            decrypted_pem = cipher.decrypt_and_verify(ciphertext, tag)
            return ECC.import_key(decrypted_pem.decode('utf-8'))
        else:
            return ECC.import_key(open(key_path, 'rt').read())

    def perform_ecdh_hkdf(self, my_priv_key, peer_pub_path):
        """ECDH Key Exchange + HKDF Key Diversification"""
        peer_pub = ECC.import_key(open(peer_pub_path, 'rt').read())
        
        from Crypto.Protocol.DH import key_agreement
        shared_secret = key_agreement(static_priv=my_priv_key, static_pub=peer_pub, kdf=lambda x: x)
        
        # Derive encryption and mac keys
        master_key = HKDF(shared_secret, 64, b"SEC-Wallet-Salt", SHA256)
        return master_key[:32], master_key[32:]

    def encrypt_and_sign(self, data: bytes, sender_sig_priv_path: str, receiver_kex_pub_path: str, passphrase: str = None, salt_path: str = "keys/salt.bin", aad: bytes = None):
        """
        Encrypt payload with AES-GCM (AAD supported) and sign the final envelope+aad.
        Returns envelope bytes and signature and separated nonce/tag for DB storage.
        """
        # 1. Load Signing Key (handle encryption)
        sig_priv = self._load_private_key(sender_sig_priv_path, passphrase, salt_path)
        
        # 2. PERFECT FORWARD SECRECY (PFS)
        # Generate Ephemeral Session Keypair for this transaction only
        ephemeral_key = ECC.generate(curve='curve25519')
        ephemeral_pub_pem = ephemeral_key.public_key().export_key(format='PEM')
        
        # 3. ECDH to get session keys using Ephemeral Private X Static Receiver Public
        enc_key, _ = self.perform_ecdh_hkdf(ephemeral_key, receiver_kex_pub_path)
        
        # 3. Add Timestamp for Freshness
        timestamp = int(time.time())
        payload = timestamp.to_bytes(8, 'big') + data
        
        # 4. Symmetric Encryption (AES-GCM) with AAD support
        cipher = AES.new(enc_key, AES.MODE_GCM)
        if aad:
            # ensure bytes
            if isinstance(aad, str):
                aad_bytes = aad.encode()
            else:
                aad_bytes = aad
            cipher.update(aad_bytes)
        else:
            aad_bytes = b""
        ciphertext, tag = cipher.encrypt_and_digest(payload)
        
        # 5. EdDSA Signature over (nonce || tag || ciphertext || aad)
        signer = eddsa.new(sig_priv, 'rfc8032')
        signed_blob = cipher.nonce + tag + ciphertext + aad_bytes
        signature = signer.sign(signed_blob)
        
        self._log_event("PFS_INFO", f"Data encrypted with Ephemeral ECDHE. Nonce: {cipher.nonce.hex()}")
        return {
            "envelope": cipher.nonce + tag + ciphertext,
            "signature": signature,
            "nonce": cipher.nonce,
            "tag": tag,
            "ephemeral_pub": ephemeral_pub_pem,
            "aad": aad_bytes
        }

if __name__ == "__main__":
    pass