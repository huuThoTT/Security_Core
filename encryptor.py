import time
import os
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
            
            # Derive KEK
            kek = PBKDF2(passphrase, salt, 32, count=600000, hmac_hash_module=SHA256)
            
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
        master_key = HKDF(shared_secret, 64, b"AT-Wallet-Salt", SHA256)
        return master_key[:32], master_key[32:]

    def encrypt_and_sign(self, data, sender_sig_priv_path, sender_kex_priv_path, receiver_kex_pub_path, passphrase=None, salt_path="keys/salt.bin"):
        # 1. Load Keys (handle encryption)
        sig_priv = self._load_private_key(sender_sig_priv_path, passphrase, salt_path)
        kex_priv = self._load_private_key(sender_kex_priv_path, passphrase, salt_path)
        
        # 2. ECDH to get session keys
        enc_key, _ = self.perform_ecdh_hkdf(kex_priv, receiver_kex_pub_path)
        
        # 3. Add Timestamp for Freshness
        timestamp = int(time.time())
        payload = timestamp.to_bytes(8, 'big') + data
        
        # 4. Symmetric Encryption (AES-GCM)
        cipher = AES.new(enc_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(payload)
        
        # 5. EdDSA Signature (Ed25519)
        signer = eddsa.new(sig_priv, 'rfc8032')
        signature = signer.sign(data)
        
        self._log_event("ADVANCED_INFO", f"Data encrypted and signed. Nonce: {cipher.nonce.hex()}")
        return {
            "envelope": cipher.nonce + tag + ciphertext,
            "signature": signature
        }

if __name__ == "__main__":
    pass