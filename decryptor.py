import time
import sys
import json
import os
from Crypto.PublicKey import ECC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Signature import eddsa
from Crypto.Protocol.KDF import HKDF, PBKDF2
from Crypto.Protocol.DH import key_agreement

class AdvancedSecurityDecryptor:
    def __init__(self, log_file="advanced_audit.log", nonce_db="nonces.json"):
        self.log_file = log_file
        self.nonce_db = nonce_db
        self.processed_nonces = self._load_nonces()

    def _load_nonces(self):
        if os.path.exists(self.nonce_db):
            try:
                with open(self.nonce_db, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def _save_nonce(self, nonce_hex):
        self.processed_nonces[nonce_hex] = time.time()
        # Cleanup old nonces (> 24h)
        now = time.time()
        self.processed_nonces = {n: t for n, t in self.processed_nonces.items() if now - t < 86400}
        with open(self.nonce_db, 'w') as f:
            json.dump(self.processed_nonces, f)

    def _log_event(self, event_type, message):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with open(self.log_file, "a") as f:
            f.write(f"[{timestamp}] {event_type}: {message}\n")

    def _trigger_alert(self, message):
        self._log_event("SECURITY_BREACH", message)
        print(f"CRITICAL SECURITY ALERT: {message}", file=sys.stderr)
        raise SecurityAlert(message)

    def _load_private_key(self, key_path, passphrase=None, salt_path="keys/salt.bin"):
        if key_path.endswith(".enc"):
            if not passphrase:
                raise ValueError("Mật mã Master Key là bắt buộc.")
            with open(salt_path, "rb") as f:
                salt = f.read()
            kek = PBKDF2(passphrase, salt, 32, count=600000, hmac_hash_module=SHA256)
            with open(key_path, "rb") as f:
                data = f.read()
                nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
            cipher = AES.new(kek, AES.MODE_GCM, nonce=nonce)
            decrypted_pem = cipher.decrypt_and_verify(ciphertext, tag)
            return ECC.import_key(decrypted_pem.decode('utf-8'))
        else:
            return ECC.import_key(open(key_path, 'rt').read())

    def decrypt_and_verify(self, envelope, rec_kex_priv_path, sender_kex_pub_path, sender_sig_pub_path, signature, passphrase=None, salt_path="keys/salt.bin"):
        try:
            # 1. Load Keys
            rec_kex_priv = self._load_private_key(rec_kex_priv_path, passphrase, salt_path)
            sender_kex_pub = ECC.import_key(open(sender_kex_pub_path, 'rt').read())
            
            # 2. ECDH Shared Secret Recovery
            shared_secret = key_agreement(static_priv=rec_kex_priv, static_pub=sender_kex_pub, kdf=lambda x: x)
            master_key = HKDF(shared_secret, 64, b"AT-Wallet-Salt", SHA256)
            enc_key = master_key[:32]
            
            # 3. Parse Envelope & Replay Check
            nonce = envelope[:16]
            tag = envelope[16:32]
            ciphertext = envelope[32:]
            
            nonce_hex = nonce.hex()
            if nonce_hex in self.processed_nonces:
                self._trigger_alert(f"Replay Attack Detected! Nonce {nonce_hex} already used.")
            
            # 4. AES-GCM Decrypt
            cipher_aes = AES.new(enc_key, AES.MODE_GCM, nonce=nonce)
            decrypted_payload = cipher_aes.decrypt_and_verify(ciphertext, tag)
            
            # 5. Freshness Check (Window: 300s)
            timestamp = int.from_bytes(decrypted_payload[:8], 'big')
            original_data = decrypted_payload[8:]
            if abs(int(time.time()) - timestamp) > 300:
                self._trigger_alert("Timestamp Expired! Potential delayed message attack.")

            # 6. EdDSA Signature Verification
            sender_sig_pub = ECC.import_key(open(sender_sig_pub_path, 'rt').read())
            verifier = eddsa.new(sender_sig_pub, 'rfc8032')
            try:
                verifier.verify(original_data, signature)
            except ValueError:
                self._trigger_alert("Digital Signature Forgery detected! Data integrity compromised.")

            # Commit nonce to DB after successful verification
            self._save_nonce(nonce_hex)
            self._log_event("SUCCESS", "Advanced integrity and authenticity check passed")
            return original_data

        except Exception as e:
            if not isinstance(e, SecurityAlert):
                self._trigger_alert(f"Internal Crypto Error: {str(e)}")
            raise

class SecurityAlert(Exception):
    pass

if __name__ == "__main__":
    pass