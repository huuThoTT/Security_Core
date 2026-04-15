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

class FileNonceStore:
    def __init__(self, path="nonces.json"):
        self.path = path
        if not os.path.exists(self.path):
            try:
                with open(self.path, "w") as f:
                    json.dump({}, f)
            except Exception:
                pass

    def seen(self, nonce: str) -> bool:
        try:
            with open(self.path, "r") as f:
                data = json.load(f)
        except Exception:
            data = {}
        return nonce in data

    def store(self, nonce: str, tx_id: str = None):
        try:
            with open(self.path, "r+") as f:
                try:
                    data = json.load(f)
                except Exception:
                    data = {}
                data[nonce] = {"tx_id": tx_id, "ts": time.time()}
                # cleanup >24h
                now = time.time()
                data = {n: v for n, v in data.items() if now - v.get("ts", 0) < 86400}
                f.seek(0)
                json.dump(data, f)
                f.truncate()
        except Exception:
            pass

class AdvancedSecurityDecryptor:
    def __init__(self, private_key_path=None, nonce_store=None, log_file="advanced_audit.log"):
        self.private_key_path = private_key_path
        self.log_file = log_file
        # default file-backed nonce store
        self.nonce_store = nonce_store if nonce_store is not None else FileNonceStore()

    def _log_event(self, event_type, message):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        try:
            with open(self.log_file, "a") as f:
                f.write(f"[{timestamp}] {event_type}: {message}\n")
        except Exception:
            pass

    def _trigger_alert(self, message):
        self._log_event("SECURITY_BREACH", message)
        print(f"CRITICAL SECURITY ALERT: {message}", file=sys.stderr)
        raise SecurityAlert(message)

    def _load_private_key(self, key_path, passphrase=None, salt_path="keys/salt.bin"):
        if not key_path:
            raise ValueError("Đường dẫn khóa bí mật (private key path) là bắt buộc.")
            
        if key_path.endswith(".enc"):
            if not passphrase:
                raise ValueError("Mật mã Master Key là bắt buộc.")
            
            # Ensure salt path exists or use a default if provided
            if not os.path.exists(salt_path):
                 # fallback if salt is relative to key_dir
                 key_dir = os.path.dirname(key_path)
                 potential_salt = os.path.join(key_dir, "salt.bin")
                 if os.path.exists(potential_salt):
                     salt_path = potential_salt

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

    def decrypt_and_verify(self, envelope: bytes, rec_kex_priv_path: str, ephemeral_pub_pem: str, sender_sig_pub_path: str, signature: bytes, passphrase: str = None, salt_path: str = "keys/salt.bin", aad: bytes = None):
        try:
            # 1. Load Receiver's Static Private Key
            rec_kex_priv = self._load_private_key(rec_kex_priv_path, passphrase, salt_path)
            # PERFECT FORWARD SECRECY: Load the Ephemeral Public Key generated exclusively for this transaction
            ephemeral_pub = ECC.import_key(ephemeral_pub_pem)

            # 2. ECDH Shared Secret Recovery (Receiver Static Private X Sender Ephemeral Public)
            shared_secret = key_agreement(static_priv=rec_kex_priv, static_pub=ephemeral_pub, kdf=lambda x: x)
            master_key = HKDF(shared_secret, 64, b"AT-Wallet-Salt", SHA256)
            enc_key = master_key[:32]

            # 3. Parse Envelope & Replay Check
            if len(envelope) < 32:
                self._trigger_alert("Malformed envelope")
            
            nonce = envelope[:16]
            tag = envelope[16:32]
            ciphertext = envelope[32:]

            nonce_hex = nonce.hex()
            if self.nonce_store.seen(nonce_hex):
                self._trigger_alert(f"Replay Attack Detected! Nonce {nonce_hex} already used.")

            # 4. AES-GCM Decrypt (with AAD support if provided)
            cipher_aes = AES.new(enc_key, AES.MODE_GCM, nonce=nonce)
            if aad:
                cipher_aes.update(aad)
            
            decrypted_payload = cipher_aes.decrypt_and_verify(ciphertext, tag)

            # 5. Freshness Check (Window: 300s)
            if len(decrypted_payload) < 8:
                self._trigger_alert("Decrypted payload too short")
            timestamp = int.from_bytes(decrypted_payload[:8], 'big')
            original_data = decrypted_payload[8:]
            if abs(int(time.time()) - timestamp) > 300:
                self._trigger_alert("Timestamp Expired! Potential delayed message attack.")

            # 6. EdDSA Signature Verification
            # Important: signature blob MUST exactly match what was signed in encryptor.py
            # Blob = nonce + tag + ciphertext + aad
            signed_blob = envelope + (aad if aad else b"")
            
            sender_sig_pub = ECC.import_key(open(sender_sig_pub_path, 'rt').read())
            verifier = eddsa.new(sender_sig_pub, 'rfc8032')
            try:
                verifier.verify(signed_blob, signature)
            except ValueError:
                self._trigger_alert("Digital Signature Forgery detected! Data integrity compromised.")

            # Commit nonce to store after successful verification
            try:
                self.nonce_store.store(nonce_hex)
            except Exception:
                pass
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