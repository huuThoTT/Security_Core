import unittest
import os
import shutil
import time
from keygen import generate_ecc_keys
from encryptor import AdvancedSecurityEncryptor
from decryptor import AdvancedSecurityDecryptor, SecurityAlert

class TestATWalletSecurityCore(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.test_dir = "test_env"
        cls.passphrase = "SuperSecurePassword123!"
        if os.path.exists(cls.test_dir):
            shutil.rmtree(cls.test_dir)
        os.makedirs(cls.test_dir)
        
        # 1. Generate keys with passphrase
        generate_ecc_keys(output_dir=cls.test_dir, passphrase=cls.passphrase)
        
        cls.encryptor = AdvancedSecurityEncryptor(log_file=os.path.join(cls.test_dir, "test_audit.log"))
        cls.decryptor = AdvancedSecurityDecryptor(log_file=os.path.join(cls.test_dir, "test_audit.log"), 
                                                 nonce_db=os.path.join(cls.test_dir, "nonces.json"))

    def test_01_functional_roundtrip(self):
        """TC-01: Thử nghiệm mã hóa và giải mã thành công (Happy Path)"""
        data = b"Giao dich chuyen 1000 AT-Coin"
        
        # Encrypt
        result = self.encryptor.encrypt_and_sign(
            data,
            os.path.join(self.test_dir, "sender_sig_private.enc"),
            os.path.join(self.test_dir, "sender_kex_private.enc"),
            os.path.join(self.test_dir, "receiver_kex_public.pem"),
            passphrase=self.passphrase,
            salt_path=os.path.join(self.test_dir, "salt.bin")
        )
        
        # Decrypt
        decrypted_data = self.decryptor.decrypt_and_verify(
            result["envelope"],
            os.path.join(self.test_dir, "receiver_kex_private.enc"),
            os.path.join(self.test_dir, "sender_kex_public.pem"),
            os.path.join(self.test_dir, "sender_sig_public.pem"),
            result["signature"],
            passphrase=self.passphrase,
            salt_path=os.path.join(self.test_dir, "salt.bin")
        )
        self.assertEqual(data, decrypted_data)

    def test_02_tamper_ciphertext(self):
        """TC-04: Thử nghiệm sửa đổi Ciphertext (AEAD Integrity Check)"""
        data = b"Important Data"
        result = self.encryptor.encrypt_and_sign(
            data,
            os.path.join(self.test_dir, "sender_sig_private.enc"),
            os.path.join(self.test_dir, "sender_kex_private.enc"),
            os.path.join(self.test_dir, "receiver_kex_public.pem"),
            passphrase=self.passphrase,
            salt_path=os.path.join(self.test_dir, "salt.bin")
        )
        
        # Tamper with ciphertext (last byte)
        envelope = bytearray(result["envelope"])
        envelope[-1] ^= 0xFF 
        
        with self.assertRaises(SecurityAlert) as cm:
            self.decryptor.decrypt_and_verify(
                bytes(envelope),
                os.path.join(self.test_dir, "receiver_kex_private.enc"),
                os.path.join(self.test_dir, "sender_kex_public.pem"),
                os.path.join(self.test_dir, "sender_sig_public.pem"),
                result["signature"],
                passphrase=self.passphrase,
                salt_path=os.path.join(self.test_dir, "salt.bin")
            )
        self.assertIn("Internal Crypto Error", str(cm.exception))

    def test_03_replay_attack(self):
        """TC-07: Thử nghiệm tấn công Replay (Anti-Replay Protection)"""
        data = b"Money Transfer"
        result = self.encryptor.encrypt_and_sign(
            data,
            os.path.join(self.test_dir, "sender_sig_private.enc"),
            os.path.join(self.test_dir, "sender_kex_private.enc"),
            os.path.join(self.test_dir, "receiver_kex_public.pem"),
            passphrase=self.passphrase,
            salt_path=os.path.join(self.test_dir, "salt.bin")
        )
        
        # First decryption - success
        self.decryptor.decrypt_and_verify(
            result["envelope"],
            os.path.join(self.test_dir, "receiver_kex_private.enc"),
            os.path.join(self.test_dir, "sender_kex_public.pem"),
            os.path.join(self.test_dir, "sender_sig_public.pem"),
            result["signature"],
            passphrase=self.passphrase,
            salt_path=os.path.join(self.test_dir, "salt.bin")
        )
        
        # Second decryption (Replay) - should fail
        with self.assertRaises(SecurityAlert) as cm:
            self.decryptor.decrypt_and_verify(
                result["envelope"],
                os.path.join(self.test_dir, "receiver_kex_private.enc"),
                os.path.join(self.test_dir, "sender_kex_public.pem"),
                os.path.join(self.test_dir, "sender_sig_public.pem"),
                result["signature"],
                passphrase=self.passphrase,
                salt_path=os.path.join(self.test_dir, "salt.bin")
            )
        self.assertIn("Replay Attack Detected", str(cm.exception))

    def test_04_signature_forgery(self):
        """TC-06: Thử nghiệm giả mạo chữ ký (Authenticity Check)"""
        data = b"Valid Data"
        result = self.encryptor.encrypt_and_sign(
            data,
            os.path.join(self.test_dir, "sender_sig_private.enc"),
            os.path.join(self.test_dir, "sender_kex_private.enc"),
            os.path.join(self.test_dir, "receiver_kex_public.pem"),
            passphrase=self.passphrase,
            salt_path=os.path.join(self.test_dir, "salt.bin")
        )
        
        # Forge signature (random 64 bytes)
        forged_sig = os.urandom(64)
        
        with self.assertRaises(SecurityAlert) as cm:
            self.decryptor.decrypt_and_verify(
                result["envelope"],
                os.path.join(self.test_dir, "receiver_kex_private.enc"),
                os.path.join(self.test_dir, "sender_kex_public.pem"),
                os.path.join(self.test_dir, "sender_sig_public.pem"),
                forged_sig,
                passphrase=self.passphrase,
                salt_path=os.path.join(self.test_dir, "salt.bin")
            )
        self.assertIn("Digital Signature Forgery", str(cm.exception))

    def test_05_expired_timestamp(self):
        """TC-09: Thử nghiệm hết hạn Timestamp (Freshness Check)"""
        # Manually construct a payload with an old timestamp
        old_time = int(time.time()) - 400 # 400s ago (> 300s limit)
        data = b"Old Message"
        payload = old_time.to_bytes(8, 'big') + data
        
        # Get keys for manual encryption
        from Crypto.Cipher import AES
        kex_priv = self.encryptor._load_private_key(os.path.join(self.test_dir, "sender_kex_private.enc"), self.passphrase, salt_path=os.path.join(self.test_dir, "salt.bin"))
        enc_key, _ = self.encryptor.perform_ecdh_hkdf(kex_priv, os.path.join(self.test_dir, "receiver_kex_public.pem"))
        
        cipher = AES.new(enc_key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(payload)
        envelope = cipher.nonce + tag + ciphertext
        
        # Sign the original data
        from Crypto.Signature import eddsa
        sig_priv = self.encryptor._load_private_key(os.path.join(self.test_dir, "sender_sig_private.enc"), self.passphrase, salt_path=os.path.join(self.test_dir, "salt.bin"))
        signer = eddsa.new(sig_priv, 'rfc8032')
        signature = signer.sign(data)
        
        with self.assertRaises(SecurityAlert) as cm:
            self.decryptor.decrypt_and_verify(
                envelope,
                os.path.join(self.test_dir, "receiver_kex_private.enc"),
                os.path.join(self.test_dir, "sender_kex_public.pem"),
                os.path.join(self.test_dir, "sender_sig_public.pem"),
                signature,
                passphrase=self.passphrase,
                salt_path=os.path.join(self.test_dir, "salt.bin")
            )
        self.assertIn("Timestamp Expired", str(cm.exception))

    def test_06_wrong_passphrase(self):
        """TC-10: Thử nghiệm sai mật khẩu Master Key (Dictionary Attack Protection)"""
        with self.assertRaises(Exception): # PBKDF2 or AES-GCM will fail
            self.encryptor._load_private_key(
                os.path.join(self.test_dir, "sender_sig_private.enc"), 
                passphrase="WRONG_PASSWORD",
                salt_path=os.path.join(self.test_dir, "salt.bin")
            )

    @classmethod
    def tearDownClass(cls):
        # Keep test_env for user review
        pass

if __name__ == "__main__":
    unittest.main()
