# AT-Wallet Security Core & Web Application

A professional, high-performance security ecosystem for electronic wallets. This project implements a cutting-edge **Security Core** based on hybrid cryptography and wraps it into a modern **FastAPI Web Application**.

## 🌟 Key Features
- **Hybrid Cryptography**: Uses **Curve25519 (X25519)** for key agreement and **AES-256-GCM** for authenticated data encryption.
- **Digital Signatures**: Implementing **Ed25519 (EdDSA)** for non-repudiation and transaction authenticity.
- **Key Hardening (KEK)**: Protects user private keys at rest using **PBKDF2-HMAC-SHA256** with **600,000 iterations** (NIST Standard).
- **Anti-Replay Mechanism**: Persistent nonce database and sliding window timestamp checks.
- **Full-Stack Dashboard**: A premium, glassmorphic UI to manage keys, perform secure transfers, and monitor security logs.
- **Audit Logging**: Real-time detection and logging of adversarial attempts (Tampering, Replay, Forgery).

## 🏗 Technology Stack
- **Backend**: Python 3.9+, FastAPI, SQLAlchemy.
- **Frontend**: HTML5, Vanilla CSS (Glassmorphism), JavaScript (Vanilla).
- **Database**: SQLite (Adhering to Phase 4 ERD: Users, Wallets, KeyStore, Transactions, Logs).
- **Cryptography**: `PyCryptodome` library.

## 📁 Project Structure
- `/app`: Contains the FastAPI backend and static frontend files.
- `keygen.py`: Core logic for generating ECC key pairs.
- `encryptor.py`: Core logic for encryption and signing (Secure Envelope).
- `decryptor.py`: Core logic for verification and decryption.
- `test_security_core.py`: Adversarial test suite (TC-01 to TC-08).
- `at_wallet.db`: The SQLite database (Generated upon first run).

## 🚀 Installation & Setup

### 1. Requirements
Ensure you have Python 3.9+ installed. Install the necessary dependencies:
```bash
pip install fastapi uvicorn sqlalchemy pycryptodome
```

### 2. Running the Web Application
Launch the FastAPI server using Uvicorn:
```bash
python3 -m uvicorn app.main:app --reload
```
Once running, visit **`http://127.0.0.1:8000`** in your browser to access the Dashboard.

### 3. Running Security Tests
To verify the core cryptographic functions and defense mechanisms:
```bash
python3 test_security_core.py
```

## 🛡 Security Architecture
The system follows the **Zero Trust** principle. All transaction payloads are wrapped in a **Secure Envelope** containing:
1. **Ciphertext**: AES-256 encrypted data.
2. **Auth Tag**: 16-byte MAC for integrity verification.
3. **Nonce**: 16-byte unique number for anti-replay.
4. **Signature**: 64-byte EdDSA digital signature.

## 🎓 Academic Context
This project was developed as part of a Graduation Thesis focusing on **Applied Cryptography and Information Security**. All implementations comply with the requirements defined in Phase 1-5 documentation.

---
**Developed by:** Thai Huu Tho  
**Advisors:** Dr. Nguyen Dinh Thuc, Dr. Ngo Dinh Hy
