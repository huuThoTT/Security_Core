# AT-Wallet Security Core

A high-performance, professional-grade security core for electronic wallet systems, implementing hybrid cryptography with ECC and AES-GCM.

## Features
- **Hybrid Cryptography**: Uses **Curve25519 (X25519)** for key agreement and **AES-256-GCM** for data encryption.
- **Digital Signatures**: **Ed25519 (EdDSA)** for high-speed, secure transaction signing.
- **Key Hardening**: Protects private keys at rest using **PBKDF2-HMAC-SHA256** with 600,000 iterations.
- **Anti-Replay Protection**: Persistent nonce storage to prevent re-submission of transaction packets.
- **Audit Logging**: Comprehensive security monitoring through structured audit logs.

## Project Structure
- `keygen.py`: Generates the ECC key pairs and protects them with a Master Password.
- `encryptor.py`: Handles encryption and signature generation.
- `decryptor.py`: Handles decryption, integrity verification, and signature validation.
- `test_security_core.py`: Automated test suite covering 20+ security scenarios.
- `benchmark_security.py`: Performance benchmarking tool.

## Installation
Requires Python 3.9+ and the `pycryptodome` library.

```bash
pip install pycryptodome
```

## How to Run
1. **Generate Keys**:
   ```bash
   python keygen.py
   ```
2. **Perform Tests**:
   ```bash
   python test_security_core.py
   ```

## Security Compliance
This project is designed to meet modern security standards for graduation-level cryptographic systems, ensuring **Confidentiality**, **Integrity**, **Authenticity**, and **Freshness**.
