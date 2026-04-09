from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
import os
import sys
import time
import json
from typing import List

# Import local modules
from . import models, schemas, database
from .database import engine, get_db

# Ensure we can import core security scripts from parent dir
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from keygen import generate_user_keys
from encryptor import AdvancedSecurityEncryptor
from decryptor import AdvancedSecurityDecryptor, SecurityAlert

# Use the same security classes
encryptor = AdvancedSecurityEncryptor(log_file="advanced_audit.log")
decryptor = AdvancedSecurityDecryptor(log_file="advanced_audit.log", nonce_db="nonces.json")

# Create tables
models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="AT-Wallet Security Core API")

# Helper for PBKDF2 matching Lab 1 requirements
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256

def hash_password(password: str, salt_hex: str = None):
    if salt_hex is None:
        from Crypto.Random import get_random_bytes
        salt = get_random_bytes(16)
    else:
        salt = bytes.fromhex(salt_hex)
    
    # Matching 600,000 iterations requirement
    key = PBKDF2(password.encode(), salt, 32, count=600000, hmac_hash_module=SHA256)
    return key.hex(), salt.hex()

@app.post("/api/register", response_model=schemas.UserResponse)
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    pwd_hash, salt = hash_password(user.password)
    new_user = models.User(username=user.username, password_hash=pwd_hash, salt=salt)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    # Initialize Wallet & Keys for user
    new_wallet = models.Wallet(user_id=new_user.id, encrypted_balance="0") # Should be encrypted in prod
    db.add(new_wallet)
    
    # Generate ECC Keys for user
    user_key_dir = os.path.join("keys", new_user.username)
    generate_user_keys(output_dir=user_key_dir, passphrase=user.password)
    
    with open(os.path.join(user_key_dir, "sig_public.pem"), "r") as f:
        pub_sig = f.read()
    with open(os.path.join(user_key_dir, "kex_public.pem"), "r") as f:
        pub_kex = f.read()
        
    db_keys = models.KeyStore(user_id=new_user.id, pubkey_sig=pub_sig, pubkey_kex=pub_kex)
    db.add(db_keys)
    db.commit()
    
    return new_user

@app.post("/api/transfer", response_model=schemas.TransactionResponse)
def transfer(tx: schemas.TransactionCreate, request: Request, db: Session = Depends(get_db)):
    # Simple auth simulation (for demo, we'd use JWT)
    # sender_username = request.headers.get("X-User") 
    # For now, let's assume we are 'Sender1' from a demo set
    sender = db.query(models.User).first() # Demo hack
    receiver = db.query(models.User).filter(models.User.username == tx.receiver_username).first()
    
    if not receiver:
        raise HTTPException(status_code=404, detail="Receiver not found")
    
    # Security Core Logic: Encrypt & Sign
    try:
        data = f"Amount: {tx.amount}, Msg: {tx.message}".encode()
        sender_path = os.path.join("keys", sender.username)
        receiver_path = os.path.join("keys", receiver.username)
        
        result = encryptor.encrypt_and_sign(
            data,
            os.path.join(sender_path, "sig_private.enc"),
            os.path.join(sender_path, "kex_private.enc"),
            os.path.join(receiver_path, "kex_public.pem"),
            passphrase=tx.passphrase,
            salt_path=os.path.join(sender_path, "salt.bin")
        )
        
        new_tx = models.Transaction(
            sender_id=sender.id,
            receiver_id=receiver.id,
            encrypted_payload=result["envelope"].hex(),
            auth_tag=result["tag"].hex(),
            nonce=result["nonce"].hex(),
            signature=result["signature"].hex()
        )
        db.add(new_tx)
        db.commit()
        db.refresh(new_tx)
        return new_tx
        
    except Exception as e:
        # Log suspected dictionary attack attempt if error in key decryption
        log = models.SecurityLog(event_type="DICTIONARY", description=str(e), ip_address=request.client.host)
        db.add(log)
        db.commit()
        raise HTTPException(status_code=401, detail="Security Check Failed: Invalid Passphrase or Key Error")

@app.get("/api/logs", response_model=List[schemas.SecurityLogResponse])
def get_logs(db: Session = Depends(get_db)):
    return db.query(models.SecurityLog).order_by(models.SecurityLog.timestamp.desc()).all()

# Serve Frontend
if os.path.exists("app/static"):
    app.mount("/", StaticFiles(directory="app/static", html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
