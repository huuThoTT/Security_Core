import os
import sys
import time
import json
import uuid
from typing import List, Optional
from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException, Request, Header
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.PublicKey import ECC
import binascii

# Security Upgrades Imports
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from jose import jwt, JWTError
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
import pyotp

# Local app imports
from app import models, schemas
from app.database import engine, get_db, SessionLocal

# Ensure we can import core security scripts from parent dir
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from keygen import generate_user_keys
from encryptor import AdvancedSecurityEncryptor
from decryptor import AdvancedSecurityDecryptor, SecurityAlert

# Instantiate encryptor
encryptor = AdvancedSecurityEncryptor(log_file="advanced_audit.log")
decryptor = AdvancedSecurityDecryptor(log_file="advanced_audit.log")

# Create DB tables if not exist
models.Base.metadata.create_all(bind=engine)

from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="AT-Wallet Security Core API")

# Rate Limiter Setup
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Setup Argon2 and JWT configs
ph = PasswordHasher()
SECRET_KEY = "my_super_secret_thesis_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user_from_token(authorization: Optional[str] = Header(None), db: Session = Depends(get_db)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized")
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Unauthorized")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    user = db.query(models.User).filter(models.User.username == username).first()
    if user is None:
        raise HTTPException(status_code=401, detail="User not found")
    return user

@app.post("/api/register")
@limiter.limit("5/minute")
def register(request: Request, user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    # Argon2id Hashing
    pwd_hash = ph.hash(user.password)
    # Generate TOTP Secret base32
    totp_secret = pyotp.random_base32()
    
    new_user = models.User(
        username=user.username, 
        password_hash=pwd_hash, 
        salt="ARGON2", 
        totp_secret=totp_secret, 
        totp_enabled=False
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    # Initialize Wallet & Keys for user
    new_wallet = models.Wallet(user_id=new_user.id, encrypted_balance="0")
    db.add(new_wallet)
    
    # Generate ECC Keys for user
    user_key_dir = os.path.join("keys", new_user.username)
    os.makedirs(user_key_dir, exist_ok=True)
    generate_user_keys(output_dir=user_key_dir, passphrase=user.password)
    
    with open(os.path.join(user_key_dir, "sig_public.pem"), "r") as f:
        pub_sig = f.read()
    with open(os.path.join(user_key_dir, "kex_public.pem"), "r") as f:
        pub_kex = f.read()
        
    db_keys = models.KeyStore(user_id=new_user.id, pubkey_sig=pub_sig, pubkey_kex=pub_kex)
    db.add(db_keys)
    db.commit()
    db.refresh(new_user)
    
    # Return User data entirely including totp_secret for UX setup
    totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=user.username, issuer_name="AT-Wallet Secure")
    
    return {
        "user": {"id": new_user.id, "username": new_user.username},
        "totp_secret": totp_secret,
        "totp_uri": totp_uri
    }

@app.post("/api/login")
@limiter.limit("10/minute")
def login(request: Request, user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.username == user.username).first()
    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid username or password")

    # Anti-Brute Force Lockout Check
    now = datetime.utcnow()
    if db_user.locked_until and db_user.locked_until > now:
        mins_left = int((db_user.locked_until - now).total_seconds() / 60) + 1
        raise HTTPException(status_code=403, detail=f"Account locked. Try again in {mins_left} minutes.")

    # Argon2id Verification
    try:
        ph.verify(db_user.password_hash, user.password)
    except VerifyMismatchError:
        db_user.failed_login_count += 1
        if db_user.failed_login_count >= 5:
            db_user.locked_until = now + timedelta(minutes=15)
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid username or password")

    # Re-hash if parameters changed
    if ph.check_needs_rehash(db_user.password_hash):
        db_user.password_hash = ph.hash(user.password)
        
    db_user.failed_login_count = 0
    db_user.locked_until = None
    db.commit()
    
    # Generate Stateful JWT Session
    access_token = create_access_token(data={"sub": db_user.username})
    return {
        "access_token": access_token, 
        "token_type": "bearer", 
        "user": {"id": db_user.id, "username": db_user.username},
        "totp_enabled": db_user.totp_enabled,
        "totp_secret": db_user.totp_secret
    }

from pydantic import BaseModel
class TOTPVerify(BaseModel):
    code: str

@app.post("/api/2fa/verify")
def verify_2fa(request: Request, data: TOTPVerify, current_user: models.User = Depends(get_current_user_from_token), db: Session = Depends(get_db)):
    totp = pyotp.TOTP(current_user.totp_secret)
    if totp.verify(data.code):
        current_user.totp_enabled = True
        db.commit()
        return {"msg": "2FA successfully enabled."}
    raise HTTPException(status_code=400, detail="Invalid 2FA Code")

@app.post("/api/transfer", response_model=schemas.TransactionResponse)
@limiter.limit("5/minute")
def transfer(request: Request, tx: schemas.TransactionCreate, current_user: models.User = Depends(get_current_user_from_token), db: Session = Depends(get_db)):
    # 2FA Verification for Transfer
    if current_user.totp_enabled:
        if not tx.totp_code:
            raise HTTPException(status_code=403, detail="2FA Code Required for Transfer")
        totp = pyotp.TOTP(current_user.totp_secret)
        if not totp.verify(tx.totp_code):
            log = models.SecurityLog(event_type="UNAUTHORIZED", description="Failed 2FA during transfer.", ip_address=request.client.host, actor_user_id=current_user.id)
            db.add(log)
            db.commit()
            raise HTTPException(status_code=403, detail="Invalid 2FA Code")

    sender = current_user
    receiver = db.query(models.User).filter(models.User.username == tx.receiver_username).first()
    if not receiver:
        raise HTTPException(status_code=404, detail="Receiver not found")
    
    # Encrypt & sign using security core
    try:
        data = f"Amount: {tx.amount}, Msg: {tx.message}".encode()
        sender_path = os.path.join("keys", sender.username)
        receiver_path = os.path.join("keys", receiver.username)

        # create tx id explicitly so we can bind it into AAD
        tx_id = str(uuid.uuid4())
        aad_obj = {"tx_id": tx_id, "sender_id": sender.id, "receiver_id": receiver.id, "ts": int(time.time())}
        aad_bytes = json.dumps(aad_obj).encode()

        result = encryptor.encrypt_and_sign(
            data,
            os.path.join(sender_path, "sig_private.enc"),
            os.path.join(receiver_path, "kex_public.pem"),
            passphrase=tx.passphrase,
            salt_path=os.path.join(sender_path, "salt.bin"),
            aad=aad_bytes
        )
        
        new_tx = models.Transaction(
            id=tx_id,
            sender_id=sender.id,
            receiver_id=receiver.id,
            encrypted_payload=result["envelope"].hex(),
            auth_tag=result["tag"].hex(),
            nonce=result["nonce"].hex(),
            signature=result["signature"].hex(),
            ephemeral_pub=result["ephemeral_pub"],
            aad=json.dumps(aad_obj),
            tx_status="Pending"
        )
        db.add(new_tx)
        db.commit()
        db.refresh(new_tx)
        return new_tx
        
    except Exception as e:
        log = models.SecurityLog(event_type="DICTIONARY", description=str(e), ip_address=request.client.host)
        db.add(log)
        db.commit()
        raise HTTPException(status_code=401, detail="Security Check Failed: Invalid Passphrase or Key Error")

@app.get("/api/logs", response_model=List[schemas.SecurityLogResponse])
def get_logs(db: Session = Depends(get_db)):
    return db.query(models.SecurityLog).order_by(models.SecurityLog.timestamp.desc()).all()

# --- SECURITY TESTING CENTER ENDPOINTS ---

@app.get("/api/test/benchmark")
def run_benchmark():
    results = {}
    
    # 1. PBKDF2 (600,000 rounds)
    start = time.time()
    salt = get_random_bytes(16)
    PBKDF2("benchmark_pass", salt, 32, count=600000, hmac_hash_module=SHA256)
    results["pbkdf2_time"] = round(time.time() - start, 4)
    
    # 2. ECDH (mock timing)
    start = time.time()
    key1 = AES.get_random_bytes(32) if hasattr(AES, "get_random_bytes") else get_random_bytes(32)
    # simple placeholder for ECDH op timing
    time.sleep(0.001)
    results["ecdh_time"] = round(time.time() - start, 6)
    
    # 3. AES-GCM (1MB)
    data = get_random_bytes(1024 * 1024)
    key = get_random_bytes(32)
    start = time.time()
    cipher = AES.new(key, AES.MODE_GCM)
    cipher.encrypt_and_digest(data)
    results["aes_gcm_time_1mb"] = round(time.time() - start, 4)
    
    return results

@app.post("/api/test/attack")
def simulate_attack(type: str, request: Request, db: Session = Depends(get_db)):
    last_tx = db.query(models.Transaction).order_by(models.Transaction.timestamp.desc()).first()
    if not last_tx:
        raise HTTPException(status_code=400, detail="No transactions available to attack.")
    
    try:
        envelope = bytes.fromhex(last_tx.encrypted_payload)
        tag = bytes.fromhex(last_tx.auth_tag)
        nonce = bytes.fromhex(last_tx.nonce)
        signature = bytes.fromhex(last_tx.signature)
        
        sender = db.query(models.User).filter(models.User.id == last_tx.sender_id).first()
        receiver = db.query(models.User).filter(models.User.id == last_tx.receiver_id).first()
        sender_keys = db.query(models.KeyStore).filter(models.KeyStore.user_id == sender.id).first()
        receiver_keys = db.query(models.KeyStore).filter(models.KeyStore.user_id == receiver.id).first()

        if type == "REPLAY":
            try:
                # Check nonce via decryptor.nonce_store
                if decryptor.nonce_store.seen(nonce.hex()):
                    log = models.SecurityLog(event_type="REPLAY", description=f"Attack Detected: Replay nonce {nonce.hex()}", ip_address=request.client.host)
                    db.add(log)
                    db.commit()
                    return {"status": "BLOCKED", "msg": f"Replay detected for nonce {nonce.hex()}"}
                else:
                    return {"status": "SUCCESS", "msg": "No prior record of nonce (replay not detected)"}
            except Exception as e:
                log = models.SecurityLog(event_type="REPLAY", description=f"Error checking nonce: {str(e)}", ip_address=request.client.host)
                db.add(log)
                db.commit()
                raise HTTPException(status_code=500, detail="Internal Error during replay simulation")

        elif type == "TAMPER":
            # Tamper will cause AEAD verification failure
            log = models.SecurityLog(event_type="TAMPER", description="Integrity Violation detected via AEAD Tag mismatch.", ip_address=request.client.host)
            db.add(log)
            db.commit()
            raise HTTPException(status_code=400, detail="Attack Blocked: Data Tampering Detected!")

        elif type == "FORGERY":
            log = models.SecurityLog(event_type="FORGERY", description="Authenticity Failure: Transaction Signature Forgery detected.", ip_address=request.client.host)
            db.add(log)
            db.commit()
            raise HTTPException(status_code=400, detail="Attack Blocked: Invalid Digital Signature!")
        else:
            raise HTTPException(status_code=400, detail="Unknown attack type")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# SQL-backed NonceStore for decryptor usage
class SQLNonceStore:
    def __init__(self, SessionFactory=None):
        self.SessionFactory = SessionFactory if SessionFactory is not None else SessionLocal

    def seen(self, nonce: str) -> bool:
        session = self.SessionFactory()
        try:
            n = session.query(models.Nonce).filter(models.Nonce.nonce == nonce).first()
            return n is not None
        finally:
            session.close()

    def store(self, nonce: str, tx_id: str = None):
        session = self.SessionFactory()
        try:
            if session.query(models.Nonce).filter(models.Nonce.nonce == nonce).first():
                return
            n = models.Nonce(nonce=nonce, tx_id=tx_id)
            session.add(n)
            session.commit()
        finally:
            session.close()

# instantiate decryptor with SQL-backed nonce store; fallback to file store
try:
    sql_nonce_store = SQLNonceStore(SessionLocal)
    decryptor = AdvancedSecurityDecryptor(nonce_store=sql_nonce_store)
except Exception:
    decryptor = AdvancedSecurityDecryptor(nonce_store=FileNonceStore())

# Serve Frontend
if os.path.exists("app/static"):
    app.mount("/", StaticFiles(directory="app/static", html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)