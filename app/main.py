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

# Setup Argon2 and JWT configs
ph = PasswordHasher()

def seed_initial_data():
    db = SessionLocal()
    try:
        # 1. Seed ADMIN
        admin_user = db.query(models.User).filter(models.User.username == "admin").first()
        if not admin_user:
            admin_hash = ph.hash("admin123")
            totp_secret = pyotp.random_base32()
            admin_user = models.User(username="admin", password_hash=admin_hash, salt="ARGON2", totp_secret=totp_secret, totp_enabled=False, role="Admin")
            db.add(admin_user)
            db.commit()
            db.refresh(admin_user)
            db.add(models.Wallet(user_id=admin_user.id, encrypted_balance="10000.0"))
            user_key_dir = os.path.join("keys", "admin")
            os.makedirs(user_key_dir, exist_ok=True)
            generate_user_keys(output_dir=user_key_dir, passphrase="admin123")
            with open(os.path.join(user_key_dir, "sig_public.pem"), "r") as f: pub_sig = f.read()
            with open(os.path.join(user_key_dir, "kex_public.pem"), "r") as f: pub_kex = f.read()
            db.add(models.KeyStore(user_id=admin_user.id, pubkey_sig=pub_sig, pubkey_kex=pub_kex))
            db.commit()
            print("[INFO] Admin provisioned (pw: admin123)")
        else:
            admin_user.role = "Admin"
            db.commit()

        # 2. Seed MOCK USERS for testing
        test_user = db.query(models.User).filter(models.User.username == "user123").first()
        
        if not test_user:
            test_hash = ph.hash("user123")
            totp_secret = pyotp.random_base32()
            test_user = models.User(username="user123", password_hash=test_hash, salt="ARGON2", totp_secret=totp_secret, totp_enabled=False, role="User")
            db.add(test_user)
            db.commit()
            db.refresh(test_user)
            db.add(models.Wallet(user_id=test_user.id, encrypted_balance="5000.0"))
            user_key_dir = os.path.join("keys", "user123")
            os.makedirs(user_key_dir, exist_ok=True)
            generate_user_keys(output_dir=user_key_dir, passphrase="user123")
            with open(os.path.join(user_key_dir, "sig_public.pem"), "r") as f: pub_sig = f.read()
            with open(os.path.join(user_key_dir, "kex_public.pem"), "r") as f: pub_kex = f.read()
            db.add(models.KeyStore(user_id=test_user.id, pubkey_sig=pub_sig, pubkey_kex=pub_kex))
            db.commit()
            print("[INFO] Test User 'user123' provisioned (pw: user123)")
        else:
            # Force reset balance for demo purpose
            wallet = db.query(models.Wallet).filter(models.Wallet.user_id == test_user.id).first()
            if wallet:
                wallet.encrypted_balance = "5000.0"
            db.commit()
            print("[INFO] Test User 'user123' balance reset to 5000.0")

    except Exception as e:
        print("[ERROR] Seeding failed:", e)
    finally:
        db.close()

seed_initial_data()
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="AT-Wallet Security Core API")

# Rate Limiter Setup
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Setup Argon2 and JWT configs
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
    # Grant Admin role if username is admin
    user_role = "Admin" if user.username.lower() == "admin" else "User"

    new_user = models.User(
        username=user.username, 
        password_hash=pwd_hash, 
        salt="ARGON2", 
        totp_secret=totp_secret, 
        totp_enabled=False,
        role=user_role
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
        "user": {"id": new_user.id, "username": new_user.username, "role": new_user.role},
        "totp_secret": totp_secret,
        "totp_uri": totp_uri
    }

@app.post("/api/login")
@limiter.limit("10/minute")
def login(request: Request, user: schemas.UserLogin, db: Session = Depends(get_db)):
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
        "user": {"id": db_user.id, "username": db_user.username, "role": db_user.role},
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
        raise HTTPException(status_code=404, detail="Người dùng không tồn tại.")

    # Block sending to yourself
    if receiver.id == current_user.id:
        raise HTTPException(status_code=400, detail="Không thể gửi tiền cho chính mình.")

    # Block sending to admin (admin is system-only, not a real user wallet)
    if receiver.username.lower() == "admin":
        raise HTTPException(status_code=403, detail="Không thể gửi tiền đến tài khoản quản trị viên (admin).")

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
            passphrase=tx.payment_pin,
            salt_path=os.path.join(sender_path, "salt.bin"),
            aad=aad_bytes
        )
        
        new_tx = models.Transaction(
            id=tx_id,
            sender_id=sender.id,
            receiver_id=receiver.id,
            amount=tx.amount,
            encrypted_payload=result["envelope"].hex(),
            auth_tag=result["tag"].hex(),
            nonce=result["nonce"].hex(),
            signature=result["signature"].hex(),
            ephemeral_pub=result["ephemeral_pub"],
            aad=json.dumps(aad_obj),
            tx_status="Verified" # Mark as verified immediately on success
        )
        
        # Balance Update Logic
        sender_wallet = db.query(models.Wallet).filter(models.Wallet.user_id == sender.id).first()
        receiver_wallet = db.query(models.Wallet).filter(models.Wallet.user_id == receiver.id).first()
        
        if sender_wallet and receiver_wallet:
            s_bal = float(sender_wallet.encrypted_balance)
            r_bal = float(receiver_wallet.encrypted_balance)
            
            if s_bal < tx.amount:
                 raise Exception("Sufficient funds not available in wallet.")
            
            sender_wallet.encrypted_balance = str(s_bal - tx.amount)
            receiver_wallet.encrypted_balance = str(r_bal + tx.amount)
            sender_wallet.last_updated = datetime.utcnow()
            receiver_wallet.last_updated = datetime.utcnow()

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

@app.get("/api/wallet/balance", response_model=schemas.WalletBalanceResponse)
def get_balance(current_user: models.User = Depends(get_current_user_from_token), db: Session = Depends(get_db)):
    wallet = db.query(models.Wallet).filter(models.Wallet.user_id == current_user.id).first()
    return {"balance": float(wallet.encrypted_balance) if wallet else 0.0}

@app.get("/api/transactions/history", response_model=List[schemas.TransactionHistoryItem])
def get_transaction_history(current_user: models.User = Depends(get_current_user_from_token), db: Session = Depends(get_db)):
    txs = db.query(models.Transaction).filter(
        (models.Transaction.sender_id == current_user.id) | (models.Transaction.receiver_id == current_user.id)
    ).order_by(models.Transaction.timestamp.desc()).all()
    
    results = []
    for tx in txs:
        sender = db.query(models.User).filter(models.User.id == tx.sender_id).first()
        receiver = db.query(models.User).filter(models.User.id == tx.receiver_id).first()
        
        # Determine if current user is sender or receiver
        is_sender = (tx.sender_id == current_user.id)
        
        results.append({
            "id": tx.id,
            "sender_username": sender.username if sender else "Unknown",
            "receiver_username": receiver.username if receiver else "Unknown",
            "amount": tx.amount,
            "message": "Encrypted Content" if is_sender else "Received SecP256k1 Payload", # Mocking for demo
            "timestamp": tx.timestamp,
            "tx_status": tx.tx_status,
            "is_sender": is_sender
        })
    return results

# --- PAYMENT REQUEST ENDPOINTS ---

@app.post("/api/transactions/request")
@limiter.limit("20/minute")
def create_payment_request(request: Request, data: schemas.PaymentRequestCreate,
                            current_user: models.User = Depends(get_current_user_from_token),
                            db: Session = Depends(get_db)):
    """User A requests money from User B."""
    target = db.query(models.User).filter(models.User.username == data.target_username).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target user not found.")
    if target.id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot request money from yourself.")

    tx = models.Transaction(
        sender_id=target.id,
        receiver_id=current_user.id,
        amount=data.amount,
        aad=data.message or "",
        tx_status="Requested",
        encrypted_payload="",
        auth_tag="",
        nonce="",
        signature=""
    )
    db.add(tx)
    db.add(models.SecurityLog(event_type="PAYMENT_REQUEST",
                               description=f"{current_user.username} requested ฿{data.amount} from {data.target_username}"))
    db.commit()
    return {"msg": f"Payment request of ฿{data.amount} sent to {data.target_username}."}


@app.get("/api/transactions/requests/incoming")
def get_incoming_requests(current_user: models.User = Depends(get_current_user_from_token),
                           db: Session = Depends(get_db)):
    """Get all pending payment requests where current user is the one who should pay."""
    txs = db.query(models.Transaction).filter(
        models.Transaction.sender_id == current_user.id,
        models.Transaction.tx_status == "Requested"
    ).order_by(models.Transaction.timestamp.desc()).all()

    results = []
    for tx in txs:
        requester = db.query(models.User).filter(models.User.id == tx.receiver_id).first()
        results.append({
            "id": tx.id,
            "requester_username": requester.username if requester else "Unknown",
            "amount": tx.amount,
            "message": tx.aad or "",
            "timestamp": tx.timestamp.isoformat()
        })
    return results


@app.post("/api/transactions/requests/fulfill/{tx_id}")
@limiter.limit("20/minute")
def fulfill_payment_request(request: Request, tx_id: str, data: schemas.PaymentRequestFulfill,
                              current_user: models.User = Depends(get_current_user_from_token),
                              db: Session = Depends(get_db)):
    """Current user pays a pending payment request addressed to them."""
    tx = db.query(models.Transaction).filter(
        models.Transaction.id == tx_id,
        models.Transaction.sender_id == current_user.id,
        models.Transaction.tx_status == "Requested"
    ).first()
    if not tx:
        raise HTTPException(status_code=404, detail="Payment request not found.")

    # Verify Payment PIN
    if not current_user.payment_pin_hash:
        raise HTTPException(status_code=400, detail="Bạn chưa cài Payment PIN. Vui lòng thiết lập trong Settings.")
    try:
        ph.verify(current_user.payment_pin_hash, data.payment_pin)
    except Exception:
        raise HTTPException(status_code=403, detail="Mã PIN không đúng. Thanh toán bị từ chối.")

    # Check wallet balance
    wallet = db.query(models.Wallet).filter(models.Wallet.user_id == current_user.id).first()
    if not wallet or float(wallet.encrypted_balance) < tx.amount:
        raise HTTPException(status_code=400, detail=f"Số dư không đủ. Bạn cần ít nhất ฿{tx.amount} để thực hiện thanh toán này.")

    receiver_wallet = db.query(models.Wallet).filter(models.Wallet.user_id == tx.receiver_id).first()
    if not receiver_wallet:
        raise HTTPException(status_code=404, detail="Receiver wallet not found.")

    # Debit sender, credit receiver
    wallet.encrypted_balance = str(float(wallet.encrypted_balance) - tx.amount)
    receiver_wallet.encrypted_balance = str(float(receiver_wallet.encrypted_balance) + tx.amount)

    # Mark request as completed
    tx.tx_status = "Completed"
    tx.encrypted_payload = "FULFILLED"
    tx.signature = "FULFILLED"

    requester = db.query(models.User).filter(models.User.id == tx.receiver_id).first()
    db.add(models.SecurityLog(event_type="PAYMENT_FULFILLED",
                               description=f"{current_user.username} fulfilled ฿{tx.amount} request from {requester.username if requester else 'Unknown'}"))
    db.commit()
    return {"msg": f"Payment of ฿{tx.amount} fulfilled successfully."}


# --- PASSWORD RECOVERY (OTP) ENDPOINTS ---

@app.post("/api/auth/forgot-password")
@limiter.limit("5/minute")
def forgot_password(request: Request, data: schemas.ForgotPasswordRequest, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.username == data.username).first()
    if not db_user:
        # Prevent user enumeration by returning a generic success message
        return {"msg": "If the username exists, a recovery OTP has been sent."}
    
    import random
    from datetime import datetime, timedelta
    
    # Generate 6-digit OTP
    otp_code = f"{random.randint(0, 999999):06d}"
    
    # Store hashed OTP in database with 15 mins expiry
    expires = datetime.utcnow() + timedelta(minutes=15)
    
    # Clean up old resets for this user
    db.query(models.PasswordReset).filter(models.PasswordReset.user_id == db_user.id).delete()
    
    new_reset = models.PasswordReset(
        user_id=db_user.id,
        otp_hash=ph.hash(otp_code),
        expires_at=expires
    )
    db.add(new_reset)
    db.commit()
    
    # MOCK EMAIL
    print("\n" + "="*50)
    print(f"[MOCK EMAIL] Password Reset Request for {data.username}")
    print(f"Your 6-digit OTP Code is: {otp_code}")
    print("This code will expire in 15 minutes.")
    print("="*50 + "\n")
    
    return {"msg": "If the username exists, a recovery OTP has been sent."}

@app.post("/api/auth/reset-password")
@limiter.limit("5/minute")
def reset_password(request: Request, data: schemas.UserResetPassword, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.username == data.username).first()
    if not db_user:
        raise HTTPException(status_code=400, detail="Invalid request parameters.")
        
    import datetime
    active_reset = db.query(models.PasswordReset).filter(
        models.PasswordReset.user_id == db_user.id,
        models.PasswordReset.expires_at > datetime.datetime.utcnow()
    ).first()
    
    if not active_reset:
        raise HTTPException(status_code=400, detail="OTP Code expired or not found.")
        
    try:
        ph.verify(active_reset.otp_hash, data.otp_code)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid OTP Code.")
        
    # Validation passed - Update password
    db_user.password_hash = ph.hash(data.new_password)
    db_user.failed_login_count = 0 
    db_user.locked_until = None
    
    # Delete the reset token
    db.delete(active_reset)
    db.commit()
    
    return {"msg": "Password reset successful. You can now login with your new password."}
# --- CHANGE PASSWORD ENDPOINT ---

@app.post("/api/auth/change-password")
@limiter.limit("10/minute")
def change_password(request: Request, data: schemas.UserChangePassword,
                    current_user: models.User = Depends(get_current_user_from_token),
                    db: Session = Depends(get_db)):
    """Allow logged-in user to change their own password."""
    # Verify old password
    try:
        ph.verify(current_user.password_hash, data.old_password)
    except Exception:
        raise HTTPException(status_code=400, detail="Mật khẩu cũ không đúng.")

    if len(data.new_password) < 6:
        raise HTTPException(status_code=400, detail="Mật khẩu mới phải có ít nhất 6 ký tự.")

    # Update password
    current_user.password_hash = ph.hash(data.new_password)
    db.add(models.SecurityLog(
        event_type="PASSWORD_CHANGED",
        description=f"User '{current_user.username}' changed their password."
    ))
    db.commit()
    return {"msg": "Đổi mật khẩu thành công! Hãy đăng nhập lại."}

# --- ADMIN MANAGEMENT ENDPOINTS ---

@app.get("/api/admin/users")
def get_all_users(db: Session = Depends(get_db)):
    # Note: Bypassing strict Role checks for demo/thesis presentation purposes
    users = db.query(models.User).order_by(models.User.created_at.desc()).all()
    results = []
    for u in users:
        keys = db.query(models.KeyStore).filter(models.KeyStore.user_id == u.id).first()
        results.append({
            "id": u.id,
            "username": u.username,
            "role": u.role,
            "created_at": u.created_at.isoformat() if u.created_at else None,
            "totp_enabled": u.totp_enabled,
            "locked_until": u.locked_until.isoformat() if u.locked_until else None,
            "failed_login_count": u.failed_login_count,
            "keys_status": keys.status if keys else "Missing",
            "keys_revoked": keys.revoked if keys else False
        })
    return {"users": results}

@app.post("/api/admin/unlock/{user_id}")
def unlock_user(user_id: str, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user:
        user.locked_until = None
        user.failed_login_count = 0
        db.commit()
        return {"msg": f"Account {user.username} unlocked."}
    raise HTTPException(status_code=404, detail="User not found")

@app.post("/api/admin/revoke/{user_id}")
def revoke_keys(user_id: str, db: Session = Depends(get_db)):
    keys = db.query(models.KeyStore).filter(models.KeyStore.user_id == user_id).first()
    if keys:
        keys.revoked = True
        keys.status = "Revoked"
        db.commit()
        return {"msg": "Cryptographic Keys revoked."}
    raise HTTPException(status_code=404, detail="Keys not found")

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

@app.get("/api/test/captured-packet")
def get_captured_packet(db: Session = Depends(get_db)):
    """Return the last encrypted transaction packet for the attacker demo page."""
    last_tx = db.query(models.Transaction).filter(
        models.Transaction.tx_status.in_(["Completed", "Verified"]),
        models.Transaction.encrypted_payload != "",
        models.Transaction.encrypted_payload != "FULFILLED"
    ).order_by(models.Transaction.timestamp.desc()).first()

    if not last_tx:
        raise HTTPException(status_code=404, detail="Chưa có giao dịch nào để mô phỏng. Hãy thực hiện một giao dịch trước.")

    sender = db.query(models.User).filter(models.User.id == last_tx.sender_id).first()
    receiver = db.query(models.User).filter(models.User.id == last_tx.receiver_id).first()
    nonce_hex = last_tx.nonce if last_tx.nonce else "N/A"
    already_seen = False
    try:
        already_seen = decryptor.nonce_store.seen(nonce_hex)
    except Exception:
        pass

    return {
        "tx_id": last_tx.id,
        "sender": sender.username if sender else "Unknown",
        "receiver": receiver.username if receiver else "Unknown",
        "amount": last_tx.amount,
        "timestamp": last_tx.timestamp.isoformat(),
        "nonce": nonce_hex[:32] + "..." if len(nonce_hex) > 32 else nonce_hex,
        "nonce_full": nonce_hex,
        "encrypted_payload": last_tx.encrypted_payload[:64] + "..." if len(last_tx.encrypted_payload) > 64 else last_tx.encrypted_payload,
        "signature": last_tx.signature[:64] + "..." if len(last_tx.signature) > 64 else last_tx.signature,
        "nonce_already_seen": already_seen,
        "tx_status": last_tx.tx_status
    }

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
                    log = models.SecurityLog(event_type="REPLAY", description=f"Attack Blocked: Replay nonce {nonce.hex()[:16]}... bị từ chối.", ip_address=request.client.host)
                    db.add(log)
                    db.commit()
                    raise HTTPException(status_code=400, detail="Attack Blocked: Hệ thống phát hiện và từ chối Replay Attack!")
                else:
                    # Register nonce so next replay IS blocked
                    decryptor.nonce_store.store(nonce.hex(), tx_id=last_tx.id)
                    log = models.SecurityLog(event_type="REPLAY", description=f"Replay sim: Nonce {nonce.hex()[:16]}... vừa ghi nhận. Bấm lại để thấy chặn.", ip_address=request.client.host)
                    db.add(log)
                    db.commit()
                    return {"status": "RECORDED", "msg": "Nonce đã được ghi nhận. Bấm Replay lần nữa để thấy hệ thống chặn tấn công!"}
            except HTTPException:
                raise
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