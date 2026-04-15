from sqlalchemy import Column, Integer, String, Float, ForeignKey, DateTime, Text, Boolean, UniqueConstraint
from sqlalchemy.orm import relationship
from .database import Base
import datetime
import uuid

class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String, unique=True, index=True)
    password_hash = Column(String) # Argon2 / PBKDF2
    salt = Column(String)  # per-user salt (hex)
    
    # 2FA Fields
    totp_secret = Column(String, nullable=True)
    totp_enabled = Column(Boolean, default=False)
    
    role = Column(String, default="User") # User/Admin
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
    # Anti-brute fields
    failed_login_count = Column(Integer, default=0)
    last_failed_at = Column(DateTime, nullable=True)
    locked_until = Column(DateTime, nullable=True)

    wallet = relationship("Wallet", back_populates="owner", uselist=False)
    keys = relationship("KeyStore", back_populates="owner")

class Wallet(Base):
    __tablename__ = "wallets"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"))
    encrypted_balance = Column(String) # AES encrypted balance string
    status = Column(String, default="Active")
    last_updated = Column(DateTime, default=datetime.datetime.utcnow)
    
    owner = relationship("User", back_populates="wallet")

class KeyStore(Base):
    __tablename__ = "keystore"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(String, ForeignKey("users.id"))
    pubkey_sig = Column(Text) # Ed25519 PEM string
    pubkey_kex = Column(Text) # Curve25519 PEM string
    status = Column(String, default="Valid")
    key_version = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    revoked = Column(Boolean, default=False)
    revoked_at = Column(DateTime, nullable=True)
    
    owner = relationship("User", back_populates="keys")

class Transaction(Base):
    __tablename__ = "transactions"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    sender_id = Column(String, ForeignKey("users.id"))
    receiver_id = Column(String, ForeignKey("users.id"))
    encrypted_payload = Column(Text) # GCM Ciphertext hex
    auth_tag = Column(String) # GCM Tag hex
    nonce = Column(String, index=True) # GCM Nonce hex
    signature = Column(Text) # EdDSA Signature hex
    ephemeral_pub = Column(Text, nullable=True) # Ephemeral Curve25519 Public Key for PFS
    aad = Column(Text, nullable=True)  # Additional Authenticated Data (metadata bound to AEAD)
    tx_status = Column(String, default="Pending") # Pending / Verified / Rejected
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

class Nonce(Base):
    __tablename__ = "nonces"
    id = Column(Integer, primary_key=True, index=True)
    nonce = Column(String, unique=True, index=True)
    used_at = Column(DateTime, default=datetime.datetime.utcnow)
    tx_id = Column(String, ForeignKey("transactions.id"), nullable=True)
    source_ip = Column(String, nullable=True)

    __table_args__ = (
        UniqueConstraint("nonce", name="uq_nonce_nonce"),
    )

class SecurityLog(Base):
    __tablename__ = "security_logs"
    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String) # REPLAY, TAMPER, FORGERY, DICTIONARY, INFO, WARN
    severity = Column(String, default="INFO") # INFO / WARNING / CRITICAL
    description = Column(Text)
    actor_user_id = Column(String, ForeignKey("users.id"), nullable=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    ip_address = Column(String, nullable=True)

    # relationship backref
    actor = relationship("User", primaryjoin="User.id==SecurityLog.actor_user_id", backref="security_events")