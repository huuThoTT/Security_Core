from sqlalchemy import Column, Integer, String, Float, ForeignKey, DateTime, Text
from sqlalchemy.orm import relationship
from .database import Base
import datetime
import uuid

class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String, unique=True, index=True)
    password_hash = Column(String) # PBKDF2 hashed
    salt = Column(String)
    role = Column(String, default="User") # User/Admin
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    
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
    
    owner = relationship("User", back_populates="keys")

class Transaction(Base):
    __tablename__ = "transactions"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    sender_id = Column(String, ForeignKey("users.id"))
    receiver_id = Column(String, ForeignKey("users.id"))
    encrypted_payload = Column(Text) # GCM Ciphertext hex
    auth_tag = Column(String) # GCM Tag hex
    nonce = Column(String) # GCM Nonce hex
    signature = Column(Text) # EdDSA Signature hex
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)

class SecurityLog(Base):
    __tablename__ = "security_logs"
    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String) # REPLAY, TAMPER, FORGERY, DICTIONARY
    description = Column(Text)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
    ip_address = Column(String)
