from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

class UserBase(BaseModel):
    username: str

class UserCreate(UserBase):
    password: str

class UserResponse(UserBase):
    id: str
    role: str
    created_at: datetime
    class Config:
        from_attributes = True

class WalletResponse(BaseModel):
    id: str
    status: str
    last_updated: datetime
    class Config:
        from_attributes = True

class TransactionCreate(BaseModel):
    receiver_username: str
    amount: float
    message: Optional[str] = ""
    passphrase: str
    totp_code: Optional[str] = None

class TransactionResponse(BaseModel):
    id: str
    sender_id: str
    receiver_id: str
    timestamp: datetime
    tx_status: str  # matches models.Transaction.tx_status
    class Config:
        from_attributes = True

class SecurityLogResponse(BaseModel):
    id: int
    event_type: str
    description: str
    timestamp: datetime
    class Config:
        from_attributes = True