from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

class UserBase(BaseModel):
    username: str

class UserCreate(UserBase):
    password: str
    payment_pin: str # 6-digit numeric PIN recommended

class UserLogin(UserBase):
    password: str

class UserChangePassword(BaseModel):
    old_password: str
    new_password: str

class ForgotPasswordRequest(BaseModel):
    username: str

class UserResetPassword(BaseModel):
    username: str
    otp_code: str # 6-digit code
    new_password: str

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
    payment_pin: str
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

class WalletBalanceResponse(BaseModel):
    balance: float

class TransactionHistoryItem(BaseModel):
    id: str
    sender_username: str
    receiver_username: str
    amount: float
    message: Optional[str]
    timestamp: datetime
    tx_status: str
    is_sender: bool

class PaymentRequestCreate(BaseModel):
    target_username: str
    amount: float
    message: Optional[str] = ""

class PaymentRequestFulfill(BaseModel):
    payment_pin: str
    totp_code: Optional[str] = None