"""
UMEagleEye - Pydantic schemas for authentication and user management.
"""

from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field

from app.db.enums import UserRole


# ── Auth Request Schemas ──
class UserRegister(BaseModel):
    username: str = Field(..., min_length=3, max_length=100)
    email: str = Field(..., max_length=255)
    password: str = Field(..., min_length=8, max_length=128)
    role: UserRole = UserRole.BUSINESS_OWNER


class UserLogin(BaseModel):
    username: str
    password: str


class MFASetupResponse(BaseModel):
    totp_secret: str
    qr_code_base64: str
    message: str = "Scan QR code with authenticator app"


class MFAVerify(BaseModel):
    username: str
    code: str = Field(..., min_length=6, max_length=6)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    user_id: str
    mfa_required: bool = False


# ── User Response Schemas ──
class UserResponse(BaseModel):
    user_id: UUID
    username: str
    email: str
    role: UserRole
    mfa_enabled: bool
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime] = None

    model_config = {"from_attributes": True}


class UserUpdate(BaseModel):
    email: Optional[str] = None
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None
