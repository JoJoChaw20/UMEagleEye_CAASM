"""
UMEagleEye - Auth API routes: register, login, MFA setup/verify, Google OAuth.
"""

import secrets
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from google.oauth2 import id_token
from google.auth.transport import requests as google_requests

from app.core.config import settings
from app.core.dependencies import get_db, get_current_user
from app.core.security import (
    hash_password, verify_password, create_access_token,
    generate_totp_secret, generate_totp_qr_base64, verify_totp
)
from app.db.models import User, AuditLog
from app.db.enums import UserRole
from app.schemas.auth import (
    UserRegister, UserLogin, TokenResponse,
    MFASetupResponse, MFAVerify, UserResponse, GoogleLoginRequest
)

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(payload: UserRegister, db: AsyncSession = Depends(get_db)):
    """Register a new user account."""
    # Check existing username
    result = await db.execute(select(User).where(User.username == payload.username))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Username already exists")

    # Check existing email
    result = await db.execute(select(User).where(User.email == payload.email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Email already registered")

    user = User(
        username=payload.username,
        email=payload.email,
        password_hash=hash_password(payload.password),
        role=payload.role,
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    return user


@router.post("/login", response_model=TokenResponse)
async def login(payload: UserLogin, db: AsyncSession = Depends(get_db)):
    """Authenticate user and return JWT token."""
    result = await db.execute(select(User).where(User.username == payload.username))
    user = result.scalar_one_or_none()

    if not user or not verify_password(payload.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is deactivated")

    # If MFA is enabled, require verification first
    if user.mfa_enabled:
        return TokenResponse(
            access_token="",
            role=user.role.value,
            user_id=str(user.user_id),
            mfa_required=True,
        )

    # Update last login
    user.last_login = datetime.now(timezone.utc)

    token = create_access_token(data={
        "sub": str(user.user_id),
        "role": user.role.value,
        "username": user.username,
    })

    return TokenResponse(
        access_token=token,
        role=user.role.value,
        user_id=str(user.user_id),
    )


@router.post("/mfa/setup", response_model=MFASetupResponse)
async def setup_mfa(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate TOTP secret and QR code for MFA enrollment."""
    secret = generate_totp_secret()
    current_user.totp_secret = secret
    qr_base64 = generate_totp_qr_base64(secret, current_user.username)

    return MFASetupResponse(totp_secret=secret, qr_code_base64=qr_base64)


@router.post("/mfa/enable", response_model=dict)
async def enable_mfa(
    payload: MFAVerify,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Verify TOTP code and enable MFA on the account."""
    if not current_user.totp_secret:
        raise HTTPException(status_code=400, detail="Run /auth/mfa/setup first")

    if not verify_totp(current_user.totp_secret, payload.code):
        raise HTTPException(status_code=400, detail="Invalid TOTP code")

    current_user.mfa_enabled = True

    # Audit log
    db.add(AuditLog(
        user_id=current_user.user_id,
        action_type="mfa_enabled",
        target_entity=f"users/{current_user.user_id}",
    ))

    return {"message": "MFA enabled successfully"}


@router.post("/mfa/verify", response_model=TokenResponse)
async def verify_mfa(payload: MFAVerify, db: AsyncSession = Depends(get_db)):
    """Verify TOTP code and issue JWT token for MFA-enabled users."""
    result = await db.execute(select(User).where(User.username == payload.username))
    user = result.scalar_one_or_none()

    if not user or not user.mfa_enabled or not user.totp_secret:
        raise HTTPException(status_code=400, detail="MFA not configured for this user")

    if not verify_totp(user.totp_secret, payload.code):
        raise HTTPException(status_code=401, detail="Invalid TOTP code")

    user.last_login = datetime.now(timezone.utc)

    token = create_access_token(data={
        "sub": str(user.user_id),
        "role": user.role.value,
        "username": user.username,
    })

    return TokenResponse(
        access_token=token,
        role=user.role.value,
        user_id=str(user.user_id),
    )


@router.post("/google", response_model=TokenResponse)
async def google_login(payload: GoogleLoginRequest, db: AsyncSession = Depends(get_db)):
    """Authenticate via Google ID token and return a JWT."""
    if not settings.GOOGLE_CLIENT_ID:
        raise HTTPException(status_code=501, detail="Google login is not configured")

    try:
        id_info = id_token.verify_oauth2_token(
            payload.credential,
            google_requests.Request(),
            settings.GOOGLE_CLIENT_ID,
        )
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid Google token")

    google_sub = id_info["sub"]
    email = id_info.get("email", "")

    # 1. Find by google_id
    result = await db.execute(select(User).where(User.google_id == google_sub))
    user = result.scalar_one_or_none()

    if not user:
        # 2. Link to existing account that shares the same email
        result = await db.execute(select(User).where(User.email == email))
        user = result.scalar_one_or_none()
        if user:
            user.google_id = google_sub
        else:
            # 3. Create a new account
            base = email.split("@")[0] if email else "user"
            username = base
            counter = 1
            while True:
                dup = await db.execute(select(User).where(User.username == username))
                if not dup.scalar_one_or_none():
                    break
                username = f"{base}{counter}"
                counter += 1

            user = User(
                username=username,
                email=email,
                password_hash=hash_password(secrets.token_hex(32)),
                google_id=google_sub,
                role=UserRole.BUSINESS_OWNER,
            )
            db.add(user)
            await db.flush()
            await db.refresh(user)

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is deactivated")

    user.last_login = datetime.now(timezone.utc)

    token = create_access_token(data={
        "sub": str(user.user_id),
        "role": user.role.value,
        "username": user.username,
    })

    return TokenResponse(
        access_token=token,
        role=user.role.value,
        user_id=str(user.user_id),
    )


@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(current_user: User = Depends(get_current_user)):
    """Get the current authenticated user's profile."""
    return current_user
