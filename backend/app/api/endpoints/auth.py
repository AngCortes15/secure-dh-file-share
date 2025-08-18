# FastAPI
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# Database
from sqlalchemy.orm import Session
from app.db.database import get_db
from app.db.models import User

# Security
from app.core.security import (
    create_access_token, create_refresh_token, store_refresh_token,
    validate_refresh_token, revoke_refresh_token, revoke_all_user_tokens
)

# Pydantic models for resquest/response
from pydantic import BaseModel, EmailStr
from typing import Optional

from datetime import datetime


# Request/Response Models
class UserRegister(BaseModel):
    username: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class MessageResponse(BaseModel):
    message: str

# Router Setup
router = APIRouter(prefix="/auth", tags=["authentication"])
security = HTTPBearer()

@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def register(user_data: UserRegister, db: Session = Depends(get_db)):
    """Register a new user and return tokens"""

    # Check if user already exists
    existing_user = db.query(User).filter(
        (User.username == user_data.username) | (User.email == user_data.email)
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email already registered"
        )
    
    # Create new user
    new_user = User(
        username=user_data.username,
        email=user_data.email
    )
    new_user.set_password(user_data.password) # Uses the method from User model

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Create tokens
    token_data = {"sub": str(new_user.id)}
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    # Store refresh token
    store_refresh_token(str(new_user.id), refresh_token, db)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token
    )

# Login Endpoint
@router.post("/login", response_model=TokenResponse)
def login(user_data: UserLogin, db: Session = Depends(get_db)):
    """Authenticate user and return tokens"""

    # Find user by username
    user = db.query(User).filter(User.username == user_data.username).first()

    if not user or not user.verify_password(user_data.password):
        # Increment failed attempts if user exists
        if user:
            user.increment_failed_attempts()
            db.commit()

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )

    # Check if account is locked
    if user.is_account_locked():
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Account is  temporarily locked due to too many failed login attempts"
        )

    # Reset failed attempts
    user.reset_failed_attempts()
    user.last_login_at = datetime.utcnow()
    db.commit()

    # Create tokens
    token_data = {"sub": str(user.id)}
    access_token = create_access_token(token_data)
    refresh_token = create_refresh_token(token_data)

    # Store refresh token
    store_refresh_token(str(user.id), refresh_token, db)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token
    )

# Refresh Token Endpoint
@router.post("/refresh", response_model=TokenResponse)
def refresh_token(token_request: RefreshTokenRequest, db: Session = Depends(get_db)):
    """Get new access token using refresh token"""

    # Validate refresh token
    user = validate_refresh_token(token_request.refresh_token, db)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token"
        )
    
    # Check if user account is still active
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive"
        )
    
    # Create new access token (refresh token stays the same)
    token_data = {"sub": str(user.id)}
    access_token = create_access_token(token_data)

    return TokenResponse(
        access_token=access_token,
        refresh_token=token_request.refresh_token # Return same refresh token
    )

# Logout Endpoint
@router.post("/logout", response_model=MessageResponse)
def logout(token_request: RefreshTokenRequest, db: Session = Depends(get_db)):
    """Logout from current device (revoke refresh token)"""

    success = revoke_refresh_token(token_request.refresh_token, db)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Refresh token not found"
        )

    return MessageResponse(message="Successfully logged out")

@router.post("/logout-all", response_model=MessageResponse)
def logout_all(credentials: HTTPAuthorizationCredentials = Depends(security), db: Session = Depends(get_db)):
    """Logout from all devices (revoke all refresh tokens)"""

    # Get user from access token
    from app.core.security import get_user_from_token
    user = get_user_from_token(credentials.credentials, db)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid access token"
        )

    # Revoke all tokens for this user
    revoke_all_user_tokens(str(user.id), db)

    return MessageResponse(message="Successfully logged out from all devices")