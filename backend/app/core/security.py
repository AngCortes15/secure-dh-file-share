# JWT handling
from jose import JWTError, jwt
from datetime import datetime, timedelta
import hashlib

# Password hashing
from passlib.context import CryptContext

# Database and models
from sqlalchemy.orm import Session
from app.db.models import User, JWTToken
from app.core.config import Setting

# Type hints
from typing import Optional, Dict, Any


# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
settings = Setting()

# JWT helper functions
def create_access_token(data: Dict[str, Any]) -> str:
    """Create a new access token"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=settings.access_token_expire_minutes)
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)

def create_refresh_token(data: Dict[str, Any]) -> str:
    """Create a new refresh token"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=settings.refresh_token_expire_days)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)

# Token Validation Functions
def verify_token(token: str, token_type: str) -> Optional[Dict[str, Any]]:
    """Verify and decode a JWT token"""
    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        if payload.get("type") != token_type:
            return None
        return payload
    except JWTError:
        return None

def get_user_from_token(token: str, db: Session) -> Optional[User]:
    """Get the user from access token"""
    payload = verify_token(token, "access")
    if payload is None:
        return None
    
    user_id: str = payload.get("sub")
    if user_id is None:
        return None
    return db.query(User).filter(User.id == user_id).first()

# Refresh Token Management
def hash_token(token: str) -> str:
    """Create SHA-256 hash of token for secure storage"""
    return hashlib.sha256(token.encode()).hexdigest()

def store_refresh_token(user_id: str, refresh_token: str, db: Session, device_info: Optional[str] = None) -> None:
    """Store refresh token hash in database"""
    token_hash = hash_token(refresh_token)
    expires_at = datetime.utcnow() + timedelta(days=settings.refresh_token_expire_days)

    jwt_token = JWTToken(
        user_id=user_id,
        token_hash=token_hash,
        expires_at=expires_at,
        device_info=device_info
    )

    db.add(jwt_token)
    db.commit()

# Refresh Token Validation & Cleanup

def validate_refresh_token(refresh_token: str, db: Session) -> Optional[User]:
    """Validate refresh token and return user if valid"""
    payload = verify_token(refresh_token, "refresh")
    if payload is None:
        return None

    user_id = payload.get("sub")
    if user_id is None:
        return None

    # Check if token exists in database and is not revoked
    token_hash = hash_token(refresh_token)
    jwt_token = db.query(JWTToken).filter(
        JWTToken.user_id == user_id,
        JWTToken.token_hash == token_hash,
        JWTToken.is_revoked == False,
        JWTToken.expires_at > datetime.utcnow()
    ).first()

    if jwt_token is None:
        return None

    # Return the user
    return db.query(User).filter(User.id == user_id).first()

def revoke_refresh_token(refresh_token: str, db: Session) -> bool:
    """Revoke a specific refresh token"""
    token_hash = hash_token(refresh_token)
    jwt_token = db.query(JWTToken).filter(JWTToken.token_hash == token_hash).first()

    if jwt_token:
        jwt_token.is_revoked = True
        db.commit()
        return True
    return False

def revoke_all_user_tokens(user_id: str, db: Session) -> None:
    """Revoke all refresh tokens for a user (logout from all devices)"""
    db.query(JWTToken).filter(JWTToken.user_id == user_id).update({"is_revoked": True})
    db.commit()