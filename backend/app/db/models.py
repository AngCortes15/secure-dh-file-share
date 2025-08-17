# SQLAlchemy Core
from sqlalchemy import Column, String, Boolean, DateTime, Text, LargeBinary, Integer
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base

# UUID Generation
import uuid
from sqlalchemy import text # For UUID default generation

# DateTime Handling
from datetime import datetime, timedelta
from sqlalchemy.sql import func # For automatic timestamp generation

# Password Handling
from passlib.context import CryptContext

# Package for SharedFile model
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship



Base = declarative_base() # Base class for SQLAlchemy models

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto") # Password hashing context

class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4) # Prevents user enumeration attacks
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(128), nullable=False) # bcrypt output is ~60 chars, 128 for safety
    # Account Security
    email_verified = Column(Boolean, default=False, nullable=False) # Email verification status
    is_active = Column(Boolean, default=True, nullable=False) # Soft delete
    # Cryptographic
    x25519_public_key = Column(LargeBinary, nullable=True) # Set after key generation
    # Audit trail timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False) # Track any profile changes (security monitoring)
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    # Security monitoring
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    account_locked_until = Column(DateTime(timezone=True), nullable=True)

    # Relationships
    uploaded_files = relationship("SharedFile", back_populates="uploader")
    jwt_tokens = relationship("JWTToken", back_populates="user")

    """
    Utility Methods

    Utility methods to the User model. These methods make
    working with users much easier and more secure.
    """
    # Utility Methods
    def set_password(self, password: str) -> None:
        """Hash and set the user's password"""
        self.password_hash = pwd_context.hash(password)

    def verify_password(self, password: str) -> bool:
        """Verify a password against the stored hash"""
        return pwd_context.verify(password, self.password_hash)

    def is_account_locked(self) -> bool:
        """Check if account is currently locked"""
        if self.account_locked_until is None:
            return False
        return datetime.utcnow() < self.account_locked_until

    def increment_failed_attempts(self) -> None:
        """Increment failed login attempts and lock if needed"""
        self.failed_login_attempts += 1
        if self.failed_login_attempts >= 5:  # Lock after 5 failed attempts
            self.account_locked_until = datetime.utcnow() + timedelta(minutes=30)

    def reset_failed_attempts(self) -> None:
        """Reset failed attempts after successful login"""
        self.failed_login_attempts = 0
        self.account_locked_until = None


class SharedFile(Base): # Represents a FILE shared between users
    __tablename__ = "shared_files"

    # Primary identification
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # Ownership and sharing
    uploaded_by = Column(UUID(as_uuid=True), ForeignKey('users.id'), nullable=False) # This creates a foreign key that references the users table's id column.
    # File metadata
    original_filename = Column(String(255), nullable=False)
    file_size = Column(Integer, nullable=False) # In bytes
    mime_type = Column(String(100), nullable=False)
    # Storage location
    server_file_path = Column(String(512), nullable=False) # Where encrypted file is stored
    # Security metadata
    file_hash = Column(String(64), nullable=False)  # SHA-256 for integrity
    encryption_algorithm = Column(String(50), default="AES-256-GCM", nullable=False)
    # File lifecycle
    expires_at = Column(DateTime(timezone=True), nullable=True)  # Auto-delete time
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    
    # Relationships
    uploader = relationship("User", back_populates="uploaded_files")
    file_shares = relationship("FileShare", back_populates="shared_file", cascade="all, delete-orphan")

class FileShare(Base): # Represents a SHARING INSTANCE of a file, who can access it
    __tablename__ = "file_shares"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    shared_file_id = Column(UUID(as_uuid=True), ForeignKey("shared_files.id"), nullable=False)
    recipient_user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    # Zero-Knowledge Security
    encrypted_file_key = Column(LargeBinary, nullable=False) # This is WHERE we store the AES encryption key
    # Access Control
    access_permissions = Column(String(50), default="read", nullable=False)  # e.g., "read", "write"
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)  # Individual share expiration
    # Security auditing
    access_count = Column(Integer, default=0, nullable=False)  # How many times this share has been accessed
    last_accessed_at = Column(DateTime(timezone=True), nullable=True) 

    # Relationships
    shared_file = relationship("SharedFile", back_populates="file_shares")

"""
Next we are going to create the JWTToken model.
Why We Need JWTToken Model:
  The Problem: Refresh tokens need to be tracked server-side for security:
  - Detect token reuse attacks
  - Allow users to revoke specific devices/sessions
  - Prevent stolen tokens from being used indefinitely
  What This Model Tracks:
  Think of it as a "logged-in device registry" - each row represents one device/browser
  that's logged in.
"""
class JWTToken(Base):
    __tablename__ = "jwt_tokens"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    #ForeigKeys
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)

    token_hash = Column(String(64), nullable=False) # storing SHA-256 hash of the actual refresh token
    expires_at = Column(DateTime(timezone=True), nullable=False) # When this refresh token expires
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False) # When token was issued
    is_revoked = Column(Boolean, default=False, nullable=False) # allows manual token revocation
    device_info = Column(String(255), nullable=True) # optional device identification

    # Relationships
    user = relationship("User", back_populates="jwt_tokens")

"""
Next: DownloadLog Model

  This is a model for security auditing and compliance.

  Purpose of DownloadLog:

  Why we need it:
  - Legal compliance (who accessed what, when)
  - Security monitoring (detect suspicious download patterns)
  - Audit trails for investigations

  What it tracks:
  Every time someone downloads a file, we log it.
"""

class DownloadLog(Base):
    __tablename__ = "download_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    #ForeignKeys
    shared_file_id = Column(UUID(as_uuid=True), ForeignKey("shared_files.id"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)

    downloaded_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False) # When the download occurred
    ip_address = Column(String(45), nullable=True) # Optional, for security monitoring
    user_agent = Column(String(512), nullable=True) # Optional, for security monitoring
    success = Column(Boolean, default=False, nullable=False) # Whether the download was successful

    #Relationships
    shared_file = relationship("SharedFile")
    user = relationship("User")


