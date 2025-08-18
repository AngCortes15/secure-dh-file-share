# SQLAlchemy Core
from sqlalchemy import create_engine # Creates database connection pool (you started this)
from sqlalchemy.orm import sessionmaker, Session # Factory for creating database sessions and Type hint for database sessions 
from sqlalchemy.pool import StaticPool # Connection pooling strategy (good for development)


# FastAPI dependency injection
from typing import Generator # Type hint for the dependency function

# My projects imports
from app.core.config import Setting
from app.db.models import Base


# Create SQLAlchemy engine
settings = Setting() # Load settings from environment variables
engine = create_engine(settings.database_url)
#   - autocommit=False = Don't automatically save changes (you control when to save)
#   - autoflush=False = Don't automatically send commands (you control when to send)
#   - bind=engine = Use our connection poo

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Dependency function for FastAPI endpoints
def get_db() -> Generator[Session, None, None]:
    """
    Creates a database session for each request.
    Automatically closes the session when done
    """
    db = SessionLocal() # Create a new session
    try:
        yield db # Yield the session to the caller
    finally:
        db.close() # Close the session

# Database initialization function
def init_db() -> None:
    """
    Create all tables in the database.
    This is an alternative to Alembic for simple setups
    """
    Base.metadata.create_all(bind=engine) # Create all tables defined in the Base metadata
    # Note: You probably won't use this since you're using Alembic migrations, but it's a good backup.