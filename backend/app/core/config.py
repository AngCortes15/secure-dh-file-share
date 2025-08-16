from pydantic_settings import BaseSettings
from typing import List
import os

class Setting(BaseSettings):
    # Application
    app_name: str = "Secure File Sharing API"
    app_version: str = "1.0.0"
    app_description: str = "API for secure file sharing with end-to-end encryption."
    app_contact: str = "is726442@iteso.com"
    app_licenses: List[str] = ["MIT"]
    debug: bool = False

    # Database
    database_url: str = "postgresql://postgres:postgres@localhost:5432/secure_files"
    database_echo: bool = False # To see exactly what SQL queries are being generated and executed

    # Security
    jwt_secret_key: str
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7

    # Redis
    redis_url: str = "redis://localhost:6379"

    # CORS (Cross-Origin Resource Sharing)
    cors_origins: List[str] = ["http://localhost:3000"] # My frontend URL

    # File Upload
    max_file_size: int = 100 * 1024 * 1024  # 100 MB in bytes
    upload_directory: str = "/tmp/secure_uploads"

    # Monitoring
    prometheus_metrics: bool = True
    grafana_admin_password: str

    # Environment Detection
    environment: str = "development"

    # Model Configuration
    class Config:
        env_file = ".env"
        case_sensitive = True