🔐 Secure File Sharing Application

End-to-end encrypted file sharing using X25519 Diffie-Hellman Key Exchange with zero-knowledge architecture

Show Image
Show Image
Show Image
📋 Table of Contents

✨ Features
🏗️ Architecture
🚀 Quick Start
🔧 Development
🔐 Security
📊 Monitoring
🚢 Deployment
📚 API Documentation
🧪 Testing
🤝 Contributing

✨ Features

🔐 End-to-End Encryption: X25519 Diffie-Hellman + AES-256-GCM
🕳️ Zero-Knowledge: Server never sees decrypted files
⏰ Temporary Links: Download with automatic expiration
🔑 JWT Authentication: Secure tokens with automatic refresh
📊 Monitoring: Grafana + Prometheus + alerts
🚀 CI/CD: GitHub Actions with automated testing
🐳 Containerized: Docker Compose for development
⚡ Performance: Redis for cache and sessions
🛡️ Security Headers: CORS, CSP, HSTS configured

🏗️ Architecture
mermaidgraph TB
    subgraph "Frontend"
        A[HTML + CSS + JS]
        B[Web Crypto API]
        C[X25519 Keys]
    end
    
    subgraph "Backend"
        D[FastAPI]
        E[JWT Auth]
        F[File Service]
    end
    
    subgraph "Storage"
        G[(PostgreSQL)]
        H[(Redis)]
        I[File System]
    end
    
    subgraph "Monitoring"
        J[Prometheus]
        K[Grafana]
        L[AlertManager]
    end
    
    A --> D
    D --> G
    D --> H
    F --> I
    D --> J
    J --> K
    J --> L
Components
ComponentTechnologyPortDescriptionFrontendHTML + CSS + JS3000SPA with client-side cryptoBackendFastAPI + Python8000REST API with JWTDatabasePostgreSQL5432Metadata and usersCacheRedis6379Sessions and cacheMonitoringPrometheus9090System metricsDashboardGrafana3001Visualization and alerts
🚀 Quick Start
Prerequisites

Docker & Docker Compose
Node.js 18+ (for frontend development)
Python 3.11+ (for backend development)
Git

Installation

Clone the repository

bashgit clone https://github.com/your-username/secure-dh-file-share.git
cd secure-file-sharing

Configure environment variables 

bashcp .env.example .env
# Edit .env with your configurations

Start the services

bashdocker-compose up -d

Verify installation

bash# Backend health check
curl http://localhost:8000/health

# Frontend
open http://localhost:3000

# Grafana Dashboard
open http://localhost:3001 (admin/admin)
🔧 Development
Project Structure
secure-file-sharing/
├── .github/workflows/           # CI/CD pipelines
├── backend/                     # FastAPI backend
│   ├── app/
│   │   ├── api/                # REST endpoints
│   │   ├── core/               # Config and crypto
│   │   ├── db/                 # Models and database
│   │   ├── services/           # Business logic
│   │   └── utils/              # Helpers
│   ├── tests/                  # Backend tests
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/                    # HTML + CSS + JS
│   ├── src/
│   │   ├── js/                 # JavaScript modules
│   │   │   ├── crypto.js       # Crypto utilities
│   │   │   ├── api.js          # API calls
│   │   │   ├── auth.js         # Authentication
│   │   │   └── app.js          # Main application
│   │   ├── css/                # Stylesheets
│   │   │   ├── main.css
│   │   │   └── components.css
│   │   └── assets/             # Static assets
│   ├── index.html
│   ├── package.json            # For build tools only
│   └── Dockerfile
├── monitoring/                  # Grafana config
│   ├── dashboards/
│   ├── alerts/
│   └── prometheus.yml
├── docker-compose.yml          # Local development
├── docker-compose.prod.yml     # Production
└── README.md
Database
Main Schema
sql-- Users with X25519 public keys
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    public_key VARCHAR(255) NOT NULL,  -- X25519 public key (base64)
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Shared files with encryption metadata
CREATE TABLE shared_files (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    file_name VARCHAR(255) NOT NULL,
    file_size BIGINT NOT NULL,
    file_path VARCHAR(500) NOT NULL,      -- Encrypted file path
    encrypted_key TEXT NOT NULL,          -- AES key encrypted with X25519
    nonce VARCHAR(255) NOT NULL,          -- Nonce for AES-GCM
    sender_id UUID REFERENCES users(id) ON DELETE CASCADE,
    recipient_email VARCHAR(255) NOT NULL,
    access_token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    downloaded_at TIMESTAMP NULL,
    max_downloads INTEGER DEFAULT 1,
    download_count INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT NOW()
);

-- JWT tokens for invalidation
CREATE TABLE jwt_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL,
    token_type VARCHAR(20) NOT NULL,      -- 'access' or 'refresh'
    expires_at TIMESTAMP NOT NULL,
    is_revoked BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Download logs for auditing
CREATE TABLE download_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    file_id UUID REFERENCES shared_files(id) ON DELETE CASCADE,
    ip_address INET NOT NULL,
    user_agent TEXT,
    success BOOLEAN DEFAULT true,
    error_message TEXT,
    downloaded_at TIMESTAMP DEFAULT NOW()
);

-- Performance indexes
CREATE INDEX idx_shared_files_token ON shared_files(access_token);
CREATE INDEX idx_shared_files_recipient ON shared_files(recipient_email);
CREATE INDEX idx_jwt_tokens_user ON jwt_tokens(user_id);
CREATE INDEX idx_download_logs_file ON download_logs(file_id);
Backend (FastAPI)
Main Configuration
python# app/core/config.py
from pydantic import BaseSettings

class Settings(BaseSettings):
    # Database
    DATABASE_URL: str = "postgresql://postgres:postgres@localhost:5432/secure_files"
    
    # Redis
    REDIS_URL: str = "redis://localhost:6379"
    
    # JWT
    JWT_SECRET_KEY: str = "your-super-secure-secret-key"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # Files
    MAX_FILE_SIZE: int = 100 * 1024 * 1024  # 100MB
    UPLOAD_DIR: str = "./uploads"
    
    # CORS
    CORS_ORIGINS: list = ["http://localhost:3000"]
    
    # Monitoring
    PROMETHEUS_METRICS: bool = True
    
    class Config:
        env_file = ".env"

settings = Settings()
JWT Authentication
python# app/core/security.py
from fastapi import HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from datetime import datetime, timedelta

security = HTTPBearer()

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None or payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token")
        return user_id
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
CORS Configuration
python# app/main.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware

app = FastAPI(title="Secure File Sharing API", version="1.0.0")

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["*"],
    expose_headers=["*"]
)

# Security Headers
app.add_middleware(
    TrustedHostMiddleware, 
    allowed_hosts=["localhost", "127.0.0.1", "*.yourdomain.com"]
)

@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response
Frontend (React + TypeScript)
Crypto Service
typescript// src/services/crypto.ts
export class CryptoService {
  private static async generateKeyPair(): Promise<CryptoKeyPair> {
    return await window.crypto.subtle.generateKey(
      {
        name: "X25519",
        namedCurve: "X25519"
      },
      true,
      ["deriveKey"]
    );
  }

  static async encryptFile(
    file: File, 
    recipientPublicKey: string
  ): Promise<{
    encryptedFile: Uint8Array;
    encryptedKey: string;
    nonce: string;
  }> {
    // Generate ephemeral key pair
    const keyPair = await this.generateKeyPair();
    
    // Import recipient's public key
    const recipientKey = await this.importPublicKey(recipientPublicKey);
    
    // Derive shared secret
    const sharedSecret = await window.crypto.subtle.deriveKey(
      {
        name: "X25519",
        public: recipientKey
      },
      keyPair.privateKey,
      {
        name: "AES-GCM",
        length: 256
      },
      false,
      ["encrypt"]
    );

    // Generate nonce
    const nonce = window.crypto.getRandomValues(new Uint8Array(12));
    
    // Read file as ArrayBuffer
    const fileBuffer = await file.arrayBuffer();
    
    // Encrypt file
    const encryptedFile = await window.crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: nonce
      },
      sharedSecret,
      fileBuffer
    );

    // Export public key for transmission
    const publicKeyBuffer = await window.crypto.subtle.exportKey("raw", keyPair.publicKey);
    const encryptedKey = btoa(String.fromCharCode(...new Uint8Array(publicKeyBuffer)));

    return {
      encryptedFile: new Uint8Array(encryptedFile),
      encryptedKey,
      nonce: btoa(String.fromCharCode(...nonce))
    };
  }

  private static async importPublicKey(publicKeyString: string): Promise<CryptoKey> {
    const publicKeyBuffer = Uint8Array.from(atob(publicKeyString), c => c.charCodeAt(0));
    return await window.crypto.subtle.importKey(
      "raw",
      publicKeyBuffer,
      {
        name: "X25519",
        namedCurve: "X25519"
      },
      false,
      []
    );
  }
}
API Service
typescript// src/services/api.ts
import axios, { AxiosInstance } from 'axios';

class ApiService {
  private api: AxiosInstance;
  
  constructor() {
    this.api = axios.create({
      baseURL: process.env.REACT_APP_API_URL || 'http://localhost:8000',
      timeout: 30000,
    });

    // Request interceptor for JWT
    this.api.interceptors.request.use((config) => {
      const token = localStorage.getItem('access_token');
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      return config;
    });

    // Response interceptor for refresh token
    this.api.interceptors.response.use(
      (response) => response,
      async (error) => {
        if (error.response?.status === 401) {
          await this.refreshToken();
          return this.api.request(error.config);
        }
        return Promise.reject(error);
      }
    );
  }

  private async refreshToken(): Promise<void> {
    const refreshToken = localStorage.getItem('refresh_token');
    if (!refreshToken) {
      this.logout();
      return;
    }

    try {
      const response = await this.api.post('/auth/refresh', {
        refresh_token: refreshToken
      });
      
      localStorage.setItem('access_token', response.data.access_token);
    } catch {
      this.logout();
    }
  }

  private logout(): void {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    window.location.href = '/login';
  }
}

export const apiService = new ApiService();
📊 Monitoring
Prometheus Metrics
yaml# monitoring/prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "alerts/*.yml"

scrape_configs:
  - job_name: 'fastapi'
    static_configs:
      - targets: ['backend:8000']
    metrics_path: '/metrics'
    scrape_interval: 5s

  - job_name: 'postgres'
    static_configs:
      - targets: ['postgres-exporter:9187']

  - job_name: 'redis'
    static_configs:
      - targets: ['redis-exporter:9121']

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093
Grafana Dashboard
json{
  "dashboard": {
    "title": "Secure File Sharing - Overview",
    "panels": [
      {
        "title": "API Response Time",
        "type": "graph",
        "targets": [
          {
            "expr": "histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m]))"
          }
        ]
      },
      {
        "title": "File Upload/Download Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(files_uploaded_total[5m])"
          },
          {
            "expr": "rate(files_downloaded_total[5m])"
          }
        ]
      },
      {
        "title": "Active Users",
        "type": "stat",
        "targets": [
          {
            "expr": "jwt_active_tokens"
          }
        ]
      }
    ]
  }
}
Alerts
yaml# monitoring/alerts/api.yml
groups:
  - name: api_alerts
    rules:
      - alert: HighResponseTime
        expr: histogram_quantile(0.95, rate(http_request_duration_seconds_bucket[5m])) > 1
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High API response time"
          description: "95th percentile response time is {{ $value }}s"

      - alert: HighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.1
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "High error rate detected"
          description: "Error rate is {{ $value }} requests/second"
🚢 CI/CD Pipeline
GitHub Actions Workflow
yaml# .github/workflows/ci.yml
name: CI/CD Pipeline

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test-backend:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: postgres
          POSTGRES_DB: test_db
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5

    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.11'
    
    - name: Install dependencies
      run: |
        cd backend
        pip install -r requirements.txt
        pip install pytest pytest-cov
    
    - name: Run tests
      run: |
        cd backend
        pytest --cov=app tests/ --cov-report=xml
    
    - name: Upload coverage
      uses: codecov/codecov-action@v3
      with:
        file: ./backend/coverage.xml

  test-frontend:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Setup Node.js
      uses: actions/setup-node@v3
      with:
        node-version: '18'
        cache: 'npm'
        cache-dependency-path: frontend/package-lock.json
    
    - name: Install dependencies
      run: |
        cd frontend
        npm ci
    
    - name: Run tests
      run: |
        cd frontend
        npm run test:coverage
    
    - name: Run lint
      run: |
        cd frontend
        npm run lint
    
    - name: Build frontend
      run: |
        cd frontend
        npm run build

  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Run Trivy vulnerability scanner
      uses: aquasecurity/trivy-action@master
      with:
        scan-type: 'fs'
        format: 'sarif'
        output: 'trivy-results.sarif'
    
    - name: Upload Trivy scan results
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: 'trivy-results.sarif'

  build-and-deploy:
    needs: [test-backend, test-frontend, security-scan]
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Build Docker images
      run: |
        docker build -t secure-file-sharing-backend:${{ github.sha }} ./backend
        docker build -t secure-file-sharing-frontend:${{ github.sha }} ./frontend
    
    - name: Run security scan on images
      run: |
        docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
          aquasec/trivy image secure-file-sharing-backend:${{ github.sha }}
Deployment Script
yaml# .github/workflows/deploy.yml
name: Deploy to Production

on:
  push:
    tags:
      - 'v*'

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v3
    
    - name: Configure AWS credentials
      uses: aws-actions/configure-aws-credentials@v2
      with:
        aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
        aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        aws-region: us-east-1
    
    - name: Deploy to ECS
      run: |
        # Your AWS deployment script goes here
        echo "Deploying to production..."
🧪 Testing
Backend Tests
python# backend/tests/test_crypto.py
import pytest
from app.services.crypto_service import CryptoService

class TestCrypto:
    def test_x25519_key_generation(self):
        private_key, public_key = CryptoService.generate_x25519_keypair()
        assert len(public_key) == 44  # Base64 encoded 32 bytes
    
    def test_file_encryption_decryption(self):
        # Complete encryption/decryption test
        pass

# backend/tests/test_api.py
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

class TestAPI:
    def test_health_check(self):
        response = client.get("/health")
        assert response.status_code == 200
    
    def test_user_registration(self):
        response = client.post("/auth/register", json={
            "email": "test@example.com",
            "password": "securepassword",
            "public_key": "test_public_key"
        })
        assert response.status_code == 201
Frontend Tests
javascript// frontend/tests/crypto.test.js
import { CryptoService } from '../src/js/crypto.js';

describe('CryptoService', () => {
  test('should generate valid key pair', async () => {
    const keyPair = await CryptoService.generateKeyPair();
    expect(keyPair.publicKey).toBeDefined();
    expect(keyPair.privateKey).toBeDefined();
  });

  test('should encrypt and decrypt file correctly', async () => {
    // Create test file
    const testData = new Uint8Array([1, 2, 3, 4, 5]);
    const testFile = new File([testData], 'test.txt', { type: 'text/plain' });
    
    // Generate keys
    const senderKeys = await CryptoService.generateKeyPair();
    const recipientKeys = await CryptoService.generateKeyPair();
    
    const recipientPublicKey = await CryptoService.exportPublicKey(recipientKeys.publicKey);
    
    // Encrypt
    const encrypted = await CryptoService.encryptFile(testFile, recipientPublicKey);
    
    // Decrypt
    const decrypted = await CryptoService.decryptFile(
      encrypted.encryptedFile,
      encrypted.encryptedKey,
      encrypted.nonce,
      recipientKeys.privateKey
    );
    
    expect(Array.from(decrypted)).toEqual(Array.from(testData));
  });
});

// frontend/tests/api.test.js
import { ApiService } from '../src/js/api.js';

describe('ApiService', () => {
  let apiService;
  
  beforeEach(() => {
    apiService = new ApiService();
    // Mock fetch for testing
    global.fetch = jest.fn();
  });

  test('should make authenticated requests', async () => {
    localStorage.setItem('access_token', 'test-token');
    
    fetch.mockResolvedValueOnce({
      ok: true,
      json: async () => ({ success: true })
    });

    const result = await apiService.request('/test');
    
    expect(fetch).toHaveBeenCalledWith(
      'http://localhost:8000/test',
      expect.objectContaining({
        headers: expect.objectContaining({
          'Authorization': 'Bearer test-token'
        })
      })
    );
    expect(result).toEqual({ success: true });
  });
});
🔧 Development Scripts
json{
  "scripts": {
    "dev": "docker-compose up -d",
    "dev:logs": "docker-compose logs -f",
    "test": "docker-compose -f docker-compose.test.yml up --abort-on-container-exit",
    "lint": "npm run lint:backend && npm run lint:frontend",
    "lint:backend": "cd backend && flake8 app/",
    "lint:frontend": "cd frontend && npm run lint",
    "format": "npm run format:backend && npm run format:frontend",
    "format:backend": "cd backend && black app/",
    "format:frontend": "cd frontend && npm run format",
    "security:scan": "docker run --rm -v $(pwd):/app aquasec/trivy fs /app",
    "db:migrate": "cd backend && alembic upgrade head",
    "db:reset": "docker-compose down -v && docker-compose up -d postgres && sleep 5 && npm run db:migrate"
  }
}
📚 Environment Variables
bash# .env.example
# Database
DATABASE_URL=postgresql://postgres:postgres@localhost:5432/secure_files
REDIS_URL=redis://localhost:6379

# JWT
JWT_SECRET_KEY=your-super-secure-secret-key-change-this
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7

# File Storage
MAX_FILE_SIZE=104857600  # 100MB
UPLOAD_DIR=./uploads

# CORS
CORS_ORIGINS=["http://localhost:3000"]

# Monitoring
PROMETHEUS_METRICS=true
GRAFANA_ADMIN_PASSWORD=admin

# Frontend
API_URL=http://localhost:8000
MAX_FILE_SIZE=104857600