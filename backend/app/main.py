from app.api.endpoints.auth import router as auth_router

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Import settings for CORS
from app.core.config import Setting

# Create settings instance
settings = Setting()

# Create FastAPI app
app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description=settings.app_description
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Include routers
app.include_router(auth_router)

# Health check endpoint
@app.get("/health")
def health_check():
    return {"status": "healthy", "service": "secure-file-sharing-api"}

# Root endpoint
@app.get("/")
def root():
    return {"message": "Secure File Sharing API", "version": settings.app_version}
