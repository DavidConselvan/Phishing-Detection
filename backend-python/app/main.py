from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.routes import router
from app.core.config import settings

app = FastAPI(
    title=settings.PROJECT_NAME,
    openapi_url=f"{settings.API_V1_STR}/openapi.json"
)

# Set up CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include our API router
app.include_router(router, prefix=settings.API_V1_STR)

# Add a root endpoint for health check
@app.get("/")
async def root():
    return {
        "message": "Welcome to Phishing Detection API",
        "docs_url": "/docs",
        "api_url": settings.API_V1_STR
    } 