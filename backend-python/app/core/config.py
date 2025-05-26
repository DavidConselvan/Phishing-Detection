class Settings:
    API_V1_STR: str = "/api"
    PROJECT_NAME: str = "Phishing Detection API"
    BACKEND_CORS_ORIGINS: list = ["http://localhost:5173", "http://127.0.0.1:5173"]

settings = Settings() 