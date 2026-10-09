import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    APP_NAME: str = "VulnPilot AI"
    VERSION: str = "1.0.0"
    DEBUG: bool = True
    
    # Storage & DB
    BASE_DIR: str = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    DATABASE_URL: str = "sqlite:///./vulpilot.db"
    UPLOAD_DIR: str = os.path.join(BASE_DIR, "uploads")
    REPORTS_DIR: str = os.path.join(BASE_DIR, "reports_output")
    
    # Security Scanners
    SEMGREP_PATH: str = "semgrep"
    TRIVY_PATH: str = "trivy"
    USE_BUILTIN_FALLBACK: bool = True
    
    # LLM Settings
    DEFAULT_LLM_PROVIDER: str = "gemini" # gemini, openai, local_fallback
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    GEMINI_MODEL: str = "gemini-1.5-flash"
    OPENAI_MODEL: str = "gpt-4o-mini"
    
    class Config:
        env_file = ".env"
        extra = "ignore"

settings = Settings()

# Ensure required runtime folders exist
os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
os.makedirs(settings.REPORTS_DIR, exist_ok=True)
