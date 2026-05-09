"""
UMEagleEye - AI-Driven Cyber Asset Attack Surface Management (CAASM)
Core configuration module using Pydantic Settings.
"""

from pydantic_settings import BaseSettings
from pydantic import Field
from typing import List


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # ── App ──
    APP_NAME: str = "UMEagleEye"
    APP_ENV: str = "development"
    BACKEND_CORS_ORIGINS: str = "http://localhost:5173,http://localhost:3000"

    # ── Database ──
    DATABASE_URL: str = "postgresql+asyncpg://eagleeye:eagleeye_secret@db:5432/umeagleeye"
    DATABASE_URL_SYNC: str = "postgresql://eagleeye:eagleeye_secret@db:5432/umeagleeye"

    # ── Redis ──
    REDIS_URL: str = "redis://redis:6379/0"

    # ── JWT / Auth ──
    JWT_SECRET_KEY: str = "change-me-to-a-random-secret-key"
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    # ── OpenRouter AI (DeepSeek via OpenRouter) ──
    OPENROUTER_API_KEY: str = ""
    OPENROUTER_MODEL: str = "deepseek/deepseek-chat"

    # ── Telegram Bot ──
    TELEGRAM_BOT_TOKEN: str = ""

    # ── Google Cloud Storage ──
    GCS_BUCKET_NAME: str = "umeagleeye-reports"
    GCS_SERVICE_ACCOUNT_KEY: str = ""

    # ── MyCERT TAXII ──
    MYCERT_TAXII_URL: str = "https://taxii.mycert.org.my/taxii2/"
    MYCERT_USERNAME: str = ""
    MYCERT_PASSWORD: str = ""

    # ── AlienVault OTX & ThreatFox ──
    OTX_API_KEY: str = ""
    OTX_TAXII_URL: str = "https://otx.alienvault.com/taxii/discovery"
    THREATFOX_API_KEY: str = ""

    # ── NVD API ──
    NVD_API_KEY: str = ""

    # ── Scanning ──
    SCAN_DEFAULT_SUBNET: str = "192.168.1.0/24"
    SCAN_RATE_LIMIT: int = 1000
    DISCOVERY_CYCLE_MINUTES: int = 15

    @property
    def cors_origins(self) -> List[str]:
        return [origin.strip() for origin in self.BACKEND_CORS_ORIGINS.split(",")]

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
