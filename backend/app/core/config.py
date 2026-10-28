from functools import lru_cache
from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    DATABASE_URL: str
    SECRET_KEY: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    CORS_ALLOWED_ORIGINS: str = "http://localhost:3000"
    SCREENSHOT_STORAGE_PATH: str = "./storage/screenshots"
    COMPANY_TIMEZONE: str = "Asia/Kolkata"
    AGENT_HEARTBEAT_TIMEOUT: int = 120
    APP_ENV: str = "production"  # "development" logs reset links instead of emailing
    COOKIE_SECURE: bool = True  # set false only for local http development

    @field_validator("DATABASE_URL")
    @classmethod
    def _normalise_db_url(cls, v: str) -> str:
        # Render/Heroku give postgres:// or postgresql://; SQLAlchemy needs the psycopg driver name.
        for prefix in ("postgres://", "postgresql://"):
            if v.startswith(prefix):
                return "postgresql+psycopg://" + v[len(prefix):]
        return v

    @property
    def cors_origins(self) -> list[str]:
        return [o.strip() for o in self.CORS_ALLOWED_ORIGINS.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    if len(s.SECRET_KEY) < 32:
        raise ValueError("SECRET_KEY must be at least 32 characters")
    return s
