from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache


class Settings(BaseSettings):
    DATABASE_URL: str
    LOCALHOST_URL: str
    JWT_SECRET_KEY: str

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


@lru_cache
def get_config():
    return Settings()


@lru_cache
def get_allowed_origins():
    config = get_config()
    return [
        config.LOCALHOST_URL,
    ]
