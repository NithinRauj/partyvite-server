from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache


class Settings(BaseSettings):
    DATABASE_URL: str
    LOCAL_CLIENT_URL: str
    LOCALHOST_URL: str

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


@lru_cache
def get_config():
    return Settings()


@lru_cache
def get_allowed_origins():
    config = get_config()
    return [
        config.LOCAL_CLIENT_URL,
        config.LOCALHOST_URL
    ]
