from pydantic_settings import BaseSettings, SettingsConfigDict
from functools import lru_cache


class Settings(BaseSettings):
    DATABASE_URL: str
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


@lru_cache
def get_config():
    return Settings()
