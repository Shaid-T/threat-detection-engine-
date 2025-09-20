from pydantic_settings import BaseSettings
from pydantic import Field, validator
from typing import Optional, List
import os
from pathlib import Path

class Settings(BaseSettings):
    """
    Central configuration using Pydantic.
    Reads from environment variables and .env file
    """
    
    # Application Settings
    app_name: str = "Security Detection Engine"
    environment: str = Field("development", env="ENVIRONMENT")
    debug: bool = Field(False, env="DEBUG")
    log_level: str = Field("INFO", env="LOG_LEVEL")
    
    # Performance Settings
    max_workers: int = Field(4, env="MAX_WORKERS")
    batch_size: int = Field(1000, env="BATCH_SIZE")
    queue_size: int = Field(10000, env="QUEUE_SIZE")
    
    database_url: str = Field(
    "postgresql://user:pass@localhost/secdb", env="DATABASE_URL"
    )

    redis_url: str = Field(
        "redis://localhost:6379/0",
        env="REDIS_URL"
    )
    
    # Paths
    data_dir: Path = Field(Path("./data"), env="DATA_DIR")
    log_dir: Path = Field(Path("./logs"), env="LOG_DIR")
    
    @validator("data_dir", "log_dir")
    def create_directories(cls, v):
        v.mkdir(parents=True, exist_ok=True)
        return v
    
    class Config:
        env_file = ".env"
        case_sensitive = False

# Singleton instance
settings = Settings()
