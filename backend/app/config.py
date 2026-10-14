from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# backend/app/config.py -> parents[0]=app, [1]=backend, [2]=repo root
PROJECT_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    """Application settings loaded from environment variables / .env.

    A Groq key is optional: without one the L1 agent runs without an LLM and
    escalates every incident. Missing keys are handled at runtime by the
    calling service, never at import time.
    """

    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- application ---
    app_name: str = "AI SOC Simulator"
    app_version: str = "0.1.0"
    environment: str = "development"
    log_level: str = "INFO"
    data_dir: Path = PROJECT_ROOT / "data"

    # --- LLM (L1 analyst agent) ---
    groq_api_key: str | None = None
    llm_model: str = "llama-3.3-70b-versatile"

    # --- RAG (persistent ChromaDB directory) ---
    vector_store_path: Path = PROJECT_ROOT / "data" / "vectorstore"


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()