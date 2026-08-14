from pathlib import Path

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from src.paths import PROJECT_ROOT


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Bonsai関連
    bonsai_base_url: str = "http://127.0.0.1:8080/v1"
    bonsai_model: str = "Bonsai-8B.gguf"
    bonsai_timeout_seconds: int = Field(default=60, gt=0)
    bonsai_temperature: float = Field(default=0.1, ge=0, le=2)
    bonsai_max_tokens: int = Field(default=1000, gt=0)
    bonsai_prompt_path: Path = PROJECT_ROOT / "src" / "clients" / "bonsai_prompt.md"

    # Outscraper関連
    outscraper_api_key: str = ""
    outscraper_endpoint: str = "https://api.outscraper.cloud/amazon-products"
    outscraper_domain: str = "amazon.co.jp"
    outscraper_language: str = "ja"
    outscraper_postal_code: str = "100-0001"
    outscraper_limit: int = Field(default=100, gt=0)
    usd_to_jpy_rate: int = Field(default=160, gt=0)
    # 結果取得のチェック間隔と上限
    outscraper_poll_interval_seconds: int = Field(default=30, gt=0)
    outscraper_max_polls: int = Field(default=50, gt=0)
    outscraper_request_timeout_seconds: int = Field(default=30, gt=0)
    outscraper_max_attempts: int = Field(default=3, gt=0)
    outscraper_retry_backoff_seconds: float = Field(default=1.0, ge=0)

    # スコアリング関連
    # 商品名類似度倍率
    title_score_weight: float = Field(default=0.45, ge=0, le=1)
    # 属性類似度倍率
    attribute_score_weight: float = Field(default=0.35, ge=0, le=1)
    # 価格スコア倍率
    price_score_weight: float = Field(default=0.20, ge=0, le=1)
    # 必須語の繰り返し回数
    required_term_weight: int = Field(default=4, ge=0)
    # 色語の繰り返し回数
    color_term_weight: int = Field(default=3, ge=0)
    # 特徴語の繰り返し回数
    feature_term_weight: int = Field(default=2, ge=0)
    # 優先語の繰り返し回数
    preferred_term_weight: int = Field(default=2, ge=0)
    # 関連語の繰り返し回数
    related_term_weight: int = Field(default=1, ge=0)

    # UI関連
    app_env: str = "local"
    log_level: str = "INFO"
    search_result_display_limit: int = Field(default=10, gt=0)
    show_debug_info: bool = False

    cache_dir: Path = PROJECT_ROOT / "cache"
    enable_cache: bool = True
    llm_cache_ttl_seconds: int = Field(default=86400, gt=0)
    outscraper_cache_ttl_seconds: int = Field(default=3600, gt=0)

    @field_validator("bonsai_prompt_path", "cache_dir", mode="after")
    @classmethod
    def resolve_project_path(cls, value: Path) -> Path:
        return value if value.is_absolute() else PROJECT_ROOT / value

    @model_validator(mode="after")
    def validate_weights(self) -> "Settings":
        total = self.title_score_weight + self.attribute_score_weight + self.price_score_weight
        if abs(total - 1.0) > 1e-9:
            raise ValueError("title, attribute, and price score weights must add up to 1.0")
        condition_total = (
            self.required_term_weight
            + self.color_term_weight
            + self.feature_term_weight
            + self.preferred_term_weight
            + self.related_term_weight
        )
        if condition_total == 0:
            raise ValueError("at least one condition term weight must be greater than 0")
        return self


settings = Settings()
