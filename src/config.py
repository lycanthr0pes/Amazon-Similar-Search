from pathlib import Path
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Bonsai関連
    bonsai_base_url: str = "http://127.0.0.1:8080/v1"
    bonsai_model: str = "Bonsai-8B.gguf"
    bonsai_timeout_seconds: int = 60
    bonsai_temperature: float = 0.1
    bonsai_max_tokens: int = 1000
    bonsai_prompt_path: Path = Path("src/clients/bonsai_prompt.md")

    # Outscraper関連
    outscraper_api_key: str = ""
    outscraper_endpoint: str = "https://api.outscraper.cloud/amazon-products"
    outscraper_domain: str = "amazon.co.jp"
    outscraper_language: str = "ja"
    outscraper_postal_code: str = "100-0001"
    outscraper_limit: int = 100
    usd_to_jpy_rate: int = 160
    # 結果取得のチェック間隔と上限
    outscraper_poll_interval_seconds: int = 30
    outscraper_max_polls: int = 120
    outscraper_request_timeout_seconds: int = 3600

    # スコアリング関連
    # 商品名類似度倍率
    title_score_weight: float = 0.45
    # 属性類似度倍率
    attribute_score_weight: float = 0.35
    # 価格スコア倍率
    price_score_weight: float = 0.20
    # 必須語の繰り返し回数
    required_term_weight: int = 4
    # 色語の繰り返し回数
    color_term_weight: int = 3
    # 特徴語の繰り返し回数
    feature_term_weight: int = 2
    # 優先語の繰り返し回数
    preferred_term_weight: int = 2
    # 関連語の繰り返し回数
    related_term_weight: int = 1

    # UI関連
    app_env: str = "local"
    log_level: str = "INFO"
    search_result_display_limit: int = 10
    show_debug_info: str = "false"

    class Config:
        env_file = ".env"


settings = Settings()
