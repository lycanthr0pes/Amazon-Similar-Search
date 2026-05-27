# pydanticによって配列をBaseModel型にすることで, 変数の型をチェックし, デフォルト値を設定する

from typing import Any
from pydantic import BaseModel, Field


# リストに型指定した変数のデフォルト値を新規作成した空のリストにする
# 返り値自体はFieldオブジェクトなので型をAnyとする
def string_list() -> Any:
    return Field(default_factory=list)


# 商品情報の変数
# 空は空として扱う
class ProductAttributes(BaseModel):
    estimated_product_name_ja: str
    estimated_product_name_en: str | None = None
    category_ja: str | None = None
    category_en: str | None = None
    color_ja: str | None = None
    color_en: str | None = None
    features_ja: list[str] = string_list()
    features_en: list[str] = string_list()
    negative_conditions_ja: list[str] = string_list()
    negative_conditions_en: list[str] = string_list()
    search_queries_ja: list[str] = string_list()
    search_queries_en: list[str] = string_list()
    required_terms_ja: list[str] = string_list()
    required_terms_en: list[str] = string_list()
    preferred_terms_ja: list[str] = string_list()
    preferred_terms_en: list[str] = string_list()
    related_terms_ja: list[str] = string_list()
    related_terms_en: list[str] = string_list()
    price_preference: str | None = None
    min_price_jpy: int | None = None
    max_price_jpy: int | None = None
    target_price_jpy: int | None = None
    expected_price_min_jpy: int | None = None
    expected_price_max_jpy: int | None = None


# Outscraperが返したレスポンスを正規化する変数
class NormalizedAmazonProduct(BaseModel):
    source: str = "amazon"
    asin: str | None = None
    title: str
    brand_or_store: str | None = None
    price_jpy: int | None = None
    list_price_jpy: int | None = None
    currency: str | None = None
    rating: float | None = None
    review_count: int | None = None
    categories: list[str] = string_list()
    image_url: str | None = None
    image_urls: list[str] = string_list()
    product_url: str | None = None
    short_url: str | None = None
    is_prime: bool = False
    availability: str | None = None
    shipping: str | None = None
    source_query: str | None = None
    position: int | None = None
    description: str | None = None


# スコア計算の変数
class ProductScore(BaseModel):
    asin: str | None = None
    title: str
    price_jpy: int | None = None
    rating: float | None = None
    review_count: int | None = None
    image_url: str | None = None
    product_url: str | None = None
    title_similarity: float
    attribute_similarity: float
    price_score: float
    negative_penalty: float
    total_score: float
    matched_terms: list[str] = string_list()
    missing_terms: list[str] = string_list()
    negative_matches: list[str] = string_list()
