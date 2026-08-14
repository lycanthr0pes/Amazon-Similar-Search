from __future__ import annotations

import json
import os
from collections.abc import Sequence
from typing import Any
from urllib.parse import urlencode

import requests
from dotenv import load_dotenv
from pydantic import BaseModel, Field, ValidationError


def string_list() -> Any:
    return Field(default_factory=list)


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
    image_prompt: str | None = None
    price_preference: str | None = None
    max_price_jpy: int | None = None


OUTSCRAPER_AMAZON_PRODUCTS_ENDPOINT = "https://api.outscraper.cloud/amazon-products"
OUTSCRAPER_AMAZON_DOMAIN = "amazon.co.jp"
OUTSCRAPER_AMAZON_LANGUAGE = "ja"
OUTSCRAPER_AMAZON_LIMIT = 24
BONSAI_DEFAULT_BASE_URL = "http://127.0.0.1:8080/v1"
BONSAI_DEFAULT_MODEL = "Bonsai-8B.gguf"


SYSTEM_PROMPT = """\
あなたはEC商品検索用の商品属性抽出器です。
ユーザーの自然言語入力から、Amazon検索に使う商品属性を抽出してください。

制約:
- 出力はJSONのみ
- Markdownや説明文は禁止
- 不明な項目は null または [] を使う
- *_ja フィールドは日本語で出力する
- *_en フィールドは自然な英語で出力する
- search_queries_ja は日本語で1から3件
- search_queries_en はOutscraper検索に使える英語で1から3件
- image_prompt は英語の商品写真プロンプト
- price_preference は cheap / premium / none のいずれか
- category_ja / category_en はAmazonの商品カテゴリを返す。音楽ジャンルや用途名ではない。
- search_queries_ja / search_queries_en は商品カテゴリを含む検索クエリにする。単独の特徴語だけにしない。
- max_price_jpy は文字列ではなく数値または null にする。
- category_ja / category_en は具体的な商品種別を表す名詞句にする。
- category_ja / category_en は推定商品名または特徴から直接判断できる場合だけ出力する。
- category_ja / category_en に自信がない場合は null にする。
- required_terms_ja / required_terms_en は、商品の種類など必須に近いランキング語を最大5件にする。
- preferred_terms_ja / preferred_terms_en は、色、形状、機能など重視したいランキング語を最大10件にする。
- related_terms_ja / related_terms_en は、略語や言い換えなど補助的なランキング語を最大10件にする。
- required_terms / preferred_terms / related_terms には negative_conditions に該当する語を含めない。

悪い例:
{
  "category_ja": "商品",
  "category_en": "product",
  "search_queries_ja": ["黒い商品", "小さい", "安い"],
  "search_queries_en": ["black product", "small", "cheap"]
}

良い例:
{
  "category_ja": "入力内容に合う具体的な商品カテゴリ",
  "category_en": "specific product category matching the input",
  "search_queries_ja": ["商品名 色 特徴 具体的な商品カテゴリ"],
  "search_queries_en": ["product name color feature specific product category"]
}

必ず以下のJSON型に従うこと:
{
  "estimated_product_name_ja": "string",
  "estimated_product_name_en": "string or null",
  "category_ja": "string or null",
  "category_en": "string or null",
  "color_ja": "string or null",
  "color_en": "string or null",
  "features_ja": ["string"],
  "features_en": ["string"],
  "negative_conditions_ja": ["string"],
  "negative_conditions_en": ["string"],
  "search_queries_ja": ["string"],
  "search_queries_en": ["string"],
  "required_terms_ja": ["string"],
  "required_terms_en": ["string"],
  "preferred_terms_ja": ["string"],
  "preferred_terms_en": ["string"],
  "related_terms_ja": ["string"],
  "related_terms_en": ["string"],
  "image_prompt": "string or null",
  "price_preference": "cheap | premium | none",
  "max_price_jpy": number or null
}

注意:
- features_ja, features_en, negative_conditions_ja, negative_conditions_en, required_terms_ja, required_terms_en, preferred_terms_ja, preferred_terms_en, related_terms_ja, related_terms_en は、要素が1つでも必ず配列にする
- max_price_jpy は文字列ではなく数値にする
"""


def call_bonsai(user_input: str) -> str:
    load_dotenv()
    base_url = os.getenv("BONSAI_BASE_URL", BONSAI_DEFAULT_BASE_URL)
    response = requests.post(
        f"{base_url}/chat/completions",
        json=build_bonsai_payload(user_input),
        timeout=60,
    )
    response.raise_for_status()
    data = response.json()
    return data["choices"][0]["message"]["content"]


def build_bonsai_payload(user_input: str) -> dict[str, Any]:
    return {
        "model": os.getenv("BONSAI_MODEL", BONSAI_DEFAULT_MODEL),
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_input},
        ],
        "temperature": 0.1,
        "max_tokens": 1000,
    }


LIST_FIELDS = (
    "features_ja",
    "features_en",
    "negative_conditions_ja",
    "negative_conditions_en",
    "search_queries_ja",
    "search_queries_en",
    "required_terms_ja",
    "required_terms_en",
    "preferred_terms_ja",
    "preferred_terms_en",
    "related_terms_ja",
    "related_terms_en",
)


def normalize_bonsai_json(data: dict[str, Any]) -> dict[str, Any]:
    data = data.copy()
    for field in LIST_FIELDS:
        value = data.get(field)
        if value is None:
            data[field] = []
        elif isinstance(value, str):
            data[field] = [value]

    max_price_jpy = data.get("max_price_jpy")
    if isinstance(max_price_jpy, str):
        stripped_price = max_price_jpy.strip()
        data["max_price_jpy"] = int(stripped_price) if stripped_price.isdecimal() else None

    return data


def has_japanese_category_evidence(category: str, evidence_parts: Sequence[str | None]) -> bool:
    evidence = " ".join(part for part in evidence_parts if part)
    normalized_category = category.strip()
    return bool(normalized_category and normalized_category in evidence)


def english_words(text: str) -> set[str]:
    return {word for word in text.lower().replace("-", " ").split() if len(word) > 2}


def has_english_category_evidence(category: str, evidence_parts: Sequence[str | None]) -> bool:
    category_words = english_words(category)
    evidence_words = english_words(" ".join(part for part in evidence_parts if part))
    return bool(category_words and category_words <= evidence_words)


def clean_categories(attrs: ProductAttributes) -> None:
    japanese_evidence = [attrs.estimated_product_name_ja, *attrs.features_ja]
    english_evidence = [attrs.estimated_product_name_en, *attrs.features_en]

    if attrs.category_ja and not has_japanese_category_evidence(
        attrs.category_ja, japanese_evidence
    ):
        attrs.category_ja = None

    if attrs.category_en and not has_english_category_evidence(attrs.category_en, english_evidence):
        attrs.category_en = None


def unique_non_empty(values: list[str | None]) -> list[str]:
    unique_values, seen = [], set()
    for value in values:
        if not value:
            continue
        normalized = value.strip()
        if not normalized or normalized.lower() in seen:
            continue
        unique_values.append(normalized)
        seen.add(normalized.lower())
    return unique_values


def contains_japanese(text: str) -> bool:
    return any("\u3040" <= c <= "\u30ff" or "\u4e00" <= c <= "\u9fff" for c in text)


def japanese_query_part(value: str | None) -> str | None:
    return value if value and contains_japanese(value) else None


def improve_search_queries(attrs: ProductAttributes) -> None:
    japanese_parts = unique_non_empty(
        [
            japanese_query_part(attrs.estimated_product_name_ja),
            japanese_query_part(attrs.color_ja),
            *(japanese_query_part(feature) for feature in attrs.features_ja),
            japanese_query_part(attrs.category_ja),
        ]
    )
    if japanese_parts:
        attrs.search_queries_ja = [" ".join(japanese_parts)]

    english_parts = unique_non_empty(
        [attrs.estimated_product_name_en, attrs.color_en, *attrs.features_en, attrs.category_en]
    )
    if english_parts:
        attrs.search_queries_en = [" ".join(english_parts).lower()]


def select_outscraper_query(attrs: ProductAttributes) -> str:
    if attrs.search_queries_ja:
        return attrs.search_queries_ja[0]
    if attrs.search_queries_en:
        return attrs.search_queries_en[0]
    return attrs.estimated_product_name_ja


def build_outscraper_amazon_params(
    attrs: ProductAttributes,
    *,
    limit: int = OUTSCRAPER_AMAZON_LIMIT,
) -> dict[str, str | int]:
    return {
        "query": select_outscraper_query(attrs),
        "domain": OUTSCRAPER_AMAZON_DOMAIN,
        "language": OUTSCRAPER_AMAZON_LANGUAGE,
        "limit": limit,
        "async": "false",
    }


def build_outscraper_amazon_url(
    attrs: ProductAttributes,
    *,
    endpoint: str = OUTSCRAPER_AMAZON_PRODUCTS_ENDPOINT,
    limit: int = OUTSCRAPER_AMAZON_LIMIT,
) -> str:
    return f"{endpoint}?{urlencode(build_outscraper_amazon_params(attrs, limit=limit))}"


def parse_attributes(raw_text: str, fallback_query: str) -> ProductAttributes:
    try:
        data = json.loads(raw_text)
        data = normalize_bonsai_json(data)
        attrs = ProductAttributes.model_validate(data)
    except (json.JSONDecodeError, ValidationError) as exc:
        raise ValueError(f"Bonsai response is not valid product JSON: {raw_text}") from exc

    if not attrs.search_queries_ja:
        attrs.search_queries_ja = [fallback_query]

    if not attrs.search_queries_en and attrs.estimated_product_name_en:
        attrs.search_queries_en = [attrs.estimated_product_name_en]

    clean_categories(attrs)
    improve_search_queries(attrs)

    return attrs


def extract_product_attributes(user_input: str) -> ProductAttributes:
    raw_text = call_bonsai(user_input)
    return parse_attributes(raw_text, fallback_query=user_input)


if __name__ == "__main__":
    sample = "黒いワイヤレスイヤホン。ノイズキャンセリング付きで、ケースは丸くて小さい。できれば安いもの。"
    attributes = extract_product_attributes(sample)
    print(json.dumps(attributes.model_dump(), ensure_ascii=False, indent=2))
    print(f"Outscraper search query: {select_outscraper_query(attributes)}")
