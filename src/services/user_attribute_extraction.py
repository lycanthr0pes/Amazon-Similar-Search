import json
import math
import re
from collections.abc import Sequence
from typing import Any

from pydantic import ValidationError

from src.schemas import ProductAttributes

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
PRICE_FIELDS = (
    "min_price_jpy",
    "max_price_jpy",
    "target_price_jpy",
    "expected_price_min_jpy",
    "expected_price_max_jpy",
)
PRICE_STRING_PATTERN = re.compile(
    r"^\s*(?:JPY\s*)?[¥￥]?\s*([+-]?\d[\d,]*(?:\.\d+)?)\s*(?:円|JPY)?\s*$",
    re.IGNORECASE,
)
BONSAI_RESPONSE_ERROR = "Bonsai response is not valid product JSON."


def normalize_price_value(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value if value > 0 else None
    if isinstance(value, float):
        return int(value) if math.isfinite(value) and value.is_integer() and value > 0 else None
    if not isinstance(value, str):
        return None

    match = PRICE_STRING_PATTERN.fullmatch(value)
    if not match:
        return None
    try:
        number = float(match.group(1).replace(",", ""))
    except ValueError:
        return None
    if not math.isfinite(number) or not number.is_integer() or number <= 0:
        return None
    return int(number)


# bonsaiが返したJSONを正規化して型エラーを防ぐ
def normalize_bonsai_json(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ValueError(BONSAI_RESPONSE_ERROR)
    data = data.copy()

    # リストとして返るべき部分を正規化する
    for field in LIST_FIELDS:
        value = data.get(field)
        # 存在しなければ空リスト
        if value is None:
            data[field] = []
        # 存在するが文字列ならリスト化
        elif isinstance(value, str):
            data[field] = [value]

    # 価格設定を正の整数に正規化し, 通貨装飾や桁区切りにも対応する
    for field in PRICE_FIELDS:
        if field in data:
            data[field] = normalize_price_value(data.get(field))

    return data


# 価格範囲の上下限が逆転していた場合は小さい方を下限にする
def normalize_price_ranges(attrs: ProductAttributes) -> None:
    for minimum_field, maximum_field in (
        ("min_price_jpy", "max_price_jpy"),
        ("expected_price_min_jpy", "expected_price_max_jpy"),
    ):
        minimum = getattr(attrs, minimum_field)
        maximum = getattr(attrs, maximum_field)
        if minimum is not None and maximum is not None and minimum > maximum:
            setattr(attrs, minimum_field, maximum)
            setattr(attrs, maximum_field, minimum)


# BonsaiがMarkdownコードフェンス付きで返した場合もJSON部分だけ取り出す
def extract_json_text(raw_text: str) -> str:
    normalized = raw_text.strip()
    if normalized.startswith("```"):
        lines = normalized.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        normalized = "\n".join(lines).strip()

    json_start = normalized.find("{")
    json_end = normalized.rfind("}")
    if json_start == -1 or json_end == -1 or json_end < json_start:
        return normalized
    return normalized[json_start : json_end + 1]


# カテゴリ名の精度検査のために, bonsaiで推定した日本語の商品名と各機能ワードを文字列として結合
# カテゴリ名が文字列の中に含まれていればTrue
# Sequence[str | None] : str or Noneの型
def japanese_category_evidence(category: str, evidence_parts: Sequence[str | None]) -> bool:
    evidence = " ".join(part for part in evidence_parts if part)
    normalized_category = category.strip()
    return bool(normalized_category and normalized_category in evidence)


# カテゴリ名の精度検査の精度をより高めるため, 英語を単語分割する
# if len(word) > 2 : 2文字以下の短い単語を除外する
def english_words(text: str) -> set[str]:
    return {word for word in text.lower().replace("-", " ").split() if len(word) > 2}


# カテゴリ名の精度検査のために, bonsaiで推定した英語の商品名と各機能ワードを文字列として結合
# カテゴリ名が文字列の中に含まれていればTrue
def english_category_evidence(category: str, evidence_parts: Sequence[str | None]) -> bool:
    category_words = english_words(category)
    evidence_words = english_words(" ".join(part for part in evidence_parts if part))
    return bool(category_words and category_words <= evidence_words)


# 商品名+各機能ワードとカテゴリ名を照らし合わせて, 間違ったカテゴリ名を排除する
def categories_check(attrs: ProductAttributes) -> None:
    japanese_evidence = [attrs.estimated_product_name_ja, *attrs.features_ja]
    english_evidence = [attrs.estimated_product_name_en, *attrs.features_en]

    # カテゴリ名が含まれていなければNone
    if attrs.category_ja and not japanese_category_evidence(attrs.category_ja, japanese_evidence):
        attrs.category_ja = None

    if attrs.category_en and not english_category_evidence(attrs.category_en, english_evidence):
        attrs.category_en = None


# 最終的な検索ワードを作る前に順序を保ったまま重複と空の値を除外する
def clean_dupe_empty(values: list[str | None]) -> list[str]:
    # 残すものリスト, 残さないものリスト
    unique_values, seen = [], set()
    for value in values:
        # 空なら残さない
        if not value:
            continue
        normalized = value.strip()
        # 重複なら残さない
        if not normalized or normalized.lower() in seen:
            continue
        unique_values.append(normalized)
        seen.add(normalized.lower())
    return unique_values


# 文字列の中に日本語が含まれているか判定する
# \u3040 - \u30ff  → ひらがな・カタカナ(unicode)
# \u4e00 - \u9fff  → 漢字
def check_contains_japanese(text: str) -> bool:
    return any("\u3040" <= c <= "\u30ff" or "\u4e00" <= c <= "\u9fff" for c in text)


# 日本語のみ検索クエリに入れる
def japanese_query_part(value: str | None) -> str | None:
    return value if value and check_contains_japanese(value) else None


# 最終的な検索ワードを作る
def improve_search_queries(attrs: ProductAttributes) -> None:
    japanese_parts = clean_dupe_empty(
        [
            japanese_query_part(attrs.estimated_product_name_ja),
            japanese_query_part(attrs.color_ja),
            *(japanese_query_part(feature) for feature in attrs.features_ja),
            japanese_query_part(attrs.category_ja),
        ]
    )
    # 検索ワードとして結合
    if japanese_parts:
        attrs.search_queries_ja = [" ".join(japanese_parts)]

    # 類似度計算用に英語の検索ワードも作る
    english_parts = clean_dupe_empty(
        [attrs.estimated_product_name_en, attrs.color_en, *attrs.features_en, attrs.category_en]
    )
    if english_parts:
        attrs.search_queries_en = [" ".join(english_parts).lower()]


# bonsaiが返したJSONを正規化して, 最終的な検索クエリをProductAttributes型のJSONとして返す
def parse_attributes(raw_text: str, fallback_query: str) -> ProductAttributes:
    try:
        data = json.loads(extract_json_text(raw_text))
        data = normalize_bonsai_json(data)
        attrs = ProductAttributes.model_validate(data)
    except (json.JSONDecodeError, OverflowError, TypeError, ValidationError, ValueError):
        raise ValueError(BONSAI_RESPONSE_ERROR) from None

    normalize_price_ranges(attrs)

    # bonsaiが返したJSONに検索用ワードが含まれていなければ自然言語をそのまま使う
    if not attrs.search_queries_ja:
        attrs.search_queries_ja = [fallback_query]

    # 英語の検索用ワードはないが推定した商品名があるならそれを使う
    if not attrs.search_queries_en and attrs.estimated_product_name_en:
        attrs.search_queries_en = [attrs.estimated_product_name_en]

    # 最終的な検索ワードを作る
    categories_check(attrs)
    improve_search_queries(attrs)

    return attrs


# bonsaiが返した商品属性JSONを正規化して最終的な検索クエリをProductAttributes型で返す
def extract_product_attributes(raw_text: str, user_input: str) -> ProductAttributes:
    return parse_attributes(raw_text, fallback_query=user_input)
