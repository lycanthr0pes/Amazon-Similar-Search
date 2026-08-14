from __future__ import annotations

import argparse
import json
import math
import re
from pathlib import Path
from typing import Any, Sequence

from pydantic import BaseModel, Field
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from sudachipy import dictionary, tokenizer


DEFAULT_PRODUCTS_PATH = Path("cache/outscraper/amazon_products_normalized_dummy.json")
DEFAULT_ATTRIBUTES_PATH = Path("cache/product_attributes/product_attributes_dummy.json")
DEFAULT_TITLE_WEIGHT = 0.45
DEFAULT_ATTRIBUTE_WEIGHT = 0.35
DEFAULT_PRICE_WEIGHT = 0.20
REQUIRED_TERM_WEIGHT = 3
PREFERRED_TERM_WEIGHT = 2
RELATED_TERM_WEIGHT = 1
SUDACHI_TOKENIZER = dictionary.Dictionary().create()
SUDACHI_MODE = tokenizer.Tokenizer.SplitMode.C
CONTENT_PARTS_OF_SPEECH = {"名詞", "動詞", "形容詞", "形状詞"}
JAPANESE_CHARACTER_PATTERN = re.compile(r"[\u3040-\u30ff\u4e00-\u9fff]")
ENGLISH_TOKEN_PATTERN = re.compile(r"[a-z0-9]+")


def string_list() -> Any:
    return Field(default_factory=list)


class SearchAttributes(BaseModel):
    estimated_product_name_ja: str | None = None
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
    max_price_jpy: int | None = None


class ProductScore(BaseModel):
    asin: str | None = None
    title: str
    price_jpy: int | None = None
    rating: float | None = None
    review_count: int | None = None
    product_url: str | None = None
    title_similarity: float
    attribute_similarity: float
    price_score: float
    negative_penalty: float
    total_score: float
    matched_terms: list[str] = string_list()
    missing_terms: list[str] = string_list()
    negative_matches: list[str] = string_list()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def normalize_text(text: str) -> str:
    return text.casefold()


def normalized_morpheme_text(morpheme: Any) -> str:
    normalized = morpheme.normalized_form()
    if normalized == "*":
        normalized = morpheme.surface()
    return normalize_text(normalized).strip()


def is_content_japanese_token(token: str, morpheme: Any) -> bool:
    return (
        bool(token)
        and morpheme.part_of_speech()[0] in CONTENT_PARTS_OF_SPEECH
        and bool(JAPANESE_CHARACTER_PATTERN.search(token))
    )


def split_japanese_words(text: str) -> list[str]:
    japanese_tokens = []
    for morpheme in SUDACHI_TOKENIZER.tokenize(text, SUDACHI_MODE):
        token = normalized_morpheme_text(morpheme)
        if is_content_japanese_token(token, morpheme):
            japanese_tokens.append(token)
    return japanese_tokens


def split_words(text: str, *, dedupe: bool = True) -> list[str]:
    normalized = normalize_text(text)
    english_tokens = ENGLISH_TOKEN_PATTERN.findall(normalized)
    japanese_tokens = split_japanese_words(normalized)
    tokens = [*english_tokens, *japanese_tokens]

    if dedupe:
        return unique_non_empty(tokens)
    return [token for token in tokens if token]


def term_matches_text(term: str, text: str) -> bool:
    normalized_term = normalize_text(term).strip()
    normalized_text = normalize_text(text)
    if not normalized_term:
        return False
    if normalized_term in normalized_text:
        return True

    term_words = split_words(normalized_term)
    if not term_words:
        return False
    text_words = set(split_words(normalized_text))
    return all(word in text_words for word in term_words)


def unique_non_empty(values: Sequence[str | None]) -> list[str]:
    unique_values, seen = [], set()
    for value in values:
        if not value:
            continue
        normalized = value.strip()
        if not normalized or normalized.casefold() in seen:
            continue
        unique_values.append(normalized)
        seen.add(normalized.casefold())
    return unique_values


def build_title_query_terms(attrs: SearchAttributes) -> list[str]:
    return unique_non_empty(
        [
            attrs.estimated_product_name_en,
            attrs.estimated_product_name_ja,
            attrs.category_en,
            attrs.category_ja,
        ]
    )


def build_attribute_terms(attrs: SearchAttributes) -> list[str]:
    return unique_non_empty(
        [
            attrs.color_en,
            attrs.color_ja,
            attrs.category_en,
            attrs.category_ja,
            *attrs.features_en,
            *attrs.features_ja,
        ]
    )


def repeat_terms(terms: Sequence[str | None], weight: int) -> list[str]:
    repeated_terms = []
    for term in unique_non_empty(terms):
        repeated_terms.extend([term] * weight)
    return repeated_terms


def build_weighted_ranking_terms(attrs: SearchAttributes) -> list[str]:
    required_terms = [*attrs.required_terms_en, *attrs.required_terms_ja]
    preferred_terms = [*attrs.preferred_terms_en, *attrs.preferred_terms_ja]
    related_terms = [*attrs.related_terms_en, *attrs.related_terms_ja]

    return [
        *repeat_terms(required_terms, REQUIRED_TERM_WEIGHT),
        *repeat_terms(preferred_terms, PREFERRED_TERM_WEIGHT),
        *repeat_terms(related_terms, RELATED_TERM_WEIGHT),
    ]


def build_negative_terms(attrs: SearchAttributes) -> list[str]:
    return unique_non_empty([*attrs.negative_conditions_en, *attrs.negative_conditions_ja])


def combined_product_text(product: dict[str, Any]) -> str:
    return " ".join(value for value in product_text_parts(product) if value)


def product_text_parts(product: dict[str, Any]) -> list[str]:
    categories = product.get("categories")
    category_text = ""
    if isinstance(categories, list):
        category_text = " ".join(item for item in categories if isinstance(item, str))

    return [
        str(product.get("title") or ""),
        str(product.get("brand_or_store") or ""),
        category_text,
        str(product.get("description") or ""),
    ]


def build_tfidf_text(values: Sequence[str | None], *, dedupe: bool = True) -> str:
    if dedupe:
        cleaned_values = unique_non_empty(values)
    else:
        cleaned_values = [value.strip() for value in values if value and value.strip()]

    joined_text = " ".join(cleaned_values)
    tokens = split_words(joined_text, dedupe=dedupe)
    return " ".join(tokens)


def build_title_query_text(attrs: SearchAttributes) -> str:
    return build_tfidf_text(
        [*build_title_query_terms(attrs), *build_weighted_ranking_terms(attrs)], dedupe=False
    )


def build_attribute_query_text(attrs: SearchAttributes) -> str:
    return build_tfidf_text(
        [*build_attribute_terms(attrs), *build_weighted_ranking_terms(attrs)], dedupe=False
    )


def build_product_tfidf_text(product: dict[str, Any]) -> str:
    return build_tfidf_text([combined_product_text(product)])


def build_product_title_tfidf_text(product: dict[str, Any]) -> str:
    return build_tfidf_text([str(product.get("title") or "")])


def calculate_tfidf_similarities(query_text: str, document_texts: list[str]) -> list[float]:
    if not query_text or not document_texts:
        return [0.0 for _ in document_texts]

    documents = [build_tfidf_text([text]) for text in [query_text, *document_texts]]
    if not any(document.strip() for document in documents):
        return [0.0 for _ in document_texts]

    vectorizer = TfidfVectorizer(
        analyzer="word",
        token_pattern=r"(?u)\b\w+\b",
        lowercase=False,
    )
    try:
        vectorizer.fit(documents)
        query_vector = vectorizer.transform([documents[0]])
        document_vectors = vectorizer.transform(documents[1:])
    except ValueError:
        return [0.0 for _ in document_texts]

    return [float(score) for score in cosine_similarity(query_vector, document_vectors).ravel()]


def calculate_term_match_score(terms: list[str], text: str) -> tuple[float, list[str], list[str]]:
    if not terms:
        return 0.0, [], []

    matched_terms = [term for term in terms if term_matches_text(term, text)]
    missing_terms = [term for term in terms if term not in matched_terms]
    return len(matched_terms) / len(terms), matched_terms, missing_terms


def calculate_title_similarity(attrs: SearchAttributes, product: dict[str, Any]) -> float:
    return calculate_tfidf_similarities(
        build_title_query_text(attrs), [build_product_title_tfidf_text(product)]
    )[0]


def calculate_attribute_similarity(
    attrs: SearchAttributes, product: dict[str, Any]
) -> tuple[float, list[str], list[str]]:
    product_text = combined_product_text(product)
    attribute_terms = build_attribute_terms(attrs)
    _, matched_terms, missing_terms = calculate_term_match_score(attribute_terms, product_text)
    score = calculate_tfidf_similarities(
        build_attribute_query_text(attrs), [build_product_tfidf_text(product)]
    )[0]
    return score, matched_terms, missing_terms


def calculate_price_score(attrs: SearchAttributes, product: dict[str, Any]) -> float:
    price = product.get("price_jpy")
    if not isinstance(price, int) or price <= 0:
        return 0.0

    if attrs.max_price_jpy:
        if price <= attrs.max_price_jpy:
            return 1.0
        over_budget_ratio = (price - attrs.max_price_jpy) / attrs.max_price_jpy
        return max(0.0, 1.0 - over_budget_ratio)

    price_preference = (attrs.price_preference or "none").casefold()
    if price_preference == "cheap":
        return 1.0 / (1.0 + math.log10(price / 1000 + 1.0))
    if price_preference == "premium":
        return min(1.0, math.log10(price / 1000 + 1.0) / 2.0)
    return 0.5


def calculate_negative_penalty(
    attrs: SearchAttributes, product: dict[str, Any]
) -> tuple[float, list[str]]:
    product_text = combined_product_text(product)
    negative_matches = [
        term for term in build_negative_terms(attrs) if term_matches_text(term, product_text)
    ]
    if not negative_matches:
        return 0.0, []

    penalty = min(0.5, 0.2 * len(negative_matches))
    return penalty, negative_matches


def score_product(
    attrs: SearchAttributes,
    product: dict[str, Any],
    *,
    title_similarity: float | None = None,
    attribute_similarity: float | None = None,
    title_weight: float = DEFAULT_TITLE_WEIGHT,
    attribute_weight: float = DEFAULT_ATTRIBUTE_WEIGHT,
    price_weight: float = DEFAULT_PRICE_WEIGHT,
) -> ProductScore:
    if title_similarity is None:
        title_similarity = calculate_title_similarity(attrs, product)

    if attribute_similarity is None:
        attribute_similarity, matched_terms, missing_terms = calculate_attribute_similarity(
            attrs, product
        )
    else:
        _, matched_terms, missing_terms = calculate_term_match_score(
            build_attribute_terms(attrs), combined_product_text(product)
        )

    price_score = calculate_price_score(attrs, product)
    negative_penalty, negative_matches = calculate_negative_penalty(attrs, product)
    total_score = (
        title_similarity * title_weight
        + attribute_similarity * attribute_weight
        + price_score * price_weight
        - negative_penalty
    )

    return ProductScore(
        asin=product.get("asin"),
        title=str(product.get("title") or ""),
        price_jpy=product.get("price_jpy"),
        rating=product.get("rating"),
        review_count=product.get("review_count"),
        product_url=product.get("product_url"),
        title_similarity=round(title_similarity, 4),
        attribute_similarity=round(attribute_similarity, 4),
        price_score=round(price_score, 4),
        negative_penalty=round(negative_penalty, 4),
        total_score=round(max(0.0, min(1.0, total_score)), 4),
        matched_terms=matched_terms,
        missing_terms=missing_terms,
        negative_matches=negative_matches,
    )


def score_products(attrs: SearchAttributes, products: list[dict[str, Any]]) -> list[ProductScore]:
    product_title_texts = [build_product_title_tfidf_text(product) for product in products]
    product_attribute_texts = [build_product_tfidf_text(product) for product in products]

    title_scores = calculate_tfidf_similarities(
        build_title_query_text(attrs),
        product_title_texts,
    )
    attribute_scores = calculate_tfidf_similarities(
        build_attribute_query_text(attrs),
        product_attribute_texts,
    )

    scored_products = []
    for product, title_score, attribute_score in zip(
        products, title_scores, attribute_scores, strict=True
    ):
        scored_products.append(
            score_product(
                attrs,
                product,
                title_similarity=title_score,
                attribute_similarity=attribute_score,
            )
        )

    return sorted(scored_products, key=lambda product: product.total_score, reverse=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="正規化済みAmazon商品候補に商品名類似度、属性類似度、価格スコアを付与するサンプル",
    )
    parser.add_argument(
        "--products",
        type=Path,
        default=DEFAULT_PRODUCTS_PATH,
        help=f"第三段階の正規化済み商品候補JSON。デフォルトは {DEFAULT_PRODUCTS_PATH}",
    )
    parser.add_argument(
        "--attributes",
        type=Path,
        default=DEFAULT_ATTRIBUTES_PATH,
        help=f"第一段階の商品属性JSON。デフォルトは {DEFAULT_ATTRIBUTES_PATH}",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="スコア付き商品候補JSONの保存先。未指定の場合は標準出力に表示する",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    attrs = SearchAttributes.model_validate(read_json(args.attributes))
    products = read_json(args.products)
    if not isinstance(products, list):
        raise ValueError("Products JSON must be a list.")

    scored_products = score_products(attrs, products)
    output = [product.model_dump() for product in scored_products]

    if args.output:
        write_json(args.output, output)
        print(f"Scored products written to: {args.output}")
    else:
        print(json.dumps(output, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
