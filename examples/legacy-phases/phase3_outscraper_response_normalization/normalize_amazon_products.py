from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


def string_list() -> Any:
    return Field(default_factory=list)


DEFAULT_SAMPLE_RESPONSE = Path("cache/outscraper/amazon_products_dummy_response.json")
TARGET_CURRENCY = "JPY"
USD_CURRENCY = "USD"
USD_TO_JPY_RATE = 160


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


def read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def as_int(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        digits = "".join(character for character in value if character.isdecimal())
        return int(digits) if digits else None
    return None


def as_float(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def as_non_empty_string(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None


def detect_currency(item: dict[str, Any]) -> str | None:
    currency = as_non_empty_string(item.get("currency"))
    if currency:
        return currency.upper()

    price_values = [
        item.get("price"),
        item.get("old_price"),
        item.get("strike_price"),
        item.get("delivery_price"),
    ]
    for value in price_values:
        if not isinstance(value, str):
            continue
        normalized = value.upper()
        if USD_CURRENCY in normalized or "$" in normalized:
            return USD_CURRENCY
        if (
            TARGET_CURRENCY in normalized
            or "￥" in normalized
            or "¥" in normalized
            or "円" in normalized
        ):
            return TARGET_CURRENCY
    return None


def convert_price_to_jpy(value: Any, currency: str | None) -> int | None:
    if currency == USD_CURRENCY:
        price = as_float(value)
        if price is None:
            return None
        return int(price * USD_TO_JPY_RATE)
    return as_int(value)


def as_string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []

    strings = []
    for item in value:
        normalized = as_non_empty_string(item)
        if normalized:
            strings.append(normalized)
    return strings


def unique_strings(values: list[str | None]) -> list[str]:
    unique_values = []
    seen = set()
    for value in values:
        if not value or value in seen:
            continue
        unique_values.append(value)
        seen.add(value)
    return unique_values


def collect_image_urls(item: dict[str, Any]) -> list[str]:
    image_urls: list[str | None] = []

    high_res_images = item.get("high_res_images")
    if isinstance(high_res_images, list):
        image_urls.extend(as_non_empty_string(image) for image in high_res_images)

    for index in range(1, 11):
        image_urls.append(as_non_empty_string(item.get(f"image_{index}")))

    return unique_strings(image_urls)


def iter_product_items(response: dict[str, Any]) -> list[dict[str, Any]]:
    data = response.get("data")
    if not isinstance(data, list):
        return []

    product_items: list[dict[str, Any]] = []
    for group in data:
        if isinstance(group, dict):
            product_items.append(group)
        elif isinstance(group, list):
            product_items.extend(item for item in group if isinstance(item, dict))
    return product_items


def normalize_product(item: dict[str, Any]) -> NormalizedAmazonProduct | None:
    title = as_non_empty_string(item.get("name"))
    if not title:
        return None

    currency = detect_currency(item)
    if currency and currency not in {TARGET_CURRENCY, USD_CURRENCY}:
        return None

    image_urls = collect_image_urls(item)
    return NormalizedAmazonProduct(
        asin=as_non_empty_string(item.get("asin")),
        title=title,
        brand_or_store=as_non_empty_string(item.get("store_title")),
        price_jpy=convert_price_to_jpy(item.get("price_parsed") or item.get("price"), currency),
        list_price_jpy=convert_price_to_jpy(
            item.get("old_price_parsed")
            or item.get("strike_price_parsed")
            or item.get("old_price")
            or item.get("strike_price"),
            currency,
        ),
        currency=currency,
        rating=as_float(item.get("rating")),
        review_count=as_int(item.get("reviews")),
        categories=as_string_list(item.get("categories")),
        image_url=next(iter(image_urls), None),
        image_urls=image_urls,
        product_url=as_non_empty_string(item.get("url")),
        short_url=as_non_empty_string(item.get("short_url")),
        is_prime=bool(item.get("prime")),
        availability=as_non_empty_string(item.get("availability")),
        shipping=as_non_empty_string(item.get("shipping")),
        source_query=as_non_empty_string(item.get("query")),
        position=as_int(item.get("position")),
        description=as_non_empty_string(item.get("description")),
    )


def normalize_amazon_products_response(response: dict[str, Any]) -> list[NormalizedAmazonProduct]:
    products: list[NormalizedAmazonProduct] = []
    seen_keys = set()

    for item in iter_product_items(response):
        product = normalize_product(item)
        if not product:
            continue

        dedupe_key = product.asin or product.short_url or product.product_url or product.title
        if dedupe_key in seen_keys:
            continue

        products.append(product)
        seen_keys.add(dedupe_key)

    return products


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Outscraper Amazon Products Scraperレスポンスを商品候補へ正規化するサンプル",
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=DEFAULT_SAMPLE_RESPONSE,
        help=f"OutscraperレスポンスJSON。デフォルトは {DEFAULT_SAMPLE_RESPONSE}",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="正規化済み商品候補JSONの保存先。未指定の場合は標準出力に表示する",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    response = read_json(args.input)
    products = normalize_amazon_products_response(response)
    normalized = [product.model_dump() for product in products]

    if args.output:
        write_json(args.output, normalized)
        print(f"Normalized products written to: {args.output}")
    else:
        print(json.dumps(normalized, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
