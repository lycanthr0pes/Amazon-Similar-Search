from typing import Any
from pathlib import Path

from src.schemas import NormalizedAmazonProduct
from src.config import settings
from src.utilities.json_editor import read_json
from src.utilities.json_editor import write_json

TARGET_CURRENCY = "JPY"
USD_CURRENCY = "USD"


# Outscraperが返した生のJSONから商品データだけを取り出し, リスト化する
# JSON辞書の中の辞書リストの中身を取り出す
def iter_product_items(response: dict[str, Any]) -> list[dict[str, Any]]:
    data = response.get("data")
    if not isinstance(data, list):
        return []
    product_items: list[dict[str, Any]] = []
    for group in data:
        # 辞書が存在すればリストに入れる
        if isinstance(group, dict):
            product_items.append(group)
        # リストかつ, リストの中に辞書があれば取り出してリストに入れる
        # append だとリスト毎入るので extend
        elif isinstance(group, list):
            product_items.extend(item for item in group if isinstance(item, dict))
    return product_items


# 前後の空白を削除
def as_non_empty_string(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    return normalized or None


# リストの順序を保ったまま重複を削除する
def clean_dupe_strings(values: list[str | None]) -> list[str]:
    unique_values = []
    seen = set()
    for value in values:
        if not value or value in seen:
            continue
        unique_values.append(value)
        seen.add(value)
    return unique_values


# 商品の高解像度サムネと低解像度サムネを取得
# 同じ画像URLが複数挿入されることがあるので, 重複を削除して返す
def collect_image_urls(item: dict[str, Any]) -> list[str]:
    image_urls: list[str | None] = []

    # 高解像度サムネは前後の空白を削除してそのままリストに追加
    high_res_images = item.get("high_res_images")
    if isinstance(high_res_images, list):
        image_urls.extend(as_non_empty_string(image) for image in high_res_images)

    # 低解像度サムネはインデックス番号を指定して前後の空白を削除してリストに追加
    for index in range(1, 11):
        image_urls.append(as_non_empty_string(item.get(f"image_{index}")))

    return clean_dupe_strings(image_urls)


# int化
# 文字列も10進数なら結合してint化
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


# float化
def as_float(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


# 配列の各要素の前後の空白を削除
def as_string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []

    strings = []
    for item in value:
        normalized = as_non_empty_string(item)
        if normalized:
            strings.append(normalized)
    return strings


# Outscraperのcurrencyが空でも価格文字列に通貨が含まれる場合があるため補完する
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

# USDを1ドル160円換算でJPYに変換する
def convert_price_to_jpy(value: Any, currency: str | None) -> int | None:
    if currency == USD_CURRENCY:
        price = as_float(value)
        if price is None:
            return None
        return int(price * settings.usd_to_jpy_rate)
    return as_int(value)


# Outscraperが返した生のJSONから商品データ1件を正規化する
# NormalizedAmazonProduct型で返す
def normalize_product(item: dict[str, Any]) -> NormalizedAmazonProduct | None:

    # 名前から前後の空白を削除
    title = as_non_empty_string(item.get("name"))
    if not title:
        return None

    # 通貨単位を取得する
    currency = detect_currency(item)
    # 日本円またはUSDでない場合は正規化失敗とみなす
    if currency and currency not in {TARGET_CURRENCY, USD_CURRENCY}:
        return None

    # サムネから前後の空白と重複を削除
    image_urls = collect_image_urls(item)
    return NormalizedAmazonProduct(
        # ASINから前後の空白を削除
        asin=as_non_empty_string(item.get("asin")),
        title=title,
        # ストア名から前後の空白を削除
        brand_or_store=as_non_empty_string(item.get("store_title")),
        # 価格をintに
        price_jpy=convert_price_to_jpy(item.get("price_parsed") or item.get("price"), currency),
        # 定価・参考価格・値引き前価格をintに
        list_price_jpy=convert_price_to_jpy(
            item.get("old_price_parsed")
            or item.get("strike_price_parsed")
            or item.get("old_price")
            or item.get("strike_price"),
            currency,
        ),
        # 通貨単位から前後の空白を削除
        currency=currency,
        # レビュースコアをfloatに
        rating=as_float(item.get("rating")),
        # レビュー数をintに
        review_count=as_int(item.get("reviews")),
        # カテゴリをfloatに
        categories=as_string_list(item.get("categories")),
        # サムネリストから表示用に1件取得し, 他もリストして返す
        image_url=next(iter(image_urls), None),
        image_urls=image_urls,
        # 商品ページURLから前後の空白を削除
        product_url=as_non_empty_string(item.get("url")),
        # 商品ページURLから前後の空白を削除
        short_url=as_non_empty_string(item.get("short_url")),
        # Amazomプライム商品か
        is_prime=bool(item.get("prime")),
        # 在庫情報から前後の空白を削除
        availability=as_non_empty_string(item.get("availability")),
        # 配送情報から前後の空白を削除
        shipping=as_non_empty_string(item.get("shipping")),
        # 検索ワードから前後の空白を削除
        source_query=as_non_empty_string(item.get("query")),
        # 検索結果順の番号をintに
        position=as_int(item.get("position")),
        # 商品説明から前後の空白を削除
        description=as_non_empty_string(item.get("description")),
    )


# Outscraperが返した生のJSONを正規化し, NormalizedAmazonProduct型のリストとして返す
def normalize_amazon_products_response(response: dict[str, Any]) -> list[NormalizedAmazonProduct]:
    products: list[NormalizedAmazonProduct] = []
    seen_keys = set()

    # 商品を1つずつ正規化する
    for item in iter_product_items(response):
        product = normalize_product(item)
        if not product:
            continue
        # 「キーが重複=同じ商品」となるキーが商品に含まれていれば無視
        dedupe_key = product.asin or product.short_url or product.product_url or product.title
        if dedupe_key in seen_keys:
            continue

        products.append(product)
        seen_keys.add(dedupe_key)

    return products


# Outscraperが返した生のJSONを正規化し, JSONに書き込み, list[NormalizedAmazonProduct]を返す
def normalize(path: Path, query_hash: str) -> list[NormalizedAmazonProduct]:
    response = read_json(path)
    normalize_products = normalize_amazon_products_response(response)

    # list[NormalizedAmazonProduct]をJSON化して書き込む
    normalized_dump = [product.model_dump() for product in normalize_products]
    output_path = Path(f"cache/outscraper/amazon_products_normalized_{query_hash}.json")
    write_json(output_path, normalized_dump)
    print(f"Normalized products written to: {output_path}")

    # list[NormalizedAmazonProduct]を返す
    return normalize_products
