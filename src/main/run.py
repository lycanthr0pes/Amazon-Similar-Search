from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path
from typing import TYPE_CHECKING

# Path(__file__).resolve().parents[2] = ルートディレクトリ
PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = PROJECT_ROOT / "src"
# ルートディレクトリからimportするプログラムを探せるようにする
for import_path in (PROJECT_ROOT, SRC_ROOT):
    if str(import_path) not in sys.path:
        sys.path.insert(0, str(import_path))

# テスト用
if TYPE_CHECKING:
    from src.schemas import ProductAttributes
    from src.schemas import ProductScore


ATTRIBUTES_CACHE_VERSION = "2"
NORMALIZATION_CACHE_VERSION = "2"
SCORING_CACHE_VERSION = "2"


def write_product_attributes(attrs: "ProductAttributes", cache_key: str) -> Path:
    from src.config import settings
    from src.repositories.cache_repository import JsonCacheRepository
    from src.repositories.cache_repository import PRODUCT_ATTRIBUTES_CACHE

    repository = JsonCacheRepository(settings.cache_dir)
    output_path = repository.save(PRODUCT_ATTRIBUTES_CACHE, cache_key, attrs.model_dump())
    print(f"Product attributes written to: {output_path}")
    return output_path


def build_attributes_cache_key(user_input: str, *, cache_scope: str = "local-cli") -> str:
    from src.clients.bonsai_client import load_bonsai_prompt
    from src.config import settings
    from src.utilities.build_hash import build_cache_key

    prompt_digest = hashlib.sha256(load_bonsai_prompt().encode("utf-8")).hexdigest()
    return build_cache_key(
        {
            "type": "product_attributes",
            "version": ATTRIBUTES_CACHE_VERSION,
            "cache_scope": cache_scope,
            "user_input": user_input,
            "bonsai_base_url": settings.bonsai_base_url,
            "bonsai_model": settings.bonsai_model,
            "prompt_sha256": prompt_digest,
            "temperature": settings.bonsai_temperature,
            "max_tokens": settings.bonsai_max_tokens,
        }
    )


def build_outscraper_cache_key(query: str, *, cache_scope: str = "local-cli") -> str:
    from src.config import settings
    from src.utilities.build_hash import build_cache_key

    return build_cache_key(
        {
            "type": "outscraper_raw",
            "cache_scope": cache_scope,
            "query": query,
            "endpoint": settings.outscraper_endpoint,
            "domain": settings.outscraper_domain,
            "language": settings.outscraper_language,
            "postal_code": settings.outscraper_postal_code,
            "limit": settings.outscraper_limit,
        }
    )


def build_normalized_cache_key(
    raw_response: object,
    *,
    cache_scope: str = "local-cli",
) -> str:
    from src.config import settings
    from src.utilities.build_hash import build_cache_key

    return build_cache_key(
        {
            "type": "normalized_products",
            "version": NORMALIZATION_CACHE_VERSION,
            "cache_scope": cache_scope,
            "usd_to_jpy_rate": settings.usd_to_jpy_rate,
            "raw_response": raw_response,
        }
    )


def build_scored_cache_key(
    attrs: "ProductAttributes",
    normalized_cache_key: str,
) -> str:
    from src.config import settings
    from src.utilities.build_hash import build_cache_key

    return build_cache_key(
        {
            "type": "scored_products",
            "version": SCORING_CACHE_VERSION,
            "attributes": attrs.model_dump(mode="json"),
            "normalized_cache_key": normalized_cache_key,
            "title_score_weight": settings.title_score_weight,
            "attribute_score_weight": settings.attribute_score_weight,
            "price_score_weight": settings.price_score_weight,
            "required_term_weight": settings.required_term_weight,
            "color_term_weight": settings.color_term_weight,
            "feature_term_weight": settings.feature_term_weight,
            "preferred_term_weight": settings.preferred_term_weight,
            "related_term_weight": settings.related_term_weight,
        }
    )


def _validated_model_list(model_type: type, raw_items: object) -> list | None:
    from pydantic import ValidationError

    if not isinstance(raw_items, list):
        return None
    try:
        return [model_type.model_validate(item) for item in raw_items]
    except ValidationError:
        return None


# 実行部本体
# 最初にユーザーが入力した自然言語を受け取る
def run_product_search(
    user_input: str,
    *,
    use_cache: bool = True,
    cache_scope: str = "local-cli",
) -> list["ProductScore"]:
    from src.clients.bonsai_client import call_bonsai
    from src.clients.outscraper_client import call_outscraper
    from src.config import settings
    from src.repositories.cache_repository import JsonCacheRepository
    from src.repositories.cache_repository import OUTSCRAPER_NORMALIZED_CACHE
    from src.repositories.cache_repository import OUTSCRAPER_RAW_CACHE
    from src.repositories.cache_repository import OUTSCRAPER_SCORED_CACHE
    from src.repositories.cache_repository import PRODUCT_ATTRIBUTES_CACHE
    from src.services.amazon_product_normalization import normalize
    from src.services.outscraper_search_select import select_outscraper_query
    from src.services.product_scoring import scoring
    from src.schemas import NormalizedAmazonProduct
    from src.schemas import ProductAttributes
    from src.schemas import ProductScore
    from src.services.user_attribute_extraction import extract_product_attributes
    from src.utilities.json_editor import read_json

    normalized_input = user_input.strip()
    if not normalized_input:
        raise ValueError("検索条件を入力してください。")
    normalized_scope = cache_scope.strip()
    if not normalized_scope or len(normalized_scope) > 128:
        raise ValueError("Cache scope must contain between 1 and 128 characters.")

    repository = JsonCacheRepository(settings.cache_dir)
    cache_enabled = settings.enable_cache and use_cache

    print("Step 1/4: Bonsaiで商品属性を抽出します")
    attributes_cache_key = build_attributes_cache_key(
        normalized_input,
        cache_scope=normalized_scope,
    )
    cached_attributes = None
    if cache_enabled:
        cached_attributes = repository.load(
            PRODUCT_ATTRIBUTES_CACHE,
            attributes_cache_key,
            max_age_seconds=settings.llm_cache_ttl_seconds,
        )
    try:
        attrs = (
            ProductAttributes.model_validate(cached_attributes)
            if cached_attributes is not None
            else None
        )
    except ValueError:
        attrs = None

    if attrs is None:
        raw_attributes = call_bonsai(normalized_input)
        attrs = extract_product_attributes(raw_attributes, normalized_input)
        write_product_attributes(attrs, attributes_cache_key)
    else:
        print("Product attributes loaded from cache.")

    print("Step 2/4: Outscraperへ渡す検索クエリを選択します")
    query = select_outscraper_query(attrs)
    outscraper_cache_key = build_outscraper_cache_key(query, cache_scope=normalized_scope)
    print("Search query prepared.")

    print("Step 3/4: OutscraperでAmazon商品候補を取得します")
    raw_products_path = None
    raw_response = None
    if cache_enabled:
        raw_products_path = repository.fresh_path(
            OUTSCRAPER_RAW_CACHE,
            outscraper_cache_key,
            max_age_seconds=settings.outscraper_cache_ttl_seconds,
        )
        if raw_products_path is not None:
            cached_raw_response = repository.load(
                OUTSCRAPER_RAW_CACHE,
                outscraper_cache_key,
                max_age_seconds=settings.outscraper_cache_ttl_seconds,
            )
            if isinstance(cached_raw_response, dict):
                raw_response = cached_raw_response
            else:
                raw_products_path = None
    if raw_products_path is None:
        raw_products_path = call_outscraper(query, outscraper_cache_key)
        loaded_raw_response = read_json(raw_products_path)
        if not isinstance(loaded_raw_response, dict):
            raise ValueError("Outscraper cache must contain a JSON object.")
        raw_response = loaded_raw_response
    else:
        print(f"Outscraper response loaded from cache: {raw_products_path}")

    assert raw_response is not None
    normalized_cache_key = build_normalized_cache_key(
        raw_response,
        cache_scope=normalized_scope,
    )
    cached_normalized = (
        repository.load(OUTSCRAPER_NORMALIZED_CACHE, normalized_cache_key)
        if cache_enabled
        else None
    )
    normalize_products = _validated_model_list(NormalizedAmazonProduct, cached_normalized)
    if normalize_products is None:
        normalize_products = normalize(raw_products_path, normalized_cache_key)
    else:
        print("Normalized products loaded from cache.")

    print("Step 4/4: 商品候補をスコアリングします")
    scored_cache_key = build_scored_cache_key(attrs, normalized_cache_key)
    cached_scored = (
        repository.load(OUTSCRAPER_SCORED_CACHE, scored_cache_key) if cache_enabled else None
    )
    scored_products = _validated_model_list(ProductScore, cached_scored)
    if scored_products is not None:
        print("Scored products loaded from cache.")
        return scored_products
    return scoring(attrs, normalize_products, scored_cache_key)


# スコアリング済みの上位n件を標準出力する(テスト用)
def print_top_results(scored_products: list["ProductScore"], *, limit: int) -> None:
    print(f"Top {min(limit, len(scored_products))} results:")
    for index, product in enumerate(scored_products[:limit], start=1):
        price = f"{product.price_jpy}円" if product.price_jpy is not None else "価格不明"
        print(f"{index}. score={product.total_score:.4f} {price} {product.title}")
        if product.product_url:
            print(f"   {product.product_url}")


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("value must be greater than 0")
    return parsed


# テスト用
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="第1段階から第4段階までの商品検索処理をまとめて実行する",
    )
    parser.add_argument(
        "user_input",
        help="欲しい商品の自然言語説明",
    )
    parser.add_argument(
        "--display-limit",
        type=positive_int,
        default=10,
        help="標準出力に表示する上位件数。デフォルトは10",
    )
    parser.add_argument(
        "--no-cache",
        action="store_true",
        help="既存キャッシュを再利用せず外部処理から実行する",
    )
    return parser.parse_args()


# テスト用
def main() -> None:
    args = parse_args()
    scored_products = run_product_search(args.user_input, use_cache=not args.no_cache)
    print_top_results(scored_products, limit=args.display_limit)


# テスト用
if __name__ == "__main__":
    main()
