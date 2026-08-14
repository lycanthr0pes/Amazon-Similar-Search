from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import requests
from dotenv import load_dotenv


OUTSCRAPER_AMAZON_PRODUCTS_ENDPOINT = "https://api.outscraper.cloud/amazon-products"
OUTSCRAPER_AMAZON_DOMAIN = "amazon.co.jp"
OUTSCRAPER_AMAZON_LANGUAGE = "ja"
OUTSCRAPER_AMAZON_LIMIT = 10
OUTSCRAPER_POLL_INTERVAL_SECONDS = 30
OUTSCRAPER_MAX_POLLS = 50
OUTSCRAPER_REQUEST_TIMEOUT_SECONDS = 30
SAMPLE_SEARCH_QUERY = "ノイズキャンセリング 小型 ワイヤレスイヤホン ブラック"
PENDING_STATUSES = {"pending", "in progress", "in_progress", "processing"}


def validate_search_query(query: str) -> str:
    normalized_query = query.strip()
    if not normalized_query:
        raise ValueError("Search query must not be empty.")
    if normalized_query.startswith(("http://", "https://")):
        raise ValueError("Pass a search query instead of an Amazon URL.")
    return normalized_query


def build_amazon_products_params(
    query: str,
    *,
    domain: str = OUTSCRAPER_AMAZON_DOMAIN,
    language: str = OUTSCRAPER_AMAZON_LANGUAGE,
    limit: int = OUTSCRAPER_AMAZON_LIMIT,
    async_request: bool = False,
) -> dict[str, str | int]:
    normalized_query = validate_search_query(query)
    return {
        "query": normalized_query,
        "domain": domain,
        "language": language,
        "limit": limit,
        "async": str(async_request).lower(),
    }


def build_amazon_products_request_url(
    query: str,
    *,
    endpoint: str = OUTSCRAPER_AMAZON_PRODUCTS_ENDPOINT,
    domain: str = OUTSCRAPER_AMAZON_DOMAIN,
    language: str = OUTSCRAPER_AMAZON_LANGUAGE,
    limit: int = OUTSCRAPER_AMAZON_LIMIT,
    async_request: bool = False,
) -> str:
    params = build_amazon_products_params(
        query,
        domain=domain,
        language=language,
        limit=limit,
        async_request=async_request,
    )
    return f"{endpoint}?{urlencode(params)}"


def submit_amazon_products_request(
    query: str,
    *,
    api_key: str,
    endpoint: str = OUTSCRAPER_AMAZON_PRODUCTS_ENDPOINT,
    domain: str = OUTSCRAPER_AMAZON_DOMAIN,
    language: str = OUTSCRAPER_AMAZON_LANGUAGE,
    limit: int = OUTSCRAPER_AMAZON_LIMIT,
    timeout: int = OUTSCRAPER_REQUEST_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    params = build_amazon_products_params(
        query,
        domain=domain,
        language=language,
        limit=limit,
        async_request=True,
    )
    response = requests.get(
        endpoint,
        params=params,
        headers={"X-API-KEY": api_key},
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()


def fetch_request_result(
    results_location: str,
    *,
    api_key: str,
    timeout: int = OUTSCRAPER_REQUEST_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    response = requests.get(
        results_location,
        headers={"X-API-KEY": api_key},
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()


def is_pending_result(data: dict[str, Any]) -> bool:
    return str(data.get("status", "")).lower() in PENDING_STATUSES


def fetch_amazon_products(
    query: str,
    *,
    api_key: str,
    endpoint: str = OUTSCRAPER_AMAZON_PRODUCTS_ENDPOINT,
    domain: str = OUTSCRAPER_AMAZON_DOMAIN,
    language: str = OUTSCRAPER_AMAZON_LANGUAGE,
    limit: int = OUTSCRAPER_AMAZON_LIMIT,
    request_timeout: int = OUTSCRAPER_REQUEST_TIMEOUT_SECONDS,
    poll_interval: int = OUTSCRAPER_POLL_INTERVAL_SECONDS,
    max_polls: int = OUTSCRAPER_MAX_POLLS,
) -> dict[str, Any]:
    submitted = submit_amazon_products_request(
        query,
        api_key=api_key,
        endpoint=endpoint,
        domain=domain,
        language=language,
        limit=limit,
        timeout=request_timeout,
    )
    results_location = submitted.get("results_location")
    if not results_location:
        return submitted

    print(f"Request ID: {submitted.get('id')}")
    print(f"Results location: {results_location}")

    last_result: dict[str, Any] = submitted
    for poll_count in range(1, max_polls + 1):
        result = fetch_request_result(
            str(results_location),
            api_key=api_key,
            timeout=request_timeout,
        )
        last_result = result
        status = result.get("status", "unknown")
        print(f"Poll {poll_count}/{max_polls}: {status}")
        if not is_pending_result(result):
            return result
        time.sleep(poll_interval)

    last_result["results_location"] = str(results_location)
    last_result["description"] = f"Outscraper request is still pending after {max_polls} polls."
    return last_result


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Outscraper Amazon Products ScraperへAmazon検索語を渡すサンプル",
    )
    parser.add_argument(
        "query",
        nargs="?",
        default=SAMPLE_SEARCH_QUERY,
        help="Amazon Products Scraperへ渡す検索語",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=OUTSCRAPER_AMAZON_LIMIT,
        help=f"取得する商品数の上限。デフォルトは {OUTSCRAPER_AMAZON_LIMIT}",
    )
    parser.add_argument(
        "--domain",
        default=OUTSCRAPER_AMAZON_DOMAIN,
        help=f"Amazonドメイン。デフォルトは {OUTSCRAPER_AMAZON_DOMAIN}",
    )
    parser.add_argument(
        "--language",
        default=OUTSCRAPER_AMAZON_LANGUAGE,
        help=f"Amazon表示言語。デフォルトは {OUTSCRAPER_AMAZON_LANGUAGE}",
    )
    parser.add_argument(
        "--endpoint",
        default=os.getenv(
            "OUTSCRAPER_AMAZON_PRODUCTS_ENDPOINT", OUTSCRAPER_AMAZON_PRODUCTS_ENDPOINT
        ),
        help="Outscraper Amazon Products API endpoint",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="レスポンスJSONの保存先。未指定の場合は標準出力に表示する",
    )
    parser.add_argument(
        "--poll-interval",
        type=int,
        default=OUTSCRAPER_POLL_INTERVAL_SECONDS,
        help=f"結果確認の待機秒数。デフォルトは {OUTSCRAPER_POLL_INTERVAL_SECONDS}",
    )
    parser.add_argument(
        "--max-polls",
        type=int,
        default=OUTSCRAPER_MAX_POLLS,
        help=f"結果確認の最大回数。デフォルトは {OUTSCRAPER_MAX_POLLS}",
    )
    parser.add_argument(
        "--request-timeout",
        type=int,
        default=OUTSCRAPER_REQUEST_TIMEOUT_SECONDS,
        help=f"Outscraper APIへの各HTTPリクエストのタイムアウト秒数。デフォルトは {OUTSCRAPER_REQUEST_TIMEOUT_SECONDS}",
    )
    return parser.parse_args()


def main() -> None:
    load_dotenv()
    args = parse_args()
    query = validate_search_query(args.query)

    api_key = os.getenv("OUTSCRAPER_API_KEY")
    if not api_key:
        raise RuntimeError("OUTSCRAPER_API_KEY is not set. Set it in .env or shell environment.")

    request_url = build_amazon_products_request_url(
        query,
        endpoint=args.endpoint,
        domain=args.domain,
        language=args.language,
        limit=args.limit,
        async_request=True,
    )
    print(f"Request URL: {request_url}")

    data = fetch_amazon_products(
        query,
        api_key=api_key,
        endpoint=args.endpoint,
        domain=args.domain,
        language=args.language,
        limit=args.limit,
        request_timeout=args.request_timeout,
        poll_interval=args.poll_interval,
        max_polls=args.max_polls,
    )

    if args.output:
        write_json(args.output, data)
        print(f"Response JSON written to: {args.output}")
    else:
        print(json.dumps(data, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
