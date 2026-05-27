from urllib.parse import urlencode
from typing import Any
import requests
import time
from pathlib import Path

from src.config import settings
from src.utilities.json_editor import write_json

PROCESSING_STATUSES = {"pending", "in progress", "in_progress", "processing"}


# Outscraperに渡すための検索クエリJSONを組み立てる
def build_amazon_products_params(
    query: str,
    domain: str = settings.outscraper_domain,
    language: str = settings.outscraper_language,
    postal_code: str = settings.outscraper_postal_code,
    limit: int = settings.outscraper_limit,
    async_request: bool = False,
) -> dict[str, str | int]:
    params: dict[str, str | int] = {
        "query": query,
        "domain": domain,
        "language": language,
        "limit": limit,
        "async": str(async_request).lower(),
    }
    if postal_code:
        params["postal_code"] = postal_code
    return params


# Outscraperに渡す検索クエリURLを確認するためのURLを組み立てる
def build_amazon_products_request_url(
    query: str,
    endpoint: str = settings.outscraper_endpoint,
    domain: str = settings.outscraper_domain,
    language: str = settings.outscraper_language,
    postal_code: str = settings.outscraper_postal_code,
    limit: int = settings.outscraper_limit,
    async_request: bool = False,
) -> str:
    params = build_amazon_products_params(
        query,
        domain=domain,
        language=language,
        postal_code=postal_code,
        limit=limit,
        async_request=async_request,
    )
    return f"{endpoint}?{urlencode(params)}"


# Outscraperの検索結果URLをチェックし, タスクから検索結果を取得する
def fetch_request_result(
    results_location: str,
    api_key: str,
    timeout: int = settings.outscraper_request_timeout_seconds,
) -> dict[str, Any]:
    # 進行状況/結果を取得する
    response = requests.get(
        results_location,
        headers={"X-API-KEY": api_key},
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()


# Outscraperの検索タスクの進行状況をチェックする
def processing_check(data: dict[str, Any]) -> bool:
    return str(data.get("status", "")).lower() in PROCESSING_STATUSES


# 最初にOutscraperに検索クエリJSONを渡し, タスクを作成する
def task_amazon_products_request(
    query: str,
    api_key: str,
    endpoint: str = settings.outscraper_endpoint,
    domain: str = settings.outscraper_domain,
    language: str = settings.outscraper_language,
    postal_code: str = settings.outscraper_postal_code,
    limit: int = settings.outscraper_limit,
    timeout: int = settings.outscraper_request_timeout_seconds,
) -> dict[str, Any]:

    # 検索クエリJSONを組み立てる
    params = build_amazon_products_params(
        query,
        domain=domain,
        language=language,
        postal_code=postal_code,
        limit=limit,
        async_request=True,
    )
    # 検索クエリJSONを渡し, 進行状況を取得する
    response = requests.get(
        endpoint,
        params=params,
        headers={"X-API-KEY": api_key},
        timeout=timeout,
    )
    response.raise_for_status()
    return response.json()


# 検索タスクを作り, 結果を定期チェックし, 終わったらURLから検索結果JSONを取得する
def fetch_amazon_products(
    query: str,
    api_key: str,
    endpoint: str = settings.outscraper_endpoint,
    domain: str = settings.outscraper_domain,
    language: str = settings.outscraper_language,
    postal_code: str = settings.outscraper_postal_code,
    limit: int = settings.outscraper_limit,
    request_timeout: int = settings.outscraper_request_timeout_seconds,
    poll_interval: int = settings.outscraper_poll_interval_seconds,
    max_polls: int = settings.outscraper_max_polls,
) -> dict[str, Any]:

    # 検索タスクを作成し, 初期値として進行状況を取得する
    search_task = task_amazon_products_request(
        query,
        api_key=api_key,
        endpoint=endpoint,
        domain=domain,
        language=language,
        postal_code=postal_code,
        limit=limit,
        timeout=request_timeout,
    )

    # 検索タスクの最初の返り値から検索結果を取得するためのURLを取得する
    results_location = search_task.get("results_location")
    if not results_location:
        return search_task

    print(f"Request ID: {search_task.get('id')}")
    print(f"Results location: {results_location}")

    # 検索結果URLからタスクの進行状況を定期的にチェックし, 終わったら取得する
    last_result: dict[str, Any] = search_task
    for poll_count in range(1, max_polls + 1):
        result = fetch_request_result(
            str(results_location),
            api_key=api_key,
            timeout=request_timeout,
        )
        last_result = result
        status = result.get("status", "unknown")
        print(f"Poll {poll_count}/{max_polls}: {status}")
        # 終わったら結果として辞書を返す
        if not processing_check(result):
            return result
        time.sleep(poll_interval)

    # 最大チェック数を超えたら失敗とみなして最後の進行状況を返す
    last_result["results_location"] = str(results_location)
    last_result["description"] = f"Outscraper request is still pending after {max_polls} polls."
    return last_result


# OutscraperのAPIを呼び出し, 検索クエリJSONを渡し, 返り値をJSONに書き込む
def call_outscraper(query: str, query_hash: str) -> Path:
    api_key = settings.outscraper_api_key
    if not api_key:
        raise RuntimeError("OUTSCRAPER_API_KEY is not set. Set it in .env or shell environment.")

    # 検索クエリURLを確認するためのURLを組み立てる
    request_url = build_amazon_products_request_url(
        query,
        endpoint=settings.outscraper_endpoint,
        domain=settings.outscraper_domain,
        language=settings.outscraper_language,
        postal_code=settings.outscraper_postal_code,
        limit=settings.outscraper_limit,
        async_request=True,
    )
    print(f"Request URL: {request_url}")

    # 検索クエリJSONを渡し, 検索結果を取得する
    data = fetch_amazon_products(
        query,
        api_key=api_key,
        endpoint=settings.outscraper_endpoint,
        domain=settings.outscraper_domain,
        language=settings.outscraper_language,
        postal_code=settings.outscraper_postal_code,
        limit=settings.outscraper_limit,
        request_timeout=settings.outscraper_request_timeout_seconds,
        poll_interval=settings.outscraper_poll_interval_seconds,
        max_polls=settings.outscraper_max_polls,
    )

    # 検索結果をJSONに書き込む:
    output_path = Path(f"cache/outscraper/amazon_products_raw_{query_hash}.json")
    write_json(output_path, data)
    print(f"Response JSON written to: {output_path}")

    # JSONのパスとハッシュを返す
    return output_path
