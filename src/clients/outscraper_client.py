import time
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlencode, urlparse

import requests

from src.config import settings
from src.exceptions import (
    OutscraperRequestError,
    OutscraperResponseError,
    OutscraperSecurityError,
    OutscraperTaskFailedError,
    OutscraperTaskTimeoutError,
)
from src.utilities.json_editor import write_json

PROCESSING_STATUSES = {"pending", "in progress", "in_progress", "processing"}
FAILED_STATUSES = {"failed", "failure", "error", "cancelled", "canceled"}
SUCCESS_STATUSES = {"success", "succeeded", "complete", "completed", "done", "finished", "ok"}
TRANSIENT_HTTP_STATUSES = {429}

TaskState = Literal["pending", "failed", "success", "unknown"]


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


def _normalized_status(data: dict[str, Any]) -> str:
    return str(data.get("status", "")).strip().casefold()


def task_state(data: dict[str, Any]) -> TaskState:
    """Outscraperレスポンスを待機中・失敗・成功・不明へ分類する。"""
    status = _normalized_status(data)
    if status in PROCESSING_STATUSES:
        return "pending"
    if status in FAILED_STATUSES:
        return "failed"
    if status in SUCCESS_STATUSES or "data" in data:
        # data=[]も「成功したが0件」という有効な結果として扱う。
        return "success"
    return "unknown"


# Outscraperの検索タスクの進行状況をチェックする
def processing_check(data: dict[str, Any]) -> bool:
    return task_state(data) == "pending"


def _task_failure(data: dict[str, Any]) -> None:
    if task_state(data) == "failed":
        raise OutscraperTaskFailedError(_normalized_status(data), data)


def _validated_completed_result(data: dict[str, Any]) -> dict[str, Any]:
    if "data" not in data:
        raise OutscraperResponseError("Completed Outscraper response does not include data")
    if not isinstance(data["data"], list):
        raise OutscraperResponseError("Outscraper response data must be a list")
    return data


def _validated_https_origin(url: str, *, label: str) -> tuple[str, int]:
    try:
        parsed = urlparse(url)
        port = parsed.port
    except ValueError as exc:
        raise OutscraperSecurityError(f"{label} is not a valid URL") from exc

    if parsed.scheme.casefold() != "https":
        raise OutscraperSecurityError(f"{label} must use HTTPS")
    if not parsed.hostname:
        raise OutscraperSecurityError(f"{label} must include a host")
    if parsed.username is not None or parsed.password is not None:
        raise OutscraperSecurityError(f"{label} must not include user information")

    return parsed.hostname.rstrip(".").casefold(), port or 443


def validate_results_location(results_location: str, endpoint: str) -> str:
    """APIキー送信前に結果URLがOutscraper endpointと同一オリジンか確認する。"""
    endpoint_origin = _validated_https_origin(endpoint, label="Outscraper endpoint")
    results_origin = _validated_https_origin(results_location, label="Outscraper results_location")
    if results_origin != endpoint_origin:
        raise OutscraperSecurityError(
            "Outscraper results_location must use the same host and port as the endpoint"
        )
    return results_location


def _sleep_before_retry(attempt: int, backoff_seconds: float) -> None:
    delay = backoff_seconds * (2 ** (attempt - 1))
    if delay > 0:
        time.sleep(delay)


def _request_json(
    url: str,
    *,
    api_key: str,
    timeout: int,
    max_attempts: int,
    backoff_seconds: float,
    params: dict[str, str | int] | None = None,
) -> dict[str, Any]:
    if max_attempts < 1:
        raise ValueError("max_attempts must be at least 1")
    if timeout <= 0:
        raise ValueError("timeout must be greater than 0")
    if backoff_seconds < 0:
        raise ValueError("backoff_seconds must not be negative")

    for attempt in range(1, max_attempts + 1):
        try:
            response = requests.get(
                url,
                params=params,
                headers={"X-API-KEY": api_key},
                timeout=timeout,
                allow_redirects=False,
            )
        except (requests.Timeout, requests.ConnectionError) as exc:
            if attempt == max_attempts:
                raise OutscraperRequestError(
                    f"Outscraper request failed after {max_attempts} attempts"
                ) from exc
            _sleep_before_retry(attempt, backoff_seconds)
            continue

        if 300 <= response.status_code < 400:
            raise OutscraperSecurityError(
                "Outscraper redirects are not allowed for API-key requests"
            )

        is_transient = (
            response.status_code in TRANSIENT_HTTP_STATUSES or 500 <= response.status_code < 600
        )
        if is_transient and attempt < max_attempts:
            _sleep_before_retry(attempt, backoff_seconds)
            continue

        try:
            response.raise_for_status()
        except requests.HTTPError as exc:
            if is_transient:
                raise OutscraperRequestError(
                    f"Outscraper returned HTTP {response.status_code} after {max_attempts} attempts"
                ) from exc
            # 401/403を含む非一時的な4xxは再試行せず、そのまま通知する。
            raise OutscraperRequestError(
                f"Outscraper returned non-retryable HTTP {response.status_code}"
            ) from exc

        try:
            data = response.json()
        except ValueError as exc:
            raise OutscraperResponseError("Outscraper returned invalid JSON") from exc
        if not isinstance(data, dict):
            raise OutscraperResponseError("Outscraper response must be a JSON object")
        return data

    raise AssertionError("retry loop exited unexpectedly")


# Outscraperの検索結果URLをチェックし, タスクから検索結果を取得する
def fetch_request_result(
    results_location: str,
    api_key: str,
    endpoint: str = settings.outscraper_endpoint,
    timeout: int = settings.outscraper_request_timeout_seconds,
    max_attempts: int = settings.outscraper_max_attempts,
    backoff_seconds: float = settings.outscraper_retry_backoff_seconds,
) -> dict[str, Any]:
    safe_results_location = validate_results_location(results_location, endpoint)
    return _request_json(
        safe_results_location,
        api_key=api_key,
        timeout=timeout,
        max_attempts=max_attempts,
        backoff_seconds=backoff_seconds,
    )


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
    max_attempts: int = settings.outscraper_max_attempts,
    backoff_seconds: float = settings.outscraper_retry_backoff_seconds,
) -> dict[str, Any]:
    _validated_https_origin(endpoint, label="Outscraper endpoint")
    params = build_amazon_products_params(
        query,
        domain=domain,
        language=language,
        postal_code=postal_code,
        limit=limit,
        async_request=True,
    )
    return _request_json(
        endpoint,
        params=params,
        api_key=api_key,
        timeout=timeout,
        max_attempts=max_attempts,
        backoff_seconds=backoff_seconds,
    )


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
    max_attempts: int = settings.outscraper_max_attempts,
    backoff_seconds: float = settings.outscraper_retry_backoff_seconds,
) -> dict[str, Any]:
    if max_polls < 1:
        raise ValueError("max_polls must be at least 1")
    if poll_interval < 0:
        raise ValueError("poll_interval must not be negative")

    search_task = task_amazon_products_request(
        query,
        api_key=api_key,
        endpoint=endpoint,
        domain=domain,
        language=language,
        postal_code=postal_code,
        limit=limit,
        timeout=request_timeout,
        max_attempts=max_attempts,
        backoff_seconds=backoff_seconds,
    )
    _task_failure(search_task)

    results_location = search_task.get("results_location")
    if not results_location:
        state = task_state(search_task)
        if state == "success":
            return _validated_completed_result(search_task)
        if state == "pending":
            raise OutscraperResponseError(
                "Pending Outscraper response does not include results_location"
            )
        raise OutscraperResponseError(
            "Outscraper response has neither a result nor results_location"
        )
    if not isinstance(results_location, str):
        raise OutscraperResponseError("Outscraper results_location must be a string")

    safe_results_location = validate_results_location(results_location, endpoint)
    print(f"Request ID: {search_task.get('id')}")

    last_result: dict[str, Any] = search_task
    for poll_count in range(1, max_polls + 1):
        result = fetch_request_result(
            safe_results_location,
            api_key=api_key,
            endpoint=endpoint,
            timeout=request_timeout,
            max_attempts=max_attempts,
            backoff_seconds=backoff_seconds,
        )
        last_result = result
        state = task_state(result)
        print(f"Poll {poll_count}/{max_polls}: {result.get('status', 'unknown')}")

        if state == "failed":
            raise OutscraperTaskFailedError(_normalized_status(result), result)
        if state == "success":
            return _validated_completed_result(result)
        if state == "unknown":
            raise OutscraperResponseError(
                "Outscraper polling response has an unknown task status and no data"
            )
        if poll_count < max_polls:
            time.sleep(poll_interval)

    raise OutscraperTaskTimeoutError(max_polls, safe_results_location, last_result)


# OutscraperのAPIを呼び出し, 検索クエリJSONを渡し, 返り値をJSONに書き込む
def call_outscraper(query: str, cache_key: str) -> Path:
    api_key = settings.outscraper_api_key
    if not api_key:
        raise RuntimeError("OUTSCRAPER_API_KEY is not set. Set it in .env or shell environment.")

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
        max_attempts=settings.outscraper_max_attempts,
        backoff_seconds=settings.outscraper_retry_backoff_seconds,
    )

    output_path = settings.cache_dir / "outscraper" / "raw" / f"{cache_key}.json"
    write_json(output_path, data)
    print(f"Response JSON written to: {output_path}")
    return output_path
