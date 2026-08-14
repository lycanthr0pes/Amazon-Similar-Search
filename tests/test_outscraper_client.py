import json
from unittest.mock import patch

import pytest
import requests
from pydantic import ValidationError

from src.clients import outscraper_client
from src.config import Settings
from src.exceptions import (
    OutscraperRequestError,
    OutscraperResponseError,
    OutscraperSecurityError,
    OutscraperTaskFailedError,
    OutscraperTaskTimeoutError,
)

ENDPOINT = "https://api.outscraper.cloud/amazon-products"
RESULTS_LOCATION = "https://api.outscraper.cloud/requests/request-1"


def make_response(status_code: int, payload: object) -> requests.Response:
    response = requests.Response()
    response.status_code = status_code
    response.url = ENDPOINT
    response.encoding = "utf-8"
    response._content = json.dumps(payload).encode()
    return response


def test_settings_use_bounded_outscraper_defaults() -> None:
    configured = Settings(_env_file=None)

    assert configured.outscraper_request_timeout_seconds == 30
    assert configured.outscraper_max_polls == 50
    assert configured.outscraper_max_attempts == 3
    assert configured.outscraper_retry_backoff_seconds == 1.0


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("outscraper_request_timeout_seconds", 0),
        ("outscraper_max_polls", 0),
        ("outscraper_max_attempts", 0),
        ("outscraper_retry_backoff_seconds", -0.1),
        ("title_score_weight", -0.1),
    ],
)
def test_settings_reject_invalid_positive_values(field: str, value: float) -> None:
    with pytest.raises(ValidationError):
        Settings(_env_file=None, **{field: value})


def test_settings_require_score_weights_to_total_one() -> None:
    with pytest.raises(ValidationError, match="must add up to 1.0"):
        Settings(_env_file=None, title_score_weight=0.4)


def test_settings_require_at_least_one_positive_condition_weight() -> None:
    with pytest.raises(ValidationError, match="at least one condition term weight"):
        Settings(
            _env_file=None,
            required_term_weight=0,
            color_term_weight=0,
            feature_term_weight=0,
            preferred_term_weight=0,
            related_term_weight=0,
        )


def test_task_state_distinguishes_empty_success_from_failure() -> None:
    assert outscraper_client.task_state({"status": "success", "data": []}) == "success"
    assert outscraper_client.task_state({"data": []}) == "success"
    assert outscraper_client.task_state({"status": "pending"}) == "pending"
    assert outscraper_client.task_state({"status": "failed", "data": []}) == "failed"


def test_fetch_returns_successful_zero_result_response() -> None:
    expected = {"status": "success", "data": []}
    with patch.object(
        outscraper_client,
        "task_amazon_products_request",
        return_value=expected,
    ):
        result = outscraper_client.fetch_amazon_products(
            "mouse",
            api_key="secret",
            poll_interval=0,
        )

    assert result == expected


@pytest.mark.parametrize(
    "response",
    [
        {"status": "success"},
        {"status": "success", "data": {}},
    ],
)
def test_fetch_rejects_completed_response_without_product_list(response: dict) -> None:
    with (
        patch.object(
            outscraper_client,
            "task_amazon_products_request",
            return_value=response,
        ),
        pytest.raises(OutscraperResponseError, match="data"),
    ):
        outscraper_client.fetch_amazon_products("mouse", api_key="secret")


def test_fetch_raises_dedicated_exception_for_failed_initial_task() -> None:
    failed = {"status": "error", "description": "quota exhausted"}
    with (
        patch.object(
            outscraper_client,
            "task_amazon_products_request",
            return_value=failed,
        ),
        pytest.raises(OutscraperTaskFailedError, match="quota exhausted") as exc_info,
    ):
        outscraper_client.fetch_amazon_products("mouse", api_key="secret")

    assert exc_info.value.status == "error"
    assert exc_info.value.response_data == failed


def test_fetch_raises_dedicated_exception_for_failed_polled_task() -> None:
    search_task = {
        "id": "request-1",
        "status": "pending",
        "results_location": RESULTS_LOCATION,
    }
    failed = {"status": "FAILED", "message": "provider rejected request"}
    with (
        patch.object(
            outscraper_client,
            "task_amazon_products_request",
            return_value=search_task,
        ),
        patch.object(outscraper_client, "fetch_request_result", return_value=failed),
        pytest.raises(OutscraperTaskFailedError, match="provider rejected request"),
    ):
        outscraper_client.fetch_amazon_products(
            "mouse",
            api_key="secret",
            poll_interval=0,
        )


def test_fetch_raises_timeout_after_last_pending_poll_without_extra_sleep() -> None:
    search_task = {
        "id": "request-1",
        "status": "pending",
        "results_location": RESULTS_LOCATION,
    }
    pending = {"status": "processing"}
    with (
        patch.object(
            outscraper_client,
            "task_amazon_products_request",
            return_value=search_task,
        ),
        patch.object(outscraper_client, "fetch_request_result", return_value=pending) as fetch,
        patch.object(outscraper_client.time, "sleep") as sleep,
        pytest.raises(OutscraperTaskTimeoutError) as exc_info,
    ):
        outscraper_client.fetch_amazon_products(
            "mouse",
            api_key="secret",
            poll_interval=2,
            max_polls=3,
        )

    assert fetch.call_count == 3
    assert sleep.call_count == 2
    assert exc_info.value.max_polls == 3
    assert exc_info.value.last_response == pending


def test_pending_initial_response_requires_results_location() -> None:
    with (
        patch.object(
            outscraper_client,
            "task_amazon_products_request",
            return_value={"status": "pending"},
        ),
        pytest.raises(OutscraperResponseError, match="results_location"),
    ):
        outscraper_client.fetch_amazon_products("mouse", api_key="secret")


@pytest.mark.parametrize(
    "results_location",
    [
        "http://api.outscraper.cloud/requests/request-1",
        "https://evil.example/requests/request-1",
        "https://api.outscraper.cloud.evil.example/requests/request-1",
        "https://api.outscraper.cloud:444/requests/request-1",
    ],
)
def test_fetch_result_rejects_unsafe_location_before_sending_api_key(
    results_location: str,
) -> None:
    with (
        patch.object(outscraper_client.requests, "get") as get,
        pytest.raises(OutscraperSecurityError),
    ):
        outscraper_client.fetch_request_result(
            results_location,
            api_key="secret",
            endpoint=ENDPOINT,
        )

    get.assert_not_called()


def test_fetch_result_sends_api_key_only_to_validated_same_origin() -> None:
    response = make_response(200, {"status": "success", "data": []})
    with patch.object(outscraper_client.requests, "get", return_value=response) as get:
        result = outscraper_client.fetch_request_result(
            RESULTS_LOCATION,
            api_key="secret",
            endpoint=ENDPOINT,
        )

    assert result == {"status": "success", "data": []}
    assert get.call_args.kwargs["headers"] == {"X-API-KEY": "secret"}
    assert get.call_args.kwargs["allow_redirects"] is False


def test_transient_http_failures_retry_with_exponential_backoff() -> None:
    responses = [
        make_response(500, {"status": "error"}),
        make_response(429, {"status": "error"}),
        make_response(200, {"status": "pending", "results_location": RESULTS_LOCATION}),
    ]
    with (
        patch.object(outscraper_client.requests, "get", side_effect=responses) as get,
        patch.object(outscraper_client.time, "sleep") as sleep,
    ):
        result = outscraper_client.task_amazon_products_request(
            "mouse",
            api_key="secret",
            endpoint=ENDPOINT,
            max_attempts=3,
            backoff_seconds=0.5,
        )

    assert result["status"] == "pending"
    assert get.call_count == 3
    assert [call.args[0] for call in sleep.call_args_list] == [0.5, 1.0]


@pytest.mark.parametrize("error_type", [requests.Timeout, requests.ConnectionError])
def test_transient_transport_errors_retry_then_wrap_final_error(
    error_type: type[requests.RequestException],
) -> None:
    with (
        patch.object(
            outscraper_client.requests,
            "get",
            side_effect=error_type("transport failed"),
        ) as get,
        patch.object(outscraper_client.time, "sleep") as sleep,
        pytest.raises(OutscraperRequestError) as exc_info,
    ):
        outscraper_client.task_amazon_products_request(
            "mouse",
            api_key="secret",
            endpoint=ENDPOINT,
            max_attempts=2,
            backoff_seconds=0.25,
        )

    assert isinstance(exc_info.value.__cause__, error_type)
    assert get.call_count == 2
    sleep.assert_called_once_with(0.25)


@pytest.mark.parametrize("status_code", [400, 401, 403, 404])
def test_non_transient_client_errors_fail_without_retry(status_code: int) -> None:
    response = make_response(status_code, {"status": "error"})
    with (
        patch.object(outscraper_client.requests, "get", return_value=response) as get,
        patch.object(outscraper_client.time, "sleep") as sleep,
        pytest.raises(OutscraperRequestError) as exc_info,
    ):
        outscraper_client.task_amazon_products_request(
            "mouse",
            api_key="secret",
            endpoint=ENDPOINT,
            max_attempts=3,
        )

    get.assert_called_once()
    sleep.assert_not_called()
    assert isinstance(exc_info.value.__cause__, requests.HTTPError)


def test_redirect_is_rejected_instead_of_forwarding_api_key() -> None:
    response = make_response(302, {})
    response.headers["Location"] = "https://evil.example/collect"
    with (
        patch.object(outscraper_client.requests, "get", return_value=response) as get,
        pytest.raises(OutscraperSecurityError, match="redirects"),
    ):
        outscraper_client.task_amazon_products_request(
            "mouse",
            api_key="secret",
            endpoint=ENDPOINT,
        )

    get.assert_called_once()
