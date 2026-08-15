from __future__ import annotations

import hashlib
import io
import json

import pytest

from tools.ai_review import broker_entry


def request_payload() -> dict:
    return {
        "model": "gpt-5.6-sol",
        "input": [
            {
                "role": "user",
                "content": [{"type": "input_text", "text": "review packet"}],
            }
        ],
        "reasoning": {"effort": "high", "summary": "none"},
        "text": {
            "verbosity": "low",
            "format": {
                "type": "json_schema",
                "name": "review_report",
                "strict": True,
                "schema": {"type": "object", "additionalProperties": False},
            },
        },
        "tools": [],
        "store": False,
        "service_tier": "default",
        "max_output_tokens": 12_000,
    }


class FakeResponse:
    status = 200

    def __init__(self, body: bytes, *, status: int = 200, request_id: str = "req_test") -> None:
        self._body = body
        self.status = status
        self._request_id = request_id

    def getheader(self, name: str, default=None):
        if name.casefold() == "content-type":
            return "application/json"
        if name.casefold() == "x-request-id":
            return self._request_id
        return default

    def read(self, amount: int) -> bytes:
        return self._body[:amount]


class FakeConnection:
    def __init__(self, response: FakeResponse) -> None:
        self.response = response
        self.request_args = None
        self.closed = False

    def request(self, *args, **kwargs) -> None:
        self.request_args = (args, kwargs)

    def getresponse(self) -> FakeResponse:
        return self.response

    def close(self) -> None:
        self.closed = True


def execute_environment() -> dict[str, str]:
    return {
        "OPENAI_API_KEY": "test-key-never-log",
        "AI_REVIEW_EXECUTE": "1",
        "AI_REVIEW_EXTERNAL_AI": "1",
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
    }


def test_submit_uses_only_fixed_https_endpoint_and_returns_bounded_digest(monkeypatch) -> None:
    response_body = json.dumps({"id": "resp_test", "output": []}).encode()
    connection = FakeConnection(FakeResponse(response_body))
    observed = {}

    def fake_connection(context):
        observed.update(context=context)
        return connection

    raw_request = broker_entry.canonical_request_bytes(request_payload())

    # The coordinator descriptor sends exactly one framing newline on stdin.
    result = broker_entry.submit_request(
        raw_request + b"\n",
        environment=execute_environment(),
        connection_factory=fake_connection,
    )

    assert observed["context"].check_hostname is True
    assert observed["context"].verify_mode == broker_entry.ssl.CERT_REQUIRED
    args, kwargs = connection.request_args
    assert args[:2] == ("POST", "/v1/responses")
    assert kwargs["headers"]["Authorization"] == "Bearer test-key-never-log"
    assert kwargs["body"] == raw_request
    assert connection.closed is True
    assert result.request_sha256 == hashlib.sha256(raw_request).hexdigest()
    assert (
        result.response_sha256
        == hashlib.sha256(
            broker_entry.canonical_response_bytes({"id": "resp_test", "output": []})
        ).hexdigest()
    )
    assert result.request_id == "req_test"
    assert result.response == {"id": "resp_test", "output": []}
    assert "test-key-never-log" not in broker_entry.canonical_result_bytes(result).decode()


@pytest.mark.parametrize(
    "environment",
    [
        {},
        {"OPENAI_API_KEY": "key", "AI_REVIEW_EXECUTE": "1"},
        {"OPENAI_API_KEY": "key", "AI_REVIEW_EXTERNAL_AI": "1"},
        {
            **execute_environment(),
            "HTTPS_PROXY": "https://attacker.invalid",
        },
        {
            **execute_environment(),
            "SSL_CERT_FILE": "/untrusted/ca.pem",
        },
        {
            **execute_environment(),
            "LD_PRELOAD": "/untrusted/library.so",
        },
    ],
)
def test_submit_fails_before_network_without_double_opt_in_or_with_env_injection(
    monkeypatch, environment
) -> None:
    with pytest.raises(broker_entry.BrokerError):
        broker_entry.submit_request(
            broker_entry.canonical_request_bytes(request_payload()),
            environment=environment,
            connection_factory=lambda *_args: pytest.fail("network must not start"),
        )


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.update(model="other"), "model"),
        (lambda value: value.update(tools=[{"type": "web_search"}]), "tools"),
        (lambda value: value.update(store=True), "store"),
        (lambda value: value.update(service_tier="priority"), "service tier"),
        (lambda value: value.update(max_output_tokens=12_001), "output token"),
        (lambda value: value["reasoning"].update(effort="max"), "reasoning"),
        (lambda value: value["text"].update(verbosity="high"), "verbosity"),
    ],
)
def test_request_contract_rejects_unapproved_model_tools_storage_and_budget(mutation, message):
    payload = request_payload()
    mutation(payload)

    with pytest.raises(broker_entry.BrokerError, match=message):
        broker_entry.canonical_request_bytes(payload)


@pytest.mark.parametrize("status", [301, 307, 400, 429, 500])
def test_http_redirects_and_errors_are_generic_and_never_return_body(monkeypatch, status) -> None:
    secret_body = b'{"error":"secret-request-content"}'
    connection = FakeConnection(FakeResponse(secret_body, status=status))
    with pytest.raises(broker_entry.BrokerError) as captured:
        broker_entry.submit_request(
            broker_entry.canonical_request_bytes(request_payload()),
            environment=execute_environment(),
            connection_factory=lambda *_args: connection,
        )

    assert "secret-request-content" not in str(captured.value)


def test_broker_tls_targets_openai_while_tcp_connects_only_to_the_internal_gateway(
    monkeypatch,
) -> None:
    observed: dict[str, object] = {}

    class FakeSocket:
        def close(self) -> None:
            observed["raw_closed"] = True

    class FakeContext:
        def wrap_socket(self, raw_socket, *, server_hostname):
            observed.update(raw_socket=raw_socket, server_hostname=server_hostname)
            return object()

    raw_socket = FakeSocket()

    def fake_create_connection(address, *, timeout):
        observed.update(address=address, timeout=timeout)
        return raw_socket

    monkeypatch.setattr(broker_entry.socket, "create_connection", fake_create_connection)
    connection = broker_entry._FixedGatewayHTTPSConnection(
        broker_entry.API_HOST,
        broker_entry.API_PORT,
        timeout=broker_entry.REQUEST_TIMEOUT_SECONDS,
        context=FakeContext(),
    )

    connection.connect()

    assert observed["address"] == (
        broker_entry.EGRESS_GATEWAY_HOST,
        broker_entry.EGRESS_GATEWAY_PORT,
    )
    assert observed["server_hostname"] == broker_entry.API_HOST
    assert observed.get("raw_closed") is None


def test_main_never_prints_api_key_on_validation_error(monkeypatch, capsys) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "api-key-must-not-print")
    monkeypatch.delenv("AI_REVIEW_EXECUTE", raising=False)
    monkeypatch.delenv("AI_REVIEW_EXTERNAL_AI", raising=False)
    monkeypatch.setattr(
        broker_entry.sys,
        "stdin",
        io.TextIOWrapper(io.BytesIO(broker_entry.canonical_request_bytes(request_payload()))),
    )

    assert broker_entry.main() == 2
    captured = capsys.readouterr()
    assert "api-key-must-not-print" not in captured.err
    assert "review packet" not in captured.err
