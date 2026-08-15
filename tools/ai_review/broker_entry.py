#!/usr/local/bin/python -I
"""Minimal packet-only OpenAI Responses broker for a pinned isolated container.

This module never receives a candidate path and never executes candidate code. Production use
must run it in the read-only, capability-free broker container constructed by the coordinator.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import socket
import ssl
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


API_HOST = "api.openai.com"
API_PORT = 443
API_PATH = "/v1/responses"
EGRESS_GATEWAY_HOST = "ai-review-egress-gateway"
EGRESS_GATEWAY_PORT = 8443
FIXED_MODEL = "gpt-5.6-sol"
ALLOWED_REASONING_EFFORTS = {"high", "xhigh"}
MAX_OUTPUT_TOKENS = 12_000
MAX_REQUEST_BYTES = 2_000_000
MAX_RESPONSE_BYTES = 4_000_000
REQUEST_TIMEOUT_SECONDS = 180

_REQUEST_KEYS = {
    "model",
    "input",
    "reasoning",
    "text",
    "tools",
    "store",
    "service_tier",
    "max_output_tokens",
}
_FORBIDDEN_ENV_NAMES = {
    "all_proxy",
    "aws_ca_bundle",
    "curl_ca_bundle",
    "dyld_insert_libraries",
    "http_proxy",
    "https_proxy",
    "ld_audit",
    "ld_library_path",
    "ld_preload",
    "netrc",
    "no_proxy",
    "openai_base_url",
    "pythonhome",
    "pythoninspect",
    "pythonpath",
    "pythonstartup",
    "requests_ca_bundle",
    "ssl_cert_dir",
    "ssl_cert_file",
    "sslkeylogfile",
}


class BrokerError(RuntimeError):
    """A fail-closed broker error whose message contains no request or credential content."""


@dataclass(frozen=True)
class BrokerResult:
    schema_version: str
    request_sha256: str
    response_sha256: str
    request_id: str
    response: dict[str, Any]


class _FixedGatewayHTTPSConnection(http.client.HTTPSConnection):
    """Keep API TLS end-to-end while the only TCP route is the fixed internal gateway."""

    def connect(self) -> None:
        raw_socket: socket.socket | None = None
        try:
            raw_socket = socket.create_connection(
                (EGRESS_GATEWAY_HOST, EGRESS_GATEWAY_PORT),
                timeout=self.timeout,
            )
            self.sock = self._context.wrap_socket(raw_socket, server_hostname=API_HOST)
            raw_socket = None
        finally:
            if raw_socket is not None:
                raw_socket.close()


def _gateway_connection(context: ssl.SSLContext) -> http.client.HTTPSConnection:
    return _FixedGatewayHTTPSConnection(
        API_HOST,
        API_PORT,
        timeout=REQUEST_TIMEOUT_SECONDS,
        context=context,
    )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise BrokerError("JSON contains a duplicate key")
        value[key] = item
    return value


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise BrokerError("request contains a non-canonical JSON value") from exc


def _validate_request(payload: object) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != _REQUEST_KEYS:
        raise BrokerError("request contains missing or unknown fields")
    if payload["model"] != FIXED_MODEL:
        raise BrokerError("request model is not approved")
    if payload["tools"] != []:
        raise BrokerError("request tools must be empty")
    if payload["store"] is not False:
        raise BrokerError("request store must be false")
    if payload["service_tier"] != "default":
        raise BrokerError("request service tier must use standard pricing")
    output_tokens = payload["max_output_tokens"]
    if (
        isinstance(output_tokens, bool)
        or not isinstance(output_tokens, int)
        or not 1 <= output_tokens <= MAX_OUTPUT_TOKENS
    ):
        raise BrokerError("request output token budget exceeds the approved limit")

    reasoning = payload["reasoning"]
    if (
        not isinstance(reasoning, dict)
        or set(reasoning) != {"effort", "summary"}
        or reasoning["effort"] not in ALLOWED_REASONING_EFFORTS
        or reasoning["summary"] != "none"
    ):
        raise BrokerError("request reasoning configuration is not approved")

    text = payload["text"]
    if not isinstance(text, dict) or set(text) != {"verbosity", "format"}:
        raise BrokerError("request text configuration is invalid")
    if text["verbosity"] != "low":
        raise BrokerError("request verbosity must be low")
    output_format = text["format"]
    if (
        not isinstance(output_format, dict)
        or set(output_format) != {"type", "name", "strict", "schema"}
        or output_format["type"] != "json_schema"
        or output_format["name"] != "review_report"
        or output_format["strict"] is not True
        or not isinstance(output_format["schema"], dict)
    ):
        raise BrokerError("request output schema contract is invalid")

    inputs = payload["input"]
    if not isinstance(inputs, list) or len(inputs) != 1 or not isinstance(inputs[0], dict):
        raise BrokerError("request must contain exactly one text-only user input")
    message = inputs[0]
    if set(message) != {"role", "content"} or message["role"] != "user":
        raise BrokerError("request input role is invalid")
    content = message["content"]
    if not isinstance(content, list) or len(content) != 1 or not isinstance(content[0], dict):
        raise BrokerError("request must contain exactly one text input part")
    part = content[0]
    if (
        set(part) != {"type", "text"}
        or part["type"] != "input_text"
        or not isinstance(part["text"], str)
        or not part["text"]
        or "\x00" in part["text"]
    ):
        raise BrokerError("request content must be non-empty text only")
    return payload


def canonical_request_bytes(payload: object) -> bytes:
    validated = _validate_request(payload)
    raw = _canonical_json_bytes(validated)
    if len(raw) > MAX_REQUEST_BYTES:
        raise BrokerError("request exceeds the byte limit")
    return raw


def _parse_canonical_request(raw: bytes) -> bytes:
    if raw.endswith(b"\n"):
        if raw.endswith((b"\n\n", b"\r\n")):
            raise BrokerError("request framing must contain exactly one LF byte")
        raw = raw[:-1]
    if not raw or len(raw) > MAX_REQUEST_BYTES:
        raise BrokerError("request is empty or exceeds the byte limit")
    try:
        payload = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except BrokerError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise BrokerError("request is not valid UTF-8 JSON") from exc
    canonical = canonical_request_bytes(payload)
    if canonical != raw:
        raise BrokerError("request bytes are not in canonical form")
    return canonical


def _validated_environment(environment: Mapping[str, str]) -> str:
    lowered = {name.casefold() for name in environment}
    forbidden = sorted(lowered & _FORBIDDEN_ENV_NAMES)
    if forbidden:
        raise BrokerError("broker environment contains a forbidden override")
    if (
        environment.get("AI_REVIEW_EXECUTE") != "1"
        or environment.get("AI_REVIEW_EXTERNAL_AI") != "1"
    ):
        raise BrokerError("external AI requires two explicit execution opt-ins")
    api_key = environment.get("OPENAI_API_KEY", "")
    if (
        not api_key
        or len(api_key) > 512
        or any(ord(character) < 33 or ord(character) > 126 for character in api_key)
    ):
        raise BrokerError("OPENAI_API_KEY is missing or invalid")
    return api_key


def _parse_response(raw: bytes) -> dict[str, Any]:
    if not raw or len(raw) > MAX_RESPONSE_BYTES:
        raise BrokerError("Responses API body is empty or exceeds the byte limit")
    try:
        payload = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except BrokerError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise BrokerError("Responses API returned invalid JSON") from exc
    if not isinstance(payload, dict):
        raise BrokerError("Responses API returned a non-object JSON body")
    return payload


def canonical_response_bytes(response: dict[str, Any]) -> bytes:
    """Canonicalize parsed response content so the exported digest is independently checkable."""

    return _canonical_json_bytes(response)


def submit_request(
    raw_request: bytes,
    *,
    environment: Mapping[str, str] = os.environ,
    connection_factory=_gateway_connection,
) -> BrokerResult:
    """Submit one validated request; redirects, proxies, tools, and custom endpoints are absent."""

    canonical_request = _parse_canonical_request(raw_request)
    api_key = _validated_environment(environment)
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    connection: http.client.HTTPSConnection | None = None
    try:
        connection = connection_factory(context)
        connection.request(
            "POST",
            API_PATH,
            body=canonical_request,
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "amazon-explorer-attested-review-broker/1.0",
            },
        )
        response = connection.getresponse()
        if 300 <= response.status < 400:
            raise BrokerError("Responses API redirects are forbidden")
        if response.status != 200:
            raise BrokerError(f"Responses API returned HTTP status {response.status}")
        content_type = response.getheader("Content-Type", "")
        if not isinstance(content_type, str) or not content_type.casefold().startswith(
            "application/json"
        ):
            raise BrokerError("Responses API returned an unexpected content type")
        raw_response = response.read(MAX_RESPONSE_BYTES + 1)
        parsed_response = _parse_response(raw_response)
        request_id = response.getheader("x-request-id", "")
        if (
            not isinstance(request_id, str)
            or not 1 <= len(request_id) <= 256
            or any(ord(character) < 33 or ord(character) > 126 for character in request_id)
        ):
            raise BrokerError("Responses API request id is missing or invalid")
        return BrokerResult(
            schema_version="1.0",
            request_sha256=hashlib.sha256(canonical_request).hexdigest(),
            response_sha256=hashlib.sha256(canonical_response_bytes(parsed_response)).hexdigest(),
            request_id=request_id,
            response=parsed_response,
        )
    except BrokerError:
        raise
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        raise BrokerError("Responses API transport failed") from exc
    finally:
        if connection is not None:
            connection.close()


def canonical_result_bytes(result: BrokerResult) -> bytes:
    return (
        _canonical_json_bytes(
            {
                "schema_version": result.schema_version,
                "request_sha256": result.request_sha256,
                "response_sha256": result.response_sha256,
                "request_id": result.request_id,
                "response": result.response,
            }
        )
        + b"\n"
    )


def main() -> int:
    try:
        raw_request = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
        result = submit_request(raw_request)
        sys.stdout.buffer.write(canonical_result_bytes(result))
        sys.stdout.buffer.flush()
        return 0
    except BrokerError as exc:
        print(f"ai-review-broker: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
