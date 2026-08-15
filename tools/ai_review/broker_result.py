from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Any
from typing import Literal

from pydantic import ValidationError

from tools.ai_review.broker_entry import FIXED_MODEL
from tools.ai_review.broker_entry import MAX_RESPONSE_BYTES
from tools.ai_review.broker_entry import canonical_response_bytes
from tools.ai_review.codex_adapter import BrokerInferenceEvidence
from tools.ai_review.codex_adapter import MAX_ROLE_ATTEMPTS
from tools.ai_review.codex_adapter import ROLE_EFFORT
from tools.ai_review.codex_adapter import parse_codex_usage_jsonl
from tools.ai_review.models import ReviewReport


MAX_BROKER_RESULT_BYTES = MAX_RESPONSE_BYTES + 100_000
_SESSION_DOMAIN = b"amazon-explorer-broker-session-v1\0"


class BrokerResultError(ValueError):
    """Raised when a broker result cannot be safely bound to a review artifact."""


@dataclass(frozen=True)
class ParsedBrokerReview:
    review: ReviewReport
    inference: BrokerInferenceEvidence
    request_id: str
    response_id: str
    canonical_response_text: str


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BrokerResultError("broker result contains a duplicate JSON key")
        result[key] = value
    return result


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
        raise BrokerResultError("broker result is not canonical JSON") from exc


def _validated_identifier(value: object, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 256
        or any(ord(character) < 33 or ord(character) > 126 for character in value)
    ):
        raise BrokerResultError(f"broker {label} is missing or invalid")
    return value


def _extract_review_text(response: dict[str, Any]) -> str:
    if response.get("status") != "completed":
        raise BrokerResultError("Responses result must be completed")
    if response.get("model") != FIXED_MODEL:
        raise BrokerResultError("Responses result model does not match the approved model")
    if response.get("service_tier") != "default":
        raise BrokerResultError("Responses result service tier does not match standard pricing")
    if response.get("object") != "response":
        raise BrokerResultError("Responses result object type is invalid")
    output = response.get("output")
    if not isinstance(output, list) or not output:
        raise BrokerResultError("Responses result has no assistant message")
    messages: list[dict[str, Any]] = []
    for item in output:
        if not isinstance(item, dict):
            raise BrokerResultError("Responses output item is invalid")
        item_type = item.get("type")
        if item_type == "reasoning":
            continue
        if item_type != "message":
            raise BrokerResultError("Responses result contains a tool or unsupported output")
        messages.append(item)
    if len(messages) != 1:
        raise BrokerResultError("Responses result must contain exactly one assistant message")
    message = messages[0]
    if message.get("role") != "assistant" or message.get("status") != "completed":
        raise BrokerResultError("Responses assistant message is incomplete")
    content = message.get("content")
    if not isinstance(content, list) or len(content) != 1 or not isinstance(content[0], dict):
        raise BrokerResultError("Responses assistant message must contain one output_text item")
    item = content[0]
    if item.get("type") != "output_text" or not isinstance(item.get("text"), str):
        raise BrokerResultError("Responses assistant message must contain output_text")
    text = item["text"]
    if not text or "\x00" in text:
        raise BrokerResultError("Responses output_text is empty or invalid")
    return text


def _parse_review(text: str, *, role: Literal["reviewer", "adversary"]) -> ReviewReport:
    try:
        payload = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except BrokerResultError:
        raise
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise BrokerResultError("Responses output_text is not valid review JSON") from exc
    try:
        review = ReviewReport.model_validate(payload)
    except ValidationError as exc:
        raise BrokerResultError("Responses output_text does not satisfy ReviewReport") from exc
    if review.role != role:
        raise BrokerResultError("model-selected review role does not match the coordinator role")
    return review


def _coordinator_session_id(request_id: str, response_id: str, role: str) -> str:
    digest = hashlib.sha256()
    digest.update(_SESSION_DOMAIN)
    for value in (request_id, response_id, role):
        encoded = value.encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def parse_broker_review(
    raw: bytes,
    *,
    expected_request_sha256: str,
    expected_packet_sha256: str,
    role: Literal["reviewer", "adversary"],
    attempt: int,
) -> ParsedBrokerReview:
    """Validate a canonical broker envelope and replace model-claimed provenance."""

    if role not in ROLE_EFFORT:
        raise BrokerResultError("broker review role is not approved")
    if not raw or len(raw) > MAX_BROKER_RESULT_BYTES or not raw.endswith(b"\n"):
        raise BrokerResultError("broker result is empty, oversized, or not newline terminated")
    if not _is_sha256(expected_request_sha256) or not _is_sha256(expected_packet_sha256):
        raise BrokerResultError("expected request or packet SHA-256 is invalid")
    if (
        isinstance(attempt, bool)
        or not isinstance(attempt, int)
        or not 1 <= attempt <= MAX_ROLE_ATTEMPTS
    ):
        raise BrokerResultError("broker attempt is outside the approved retry limit")
    try:
        payload = json.loads(
            raw[:-1].decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except BrokerResultError:
        raise
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise BrokerResultError("broker result is not valid UTF-8 JSON") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version",
        "request_sha256",
        "response_sha256",
        "request_id",
        "response",
    }:
        raise BrokerResultError("broker result contains missing or unknown fields")
    if payload["schema_version"] != "1.0":
        raise BrokerResultError("broker result schema version is unsupported")
    if _canonical_json_bytes(payload) + b"\n" != raw:
        raise BrokerResultError("broker result is not canonical JSON")
    request_sha256 = payload["request_sha256"]
    if not _is_sha256(request_sha256) or not hmac.compare_digest(
        request_sha256, expected_request_sha256
    ):
        raise BrokerResultError("broker request SHA-256 does not match the approved request")
    response = payload["response"]
    if not isinstance(response, dict):
        raise BrokerResultError("broker response must be a JSON object")
    canonical_response = canonical_response_bytes(response)
    actual_response_sha256 = hashlib.sha256(canonical_response).hexdigest()
    if not isinstance(payload["response_sha256"], str) or not hmac.compare_digest(
        payload["response_sha256"], actual_response_sha256
    ):
        raise BrokerResultError("broker response SHA-256 does not match its content")
    request_id = _validated_identifier(payload["request_id"], label="request id")
    response_id = _validated_identifier(response.get("id"), label="response id")
    review_text = _extract_review_text(response)
    model_review = _parse_review(review_text, role=role)
    session_id = _coordinator_session_id(request_id, response_id, role)
    review = model_review.model_copy(
        update={
            "reviewer_id": f"openai-{FIXED_MODEL}-{role}",
            "session_id": session_id,
        }
    )
    try:
        usage = parse_codex_usage_jsonl(raw.decode("utf-8", errors="strict"))
    except ValueError as exc:
        raise BrokerResultError("broker response usage is outside approved bounds") from exc
    inference = BrokerInferenceEvidence(
        packet_sha256=expected_packet_sha256,
        request_sha256=expected_request_sha256,
        response_sha256=actual_response_sha256,
        usage_jsonl_sha256=usage.usage_jsonl_sha256,
        model=FIXED_MODEL,
        reasoning_effort=ROLE_EFFORT[role],  # type: ignore[arg-type]
        role=role,
        attempt=attempt,
        usage=usage,
    )
    return ParsedBrokerReview(
        review=review,
        inference=inference,
        request_id=request_id,
        response_id=response_id,
        canonical_response_text=canonical_response.decode("utf-8", errors="strict"),
    )
