from __future__ import annotations

import hashlib
import json

import pytest
from pydantic import ValidationError

from tools.ai_review.broker_entry import BrokerResult
from tools.ai_review.broker_entry import canonical_response_bytes
from tools.ai_review.broker_entry import canonical_result_bytes
from tools.ai_review.broker_result import BrokerResultError
from tools.ai_review.broker_result import parse_broker_review


REQUEST_SHA = "1" * 64
PACKET_SHA = "2" * 64


def review_payload(role: str = "reviewer") -> dict:
    return {
        "schema_version": "1.0",
        "task_id": "TASK-TEST",
        "task_sha256": "3" * 64,
        "role": role,
        "reviewer_id": "model-self-report",
        "session_id": "model-self-report",
        "prompt_sha256": "4" * 64,
        "decision": "accept",
        "base_sha": "5" * 40,
        "head_sha": "6" * 40,
        "patch_sha256": "7" * 64,
        "summary": "問題なし",
        "findings": [],
        "unverified": [],
        "external_calls": False,
    }


def api_response(*, role: str = "reviewer", output_type: str = "message") -> dict:
    review_text = json.dumps(review_payload(role), ensure_ascii=False, separators=(",", ":"))
    output = {
        "type": output_type,
        "role": "assistant",
        "status": "completed",
        "content": [{"type": "output_text", "text": review_text}],
    }
    return {
        "id": f"resp_{role}",
        "object": "response",
        "status": "completed",
        "model": "gpt-5.6-sol",
        "service_tier": "default",
        "output": [output],
        "usage": {
            "input_tokens": 100,
            "output_tokens": 20,
            "input_tokens_details": {"cached_tokens": 50},
            "output_tokens_details": {"reasoning_tokens": 5},
            "total_tokens": 120,
        },
    }


def envelope_bytes(response: dict | None = None, *, request_sha: str = REQUEST_SHA) -> bytes:
    response = api_response() if response is None else response
    return canonical_result_bytes(
        BrokerResult(
            schema_version="1.0",
            request_sha256=request_sha,
            response_sha256=hashlib.sha256(canonical_response_bytes(response)).hexdigest(),
            request_id="req_reviewer_unique",
            response=response,
        )
    )


def test_parse_broker_review_binds_response_usage_and_coordinator_provenance() -> None:
    parsed = parse_broker_review(
        envelope_bytes(),
        expected_request_sha256=REQUEST_SHA,
        expected_packet_sha256=PACKET_SHA,
        role="reviewer",
        attempt=1,
    )

    assert parsed.review.role == "reviewer"
    assert parsed.review.reviewer_id == "openai-gpt-5.6-sol-reviewer"
    assert parsed.review.session_id != "model-self-report"
    assert len(parsed.review.session_id) == 64
    assert parsed.inference.packet_sha256 == PACKET_SHA
    assert parsed.inference.request_sha256 == REQUEST_SHA
    assert (
        parsed.inference.response_sha256
        == hashlib.sha256(canonical_response_bytes(api_response())).hexdigest()
    )
    assert parsed.inference.model == "gpt-5.6-sol"
    assert parsed.inference.reasoning_effort == "high"
    assert parsed.inference.usage.cached_input_tokens == 50


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda value: value.update(status="failed"), "completed"),
        (lambda value: value.update(model="other"), "model"),
        (lambda value: value["output"].append({"type": "function_call"}), "tool|message"),
        (lambda value: value["output"][0].update(type="function_call"), "tool|message"),
        (
            lambda value: value["output"][0]["content"].append(
                {"type": "refusal", "refusal": "no"}
            ),
            "output_text",
        ),
    ],
)
def test_parse_rejects_incomplete_wrong_model_and_tool_or_refusal_output(mutation, message) -> None:
    response = api_response()
    mutation(response)

    with pytest.raises(BrokerResultError, match=message):
        parse_broker_review(
            envelope_bytes(response),
            expected_request_sha256=REQUEST_SHA,
            expected_packet_sha256=PACKET_SHA,
            role="reviewer",
            attempt=1,
        )


def test_parse_rejects_request_response_hash_tampering_and_noncanonical_envelope() -> None:
    with pytest.raises(BrokerResultError, match="request SHA"):
        parse_broker_review(
            envelope_bytes(request_sha="0" * 64),
            expected_request_sha256=REQUEST_SHA,
            expected_packet_sha256=PACKET_SHA,
            role="reviewer",
            attempt=1,
        )

    payload = json.loads(envelope_bytes())
    payload["response"]["id"] = "resp_tampered"
    tampered = (
        json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        + b"\n"
    )
    with pytest.raises(BrokerResultError, match="response SHA"):
        parse_broker_review(
            tampered,
            expected_request_sha256=REQUEST_SHA,
            expected_packet_sha256=PACKET_SHA,
            role="reviewer",
            attempt=1,
        )

    with pytest.raises(BrokerResultError, match="canonical"):
        parse_broker_review(
            b"  " + envelope_bytes(),
            expected_request_sha256=REQUEST_SHA,
            expected_packet_sha256=PACKET_SHA,
            role="reviewer",
            attempt=1,
        )


def test_model_cannot_choose_role_or_provenance() -> None:
    response = api_response(role="adversary")
    with pytest.raises(BrokerResultError, match="role"):
        parse_broker_review(
            envelope_bytes(response),
            expected_request_sha256=REQUEST_SHA,
            expected_packet_sha256=PACKET_SHA,
            role="reviewer",
            attempt=1,
        )


def test_parse_rejects_usage_output_above_the_reserved_maximum() -> None:
    response = api_response()
    response["usage"]["output_tokens"] = 12_001
    response["usage"]["total_tokens"] = 12_101

    with pytest.raises(BrokerResultError, match="usage.*approved bounds"):
        parse_broker_review(
            envelope_bytes(response),
            expected_request_sha256=REQUEST_SHA,
            expected_packet_sha256=PACKET_SHA,
            role="reviewer",
            attempt=1,
        )


def test_review_schema_still_fails_closed_before_provenance_is_overwritten() -> None:
    response = api_response()
    text = json.loads(response["output"][0]["content"][0]["text"])
    text["external_calls"] = "no"
    response["output"][0]["content"][0]["text"] = json.dumps(text)

    with pytest.raises((BrokerResultError, ValidationError)):
        parse_broker_review(
            envelope_bytes(response),
            expected_request_sha256=REQUEST_SHA,
            expected_packet_sha256=PACKET_SHA,
            role="reviewer",
            attempt=1,
        )
