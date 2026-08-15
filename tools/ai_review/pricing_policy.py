"""Pinned GPT-5.6 Sol pricing contract and conservative cost reservation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any


MICROUSD_PER_USD = 1_000_000
TOKENS_PER_RATE_UNIT = 1_000_000
MULTIPLIER_SCALE = 1_000_000
MAX_REVIEW_ATTEMPTS_PER_PACKET = 4
MAX_REVIEW_INPUT_TOKENS = 260_000
MAX_REVIEW_OUTPUT_TOKENS = 12_000
DEFAULT_PACKET_RESERVED_TOKENS = 544_000
ABSOLUTE_PACKET_RESERVED_TOKENS = 1_088_000

EXPECTED_OPENAI_PRICING_POLICY: dict[str, Any] = {
    "cache_write_input_microusd_per_million_tokens": 6_250_000,
    "cached_input_microusd_per_million_tokens": 500_000,
    "currency": "USD",
    "input_microusd_per_million_tokens": 5_000_000,
    "long_context_input_multiplier_ppm": 2_000_000,
    "long_context_output_multiplier_ppm": 1_500_000,
    "long_context_threshold_input_tokens": 272_000,
    "model": "gpt-5.6-sol",
    "output_microusd_per_million_tokens": 30_000_000,
    "price_version": "2026-08-15",
    "schema_version": "1.0",
    "service_tier": "default",
}


class PricingPolicyError(ValueError):
    """Raised when pricing bytes or a requested monetary budget are not approved."""


@dataclass(frozen=True)
class OpenAIPricingPolicy:
    schema_version: str
    price_version: str
    currency: str
    model: str
    service_tier: str
    input_microusd_per_million_tokens: int
    cached_input_microusd_per_million_tokens: int
    cache_write_input_microusd_per_million_tokens: int
    output_microusd_per_million_tokens: int
    long_context_threshold_input_tokens: int
    long_context_input_multiplier_ppm: int
    long_context_output_multiplier_ppm: int
    sha256: str


def canonical_openai_pricing_policy_bytes() -> bytes:
    return (
        json.dumps(
            EXPECTED_OPENAI_PRICING_POLICY,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def validate_openai_pricing_policy(raw: bytes) -> OpenAIPricingPolicy:
    expected = canonical_openai_pricing_policy_bytes()
    if not isinstance(raw, bytes) or raw != expected:
        raise PricingPolicyError("OpenAI pricing policy is not the approved canonical contract")
    payload = EXPECTED_OPENAI_PRICING_POLICY
    return OpenAIPricingPolicy(
        schema_version=payload["schema_version"],
        price_version=payload["price_version"],
        currency=payload["currency"],
        model=payload["model"],
        service_tier=payload["service_tier"],
        input_microusd_per_million_tokens=payload["input_microusd_per_million_tokens"],
        cached_input_microusd_per_million_tokens=payload[
            "cached_input_microusd_per_million_tokens"
        ],
        cache_write_input_microusd_per_million_tokens=payload[
            "cache_write_input_microusd_per_million_tokens"
        ],
        output_microusd_per_million_tokens=payload["output_microusd_per_million_tokens"],
        long_context_threshold_input_tokens=payload["long_context_threshold_input_tokens"],
        long_context_input_multiplier_ppm=payload["long_context_input_multiplier_ppm"],
        long_context_output_multiplier_ppm=payload["long_context_output_multiplier_ppm"],
        sha256=hashlib.sha256(raw).hexdigest(),
    )


def _ceil_ratio(numerator: int, denominator: int) -> int:
    return (numerator + denominator - 1) // denominator


def reserve_request_cost_microusd(
    policy: OpenAIPricingPolicy,
    *,
    input_tokens: int,
    output_tokens: int,
) -> int:
    """Reserve the highest supported standard-tier price without trusting cache hits."""

    for value, maximum, label in (
        (input_tokens, MAX_REVIEW_INPUT_TOKENS, "input"),
        (output_tokens, MAX_REVIEW_OUTPUT_TOKENS, "output"),
    ):
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
            raise PricingPolicyError(f"review {label} token reservation is invalid")
    input_rate = max(
        policy.input_microusd_per_million_tokens,
        policy.cached_input_microusd_per_million_tokens,
        policy.cache_write_input_microusd_per_million_tokens,
    )
    output_rate = policy.output_microusd_per_million_tokens
    if input_tokens > policy.long_context_threshold_input_tokens:
        input_rate = _ceil_ratio(
            input_rate * policy.long_context_input_multiplier_ppm,
            MULTIPLIER_SCALE,
        )
        output_rate = _ceil_ratio(
            output_rate * policy.long_context_output_multiplier_ppm,
            MULTIPLIER_SCALE,
        )
    return _ceil_ratio(
        input_tokens * input_rate,
        TOKENS_PER_RATE_UNIT,
    ) + _ceil_ratio(
        output_tokens * output_rate,
        TOKENS_PER_RATE_UNIT,
    )


def maximum_packet_cost_microusd(
    policy: OpenAIPricingPolicy,
    *,
    reserved_tokens: int,
    attempts: int = MAX_REVIEW_ATTEMPTS_PER_PACKET,
) -> int:
    """Return the conservative maximum for a packet-wide token reservation."""

    if (
        isinstance(reserved_tokens, bool)
        or not isinstance(reserved_tokens, int)
        or not attempts * MAX_REVIEW_OUTPUT_TOKENS <= reserved_tokens
        or reserved_tokens > attempts * (MAX_REVIEW_INPUT_TOKENS + MAX_REVIEW_OUTPUT_TOKENS)
    ):
        raise PricingPolicyError("packet token reservation cannot fund the approved attempts")
    remaining_input = reserved_tokens - attempts * MAX_REVIEW_OUTPUT_TOKENS
    total = 0
    for _ in range(attempts):
        request_input = min(MAX_REVIEW_INPUT_TOKENS, remaining_input)
        remaining_input -= request_input
        total += reserve_request_cost_microusd(
            policy,
            input_tokens=request_input,
            output_tokens=MAX_REVIEW_OUTPUT_TOKENS,
        )
    if remaining_input:
        raise PricingPolicyError("packet input reservation exceeds per-request limits")
    return total


APPROVED_OPENAI_PRICING_POLICY = validate_openai_pricing_policy(
    canonical_openai_pricing_policy_bytes()
)
DEFAULT_PACKET_COST_LIMIT_MICROUSD = maximum_packet_cost_microusd(
    APPROVED_OPENAI_PRICING_POLICY,
    reserved_tokens=DEFAULT_PACKET_RESERVED_TOKENS,
)
ABSOLUTE_PACKET_COST_LIMIT_MICROUSD = maximum_packet_cost_microusd(
    APPROVED_OPENAI_PRICING_POLICY,
    reserved_tokens=ABSOLUTE_PACKET_RESERVED_TOKENS,
)
