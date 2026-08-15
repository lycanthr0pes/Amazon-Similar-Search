from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from tools.ai_review.pricing_policy import ABSOLUTE_PACKET_COST_LIMIT_MICROUSD
from tools.ai_review.pricing_policy import APPROVED_OPENAI_PRICING_POLICY
from tools.ai_review.pricing_policy import DEFAULT_PACKET_COST_LIMIT_MICROUSD
from tools.ai_review.pricing_policy import PricingPolicyError
from tools.ai_review.pricing_policy import canonical_openai_pricing_policy_bytes
from tools.ai_review.pricing_policy import maximum_packet_cost_microusd
from tools.ai_review.pricing_policy import reserve_request_cost_microusd
from tools.ai_review.pricing_policy import validate_openai_pricing_policy


def test_checked_in_pricing_policy_is_canonical_and_content_addressed() -> None:
    path = Path(__file__).resolve().parents[1] / "specs/policies/openai-pricing-policy.json"
    raw = path.read_bytes()
    policy = validate_openai_pricing_policy(raw)

    assert raw == canonical_openai_pricing_policy_bytes()
    assert policy.sha256 == hashlib.sha256(raw).hexdigest()
    assert policy.model == "gpt-5.6-sol"
    assert policy.service_tier == "default"


def test_cost_reservation_uses_cache_write_and_output_worst_case() -> None:
    assert (
        reserve_request_cost_microusd(
            APPROVED_OPENAI_PRICING_POLICY,
            input_tokens=260_000,
            output_tokens=12_000,
        )
        == 1_985_000
    )


def test_packet_cost_limits_cover_all_four_reserved_attempts() -> None:
    assert DEFAULT_PACKET_COST_LIMIT_MICROUSD == 4_540_000
    assert ABSOLUTE_PACKET_COST_LIMIT_MICROUSD == 7_940_000
    assert (
        maximum_packet_cost_microusd(
            APPROVED_OPENAI_PRICING_POLICY,
            reserved_tokens=544_000,
        )
        == DEFAULT_PACKET_COST_LIMIT_MICROUSD
    )


def test_pricing_policy_and_token_bounds_fail_closed() -> None:
    forged = canonical_openai_pricing_policy_bytes().replace(b"6250000", b"1")
    with pytest.raises(PricingPolicyError, match="approved canonical"):
        validate_openai_pricing_policy(forged)
    with pytest.raises(PricingPolicyError, match="input token"):
        reserve_request_cost_microusd(
            APPROVED_OPENAI_PRICING_POLICY,
            input_tokens=260_001,
            output_tokens=12_000,
        )
    with pytest.raises(PricingPolicyError, match="cannot fund"):
        maximum_packet_cost_microusd(
            APPROVED_OPENAI_PRICING_POLICY,
            reserved_tokens=47_999,
        )
