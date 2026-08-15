from __future__ import annotations

import socket
from pathlib import Path

import pytest

from tools.ai_review import egress_gateway
from tools.ai_review.egress_policy import canonical_broker_egress_policy_bytes
from tools.ai_review.egress_policy import validate_broker_egress_policy


def test_gateway_requires_opt_in_and_rejects_credentials_or_proxy_configuration() -> None:
    with pytest.raises(egress_gateway.EgressGatewayError, match="opt-in"):
        egress_gateway._validate_environment({})
    for forbidden in ("OPENAI_API_KEY", "HTTPS_PROXY", "SSL_CERT_FILE"):
        with pytest.raises(egress_gateway.EgressGatewayError, match="not approved"):
            egress_gateway._validate_environment(
                {"AI_REVIEW_EGRESS_GATEWAY": "1", forbidden: "must-not-be-present"}
            )


def test_gateway_accepts_only_global_dns_targets_on_the_fixed_tls_port() -> None:
    def resolver(*_args, **_kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443)),
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("93.184.216.34", 443)),
        ]

    assert egress_gateway._validated_target_addresses(resolver=resolver) == (
        (socket.AF_INET, ("93.184.216.34", 443)),
    )

    def private_resolver(*_args, **_kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("169.254.169.254", 443))
        ]

    with pytest.raises(egress_gateway.EgressGatewayError, match="forbidden address"):
        egress_gateway._validated_target_addresses(resolver=private_resolver)


@pytest.mark.parametrize("address", [("127.0.0.1", 1), ("8.8.8.8", 1), ("169.254.1.1", 1)])
def test_gateway_rejects_non_private_or_special_broker_peers(address: tuple[str, int]) -> None:
    with pytest.raises(egress_gateway.EgressGatewayError, match="private broker network"):
        egress_gateway._validate_peer(address)


def test_gateway_accepts_a_private_container_peer() -> None:
    egress_gateway._validate_peer(("10.89.0.12", 32100))


def test_gateway_image_is_credential_free_and_uses_the_fixed_entrypoint() -> None:
    root = Path(__file__).resolve().parents[1]
    dockerfile = (root / "containers/ai-review-egress/Dockerfile").read_text(encoding="utf-8")

    assert "OPENAI_API_KEY" not in dockerfile
    assert 'ENTRYPOINT ["/opt/ai-review/bin/egress-gateway"]' in dockerfile
    assert "USER 65531:65531" in dockerfile


def test_checked_in_egress_policy_is_exact_canonical_allowlist() -> None:
    root = Path(__file__).resolve().parents[1]
    raw = (root / "specs/policies/broker-egress-policy.json").read_bytes()

    assert raw == canonical_broker_egress_policy_bytes()
    assert len(validate_broker_egress_policy(raw)) == 64
    with pytest.raises(ValueError, match="canonical allowlist"):
        validate_broker_egress_policy(raw.replace(b"api.openai.com", b"attacker.invalid"))
