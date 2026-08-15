"""Canonical allowlist contract shared by release, coordinator, and broker evidence checks."""

from __future__ import annotations

import hashlib
import json
from typing import Any


EXPECTED_BROKER_EGRESS_POLICY: dict[str, Any] = {
    "allowed_protocol": "tcp-tls",
    "broker_host_mounts": False,
    "broker_internal_network": True,
    "gateway_external_network": True,
    "gateway_has_api_credential": False,
    "gateway_network_alias": "ai-review-egress-gateway",
    "gateway_port": 8443,
    "max_broker_connections": 1,
    "schema_version": "1.0",
    "target_host": "api.openai.com",
    "target_port": 443,
    "tls_server_name": "api.openai.com",
}


class EgressPolicyError(ValueError):
    """Raised when the mounted policy is not the exact reviewed allowlist contract."""


def canonical_broker_egress_policy_bytes() -> bytes:
    return (
        json.dumps(
            EXPECTED_BROKER_EGRESS_POLICY,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def validate_broker_egress_policy(raw: bytes) -> str:
    if not isinstance(raw, bytes) or raw != canonical_broker_egress_policy_bytes():
        raise EgressPolicyError("broker egress policy is not the approved canonical allowlist")
    return hashlib.sha256(raw).hexdigest()
