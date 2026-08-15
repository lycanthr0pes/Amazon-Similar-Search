from __future__ import annotations

import hashlib
import json

import pytest

from tools.ai_review.coordinator_workflow_inputs import CoordinatorWorkflowInputError
from tools.ai_review.coordinator_workflow_inputs import _pinned_image
from tools.ai_review.coordinator_workflow_inputs import _runtime_binding
from tools.ai_review.phase_protocol import canonical_json_bytes


def runtime_binding_bytes() -> bytes:
    security = {
        "name": "podman",
        "rootless": True,
        "seccomp_profile": "runtime/default",
        "user_namespace": True,
    }
    return canonical_json_bytes(
        {
            **security,
            "environment_sha256": "1" * 64,
            "executable_sha256": "2" * 64,
            "security_evidence_sha256": hashlib.sha256(canonical_json_bytes(security)).hexdigest(),
        }
    )


def test_runtime_binding_rejects_unknown_fields_and_digest_substitution() -> None:
    raw = runtime_binding_bytes()
    binding = _runtime_binding(raw, expected_sha256=hashlib.sha256(raw).hexdigest())
    assert binding.name == "podman"

    value = json.loads(raw)
    value["runtime_path"] = "/host/podman"
    unknown = canonical_json_bytes(value)
    with pytest.raises(CoordinatorWorkflowInputError, match="runtime binding"):
        _runtime_binding(unknown, expected_sha256=hashlib.sha256(unknown).hexdigest())
    with pytest.raises(CoordinatorWorkflowInputError, match="SHA-256"):
        _runtime_binding(raw, expected_sha256="f" * 64)


def test_images_must_embed_the_exact_runtime_manifest_digest() -> None:
    digest = "sha256:" + "a" * 64
    image = "example.invalid/broker@" + digest
    assert _pinned_image(image, digest, label="broker image") == image
    with pytest.raises(CoordinatorWorkflowInputError, match="manifest"):
        _pinned_image(image, "sha256:" + "b" * 64, label="broker image")
