"""Shared fail-closed path policy for AI-review trust boundaries."""

from __future__ import annotations

import re
from pathlib import Path
from pathlib import PurePosixPath


_CREDENTIAL_BASENAMES = frozenset(
    {
        ".envrc",
        ".authinfo",
        ".authinfo.gpg",
        ".git-credentials",
        ".gitconfig",
        ".netrc",
        ".npmrc",
        ".pypirc",
        ".yarnrc",
        ".yarnrc.yml",
        "_netrc",
        "application_default_credentials.json",
        "auth.json",
        "credentials",
        "credentials.json",
        "credentials.toml",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "id_rsa",
        "service-account.json",
        "service_account.json",
        "secrets.json",
        "secrets.toml",
        "tokens.json",
    }
)
_CREDENTIAL_DIRECTORIES = frozenset(
    {
        ".aws",
        ".azure",
        ".gnupg",
        ".kube",
        ".ssh",
    }
)
_CREDENTIAL_SUFFIXES = (
    (".config", "gcloud"),
    (".config", "gh"),
    (".config", "glab-cli"),
    (".config", "hub"),
    (".config", "openai"),
    (".config", "pypoetry", "auth.toml"),
    (".config", "rclone", "rclone.conf"),
    (".docker", "config.json"),
)
_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_HIGH_CONFIDENCE_SECRET_PATTERNS = (
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"(?<![A-Z0-9])AKIA[A-Z0-9]{16}(?![A-Z0-9])"),
    re.compile(r"(?<![A-Za-z0-9])gh(?:p|o|u|s|r)_[A-Za-z0-9]{20,}"),
    re.compile(r"(?<![A-Za-z0-9])sk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
    re.compile(r"(?i)\b[a-z][a-z0-9+.-]{1,31}://[^\s/:@]+:[^\s/@]{3,}@[^\s/]+"),
)


def _parts(path: str | Path | PurePosixPath) -> tuple[str, ...]:
    raw = path.as_posix() if isinstance(path, (Path, PurePosixPath)) else path
    return tuple(part.casefold() for part in PurePosixPath(raw).parts)


def _contains_sequence(parts: tuple[str, ...], sequence: tuple[str, ...]) -> bool:
    width = len(sequence)
    return any(parts[index : index + width] == sequence for index in range(len(parts) - width + 1))


def sensitive_path_reason(path: str | Path | PurePosixPath) -> str | None:
    """Return a stable reason when *path* must never cross a review boundary."""

    parts = _parts(path)
    if any(part == ".env" or part.startswith(".env.") or part == ".envrc" for part in parts):
        return "sensitive environment path"
    if _contains_sequence(parts, (".streamlit", "secrets.toml")):
        return "sensitive Streamlit secrets path"
    if any(part in _CREDENTIAL_DIRECTORIES for part in parts):
        return "credential path"
    if parts and parts[-1] in _CREDENTIAL_BASENAMES:
        return "credential path"
    if any(_contains_sequence(parts, sequence) for sequence in _CREDENTIAL_SUFFIXES):
        return "credential path"
    if "cache" in parts or ".cache" in parts:
        return "sensitive cache path"
    if ".git" in parts:
        return "Git metadata"
    return None


def validate_empty_env_example(raw: bytes) -> None:
    """Accept only a small UTF-8 template whose assignment values are all empty."""

    if not isinstance(raw, bytes) or len(raw) > 64 * 1024 or b"\x00" in raw:
        raise ValueError(".env.example is not an empty-value UTF-8 template")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ValueError(".env.example is not an empty-value UTF-8 template") from exc
    if any(pattern.search(text) for pattern in _HIGH_CONFIDENCE_SECRET_PATTERNS):
        raise ValueError(".env.example contains credential-like content")
    lines = text.splitlines()
    if len(lines) > 1_000 or any(len(line) > 4_096 for line in lines):
        raise ValueError(".env.example is not an empty-value UTF-8 template")
    for line in lines:
        candidate = line.strip()
        if not candidate:
            continue
        commented = candidate.startswith("#")
        if commented:
            candidate = candidate[1:].lstrip()
            if not candidate or "=" not in candidate:
                continue
        if "=" not in candidate:
            raise ValueError(".env.example contains executable or non-assignment content")
        key, _separator, value = candidate.partition("=")
        key = key.strip()
        if key.startswith("export "):
            key = key[7:].strip()
        if _ENV_KEY_RE.fullmatch(key) is None:
            if commented:
                continue
            raise ValueError(".env.example contains an invalid variable name")
        if value.strip() not in {"", "''", '""'}:
            raise ValueError(".env.example must not contain configured values")
