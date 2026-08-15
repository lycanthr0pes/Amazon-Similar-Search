from __future__ import annotations

import hashlib
from pathlib import Path


READ_CHUNK_BYTES = 1024 * 1024


def sha256_file(path: Path) -> str:
    """Hash a file with APIs available on every supported Python version."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(READ_CHUNK_BYTES):
            digest.update(chunk)
    return digest.hexdigest()
