from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from src.utilities.json_editor import read_json
from src.utilities.json_editor import write_json


PRODUCT_ATTRIBUTES_CACHE = "product_attributes"
OUTSCRAPER_RAW_CACHE = "outscraper/raw"
OUTSCRAPER_NORMALIZED_CACHE = "outscraper/normalized"
OUTSCRAPER_SCORED_CACHE = "outscraper/scored"


class JsonCacheRepository:
    """プロジェクト配下のJSONキャッシュを安全に読み書きする。"""

    def __init__(self, root: Path) -> None:
        self.root = root.resolve()

    def path_for(self, namespace: str, cache_key: str) -> Path:
        namespace_path = Path(namespace)
        if namespace_path.is_absolute() or ".." in namespace_path.parts:
            raise ValueError("Cache namespace must stay below the cache directory.")
        if not cache_key or any(character not in "0123456789abcdef" for character in cache_key):
            raise ValueError("Cache key must be a lowercase hexadecimal string.")
        return self.root / namespace_path / f"{cache_key}.json"

    def fresh_path(
        self,
        namespace: str,
        cache_key: str,
        *,
        max_age_seconds: int | None = None,
    ) -> Path | None:
        path = self.path_for(namespace, cache_key)
        if not path.is_file():
            return None
        if max_age_seconds is not None and time.time() - path.stat().st_mtime > max_age_seconds:
            return None
        return path

    def load(
        self,
        namespace: str,
        cache_key: str,
        *,
        max_age_seconds: int | None = None,
    ) -> Any | None:
        path = self.fresh_path(namespace, cache_key, max_age_seconds=max_age_seconds)
        if path is None:
            return None
        try:
            return read_json(path)
        except (OSError, UnicodeError, json.JSONDecodeError):
            return None

    def save(self, namespace: str, cache_key: str, data: Any) -> Path:
        path = self.path_for(namespace, cache_key)
        write_json(path, data)
        return path
