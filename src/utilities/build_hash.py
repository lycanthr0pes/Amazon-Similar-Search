import hashlib
import json
from collections.abc import Mapping
from typing import Any


def build_cache_key(payload: Mapping[str, Any]) -> str:
    """結果へ影響する入力を正規化し、ファイル名用のキーを作る。"""

    raw = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def build_query_hash(query: str) -> str:
    """旧呼び出しとの互換性を保つ検索クエリ用キー。"""

    return build_cache_key({"query": query})
