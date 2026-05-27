import hashlib
import json


# 検索クエリから結果保存用JSONを管理するためのハッシュ値を作成する
def build_query_hash(
    query: str,
) -> str:
    payload = {
        "query": query,
    }
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    # 検索クエリからハッシュ値を作成し, 先頭12桁を返す
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]
