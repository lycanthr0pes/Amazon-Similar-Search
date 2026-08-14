import json

from src.config import settings
from src.main.run import build_attributes_cache_key
from src.main.run import build_scored_cache_key
from src.main.run import run_product_search
from src.schemas import ProductAttributes
from src.utilities.json_editor import write_json


def bonsai_response() -> str:
    return json.dumps(
        {
            "estimated_product_name_ja": "ワイヤレスキーボード",
            "estimated_product_name_en": "wireless keyboard",
            "category_ja": "キーボード",
            "category_en": "keyboard",
            "features_ja": ["静音"],
            "features_en": ["quiet"],
            "search_queries_ja": ["ワイヤレスキーボード 静音"],
            "search_queries_en": ["wireless keyboard quiet"],
            "required_terms_ja": ["キーボード"],
            "required_terms_en": ["keyboard"],
        },
        ensure_ascii=False,
    )


def test_cache_keys_include_input_attributes_and_scoring_settings(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    first_attributes_key = build_attributes_cache_key("静かなキーボード")
    second_attributes_key = build_attributes_cache_key("白いキーボード")
    assert first_attributes_key != second_attributes_key
    assert build_attributes_cache_key(
        "静かなキーボード", cache_scope="session-a"
    ) != build_attributes_cache_key("静かなキーボード", cache_scope="session-b")

    first_attrs = ProductAttributes(estimated_product_name_ja="キーボード", max_price_jpy=5000)
    second_attrs = first_attrs.model_copy(update={"max_price_jpy": 10000})
    assert build_scored_cache_key(first_attrs, "b" * 24) != build_scored_cache_key(
        second_attrs, "b" * 24
    )

    original_weight = settings.title_score_weight
    monkeypatch.setattr(settings, "title_score_weight", original_weight - 0.05)
    monkeypatch.setattr(settings, "attribute_score_weight", settings.attribute_score_weight + 0.05)
    changed_weight_key = build_scored_cache_key(first_attrs, "b" * 24)
    monkeypatch.setattr(settings, "title_score_weight", original_weight)
    monkeypatch.setattr(settings, "attribute_score_weight", settings.attribute_score_weight - 0.05)
    assert changed_weight_key != build_scored_cache_key(first_attrs, "b" * 24)


def test_product_search_reuses_complete_cache(monkeypatch, tmp_path):
    import src.clients.bonsai_client as bonsai_client
    import src.clients.outscraper_client as outscraper_client

    calls = {"bonsai": 0, "outscraper": 0}

    def fake_call_bonsai(user_input: str) -> str:
        calls["bonsai"] += 1
        assert user_input
        return bonsai_response()

    def fake_call_outscraper(query: str, cache_key: str):
        calls["outscraper"] += 1
        path = tmp_path / "outscraper" / "raw" / f"{cache_key}.json"
        write_json(
            path,
            {
                "status": "success",
                "data": [
                    [
                        {
                            "name": "静音 ワイヤレス キーボード",
                            "asin": "B000TEST01",
                            "currency": "JPY",
                            "price_parsed": 4980,
                            "query": query,
                        }
                    ]
                ],
            },
        )
        return path

    monkeypatch.setattr(settings, "cache_dir", tmp_path)
    monkeypatch.setattr(settings, "enable_cache", True)
    monkeypatch.setattr(bonsai_client, "call_bonsai", fake_call_bonsai)
    monkeypatch.setattr(outscraper_client, "call_outscraper", fake_call_outscraper)

    first_result = run_product_search("静かなワイヤレスキーボード")
    second_result = run_product_search("静かなワイヤレスキーボード")

    assert first_result == second_result
    assert len(first_result) == 1
    assert calls == {"bonsai": 1, "outscraper": 1}

    raw_cache_path = next((tmp_path / "outscraper" / "raw").glob("*.json"))
    raw_cache_path.write_text("broken", encoding="utf-8")
    repaired_result = run_product_search("静かなワイヤレスキーボード")

    assert repaired_result == first_result
    assert calls == {"bonsai": 1, "outscraper": 2}
