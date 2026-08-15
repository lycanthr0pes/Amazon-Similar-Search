import pytest

from src.schemas import ProductAttributes
from src.services.outscraper_search_select import select_outscraper_query


def test_select_outscraper_query_prefers_japanese_query() -> None:
    attrs = ProductAttributes(
        estimated_product_name_ja="キーボード",
        search_queries_ja=["静音 キーボード"],
        search_queries_en=["quiet keyboard"],
    )

    assert select_outscraper_query(attrs) == "静音 キーボード"


def test_select_outscraper_query_falls_back_to_english_query() -> None:
    attrs = ProductAttributes(
        estimated_product_name_ja="キーボード",
        search_queries_en=["quiet keyboard"],
    )

    assert select_outscraper_query(attrs) == "quiet keyboard"


@pytest.mark.parametrize("estimated_name", ["", "https://amazon.co.jp/dp/example"])
def test_select_outscraper_query_validates_estimated_name_fallback(
    estimated_name: str,
) -> None:
    attrs = ProductAttributes(estimated_product_name_ja=estimated_name)

    with pytest.raises(ValueError):
        select_outscraper_query(attrs)
