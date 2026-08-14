import json

import pytest

from src.services.user_attribute_extraction import BONSAI_RESPONSE_ERROR
from src.services.user_attribute_extraction import parse_attributes


@pytest.mark.parametrize(
    "raw_text",
    [
        '["sensitive-list-payload"]',
        '"sensitive-string-payload"',
        "null",
        "123",
    ],
)
def test_parse_attributes_rejects_non_object_json_without_exposing_raw_text(
    raw_text: str,
) -> None:
    with pytest.raises(ValueError) as exc_info:
        parse_attributes(raw_text, fallback_query="マウス")

    assert str(exc_info.value) == BONSAI_RESPONSE_ERROR
    assert "sensitive" not in str(exc_info.value)


def test_parse_attributes_does_not_expose_invalid_raw_response() -> None:
    raw_text = "not-json-sensitive-payload"

    with pytest.raises(ValueError) as exc_info:
        parse_attributes(raw_text, fallback_query="マウス")

    assert str(exc_info.value) == BONSAI_RESPONSE_ERROR
    assert raw_text not in str(exc_info.value)


def test_parse_attributes_normalizes_decorated_and_reversed_price_range() -> None:
    raw_text = json.dumps(
        {
            "estimated_product_name_ja": "マウス",
            "min_price_jpy": "￥10,000円",
            "max_price_jpy": "5,000",
        },
        ensure_ascii=False,
    )

    attrs = parse_attributes(raw_text, fallback_query="マウス")

    assert attrs.min_price_jpy == 5000
    assert attrs.max_price_jpy == 10000


def test_parse_attributes_discards_non_positive_price_values() -> None:
    raw_text = json.dumps(
        {
            "estimated_product_name_ja": "マウス",
            "min_price_jpy": -100,
            "max_price_jpy": True,
        },
        ensure_ascii=False,
    )

    attrs = parse_attributes(raw_text, fallback_query="マウス")

    assert attrs.min_price_jpy is None
    assert attrs.max_price_jpy is None
