from src.config import settings
from src.services.amazon_product_normalization import as_int
from src.services.amazon_product_normalization import convert_price_to_jpy
from src.services.amazon_product_normalization import normalize_product


def test_jpy_decimal_string_does_not_add_decimal_places_as_digits() -> None:
    assert as_int("￥1,980.00") == 1980
    assert convert_price_to_jpy("￥1,980.00", "JPY") == 1980


def test_decorated_usd_string_is_converted_to_jpy() -> None:
    assert convert_price_to_jpy("$12.99", "USD") == int(12.99 * settings.usd_to_jpy_rate)


def test_prime_false_string_is_normalized_to_false() -> None:
    product = normalize_product(
        {
            "name": "Sample item",
            "price": "￥1,980.00",
            "prime": "false",
        }
    )

    assert product is not None
    assert product.price_jpy == 1980
    assert product.is_prime is False


def test_prime_true_string_is_normalized_to_true() -> None:
    product = normalize_product({"name": "Sample item", "prime": "true"})

    assert product is not None
    assert product.is_prime is True
