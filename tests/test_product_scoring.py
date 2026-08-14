from src.schemas import NormalizedAmazonProduct
from src.schemas import ProductAttributes
from src.services.product_scoring import calculate_price_score
from src.services.product_scoring import score_product
from src.services.product_scoring import score_products


def test_score_products_keeps_japanese_missing_terms_when_language_scores_tie() -> None:
    attrs = ProductAttributes(
        estimated_product_name_ja="マウス",
        required_terms_ja=["静音"],
    )
    product = NormalizedAmazonProduct(title="ワイヤレスマウス")

    scored = score_products(attrs, [product])

    assert scored[0].attribute_similarity == 0.0
    assert scored[0].matched_terms == []
    assert scored[0].missing_terms == ["静音"]


def test_score_product_keeps_japanese_missing_terms_when_language_scores_tie() -> None:
    attrs = ProductAttributes(
        estimated_product_name_ja="マウス",
        required_terms_ja=["静音"],
    )
    product = NormalizedAmazonProduct(title="ワイヤレスマウス")

    scored = score_product(attrs, product)

    assert scored.attribute_similarity == 0.0
    assert scored.missing_terms == ["静音"]


def test_calculate_price_score_normalizes_reversed_range() -> None:
    attrs = ProductAttributes(
        estimated_product_name_ja="マウス",
        min_price_jpy=10000,
        max_price_jpy=5000,
    )
    product = NormalizedAmazonProduct(title="マウス", price_jpy=7000)

    assert calculate_price_score(attrs, product) == 1.0


def test_calculate_price_score_ignores_invalid_negative_prices() -> None:
    attrs = ProductAttributes(
        estimated_product_name_ja="マウス",
        price_preference="cheap",
        min_price_jpy=-1000,
        max_price_jpy=-500,
        expected_price_max_jpy=-800,
    )
    product = NormalizedAmazonProduct(title="マウス", price_jpy=7000)

    assert calculate_price_score(attrs, product) == 0.5
