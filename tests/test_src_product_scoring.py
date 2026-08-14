from src.config import settings
from src.schemas import NormalizedAmazonProduct
from src.schemas import ProductAttributes
from src.services.product_scoring import calculate_price_score
from src.services.product_scoring import calculate_weighted_condition_match_score
from src.services.product_scoring import weighted_condition_terms


def test_weighted_condition_terms_deduplicates_terms_with_required_priority() -> None:
    attrs = ProductAttributes(
        estimated_product_name_ja="軽量マウス",
        color_en="white",
        features_en=["lightweight", "Logicool"],
        required_terms_en=["Logicool", "gaming mouse"],
        preferred_terms_en=["lightweight", "white"],
        related_terms_en=["game mouse", "Logicool"],
    )

    terms = weighted_condition_terms(attrs, language="en")

    assert terms == [
        ("Logicool", settings.required_term_weight),
        ("gaming mouse", settings.required_term_weight),
        ("white", settings.color_term_weight),
        ("lightweight", settings.feature_term_weight),
        ("game mouse", settings.related_term_weight),
    ]


def test_weighted_condition_match_score_uses_deduplicated_total_weight() -> None:
    attrs = ProductAttributes(
        estimated_product_name_ja="軽量マウス",
        features_en=["lightweight"],
        required_terms_en=["Logicool"],
        preferred_terms_en=["lightweight"],
    )

    score, matched_terms, missing_terms = calculate_weighted_condition_match_score(
        attrs,
        "Logicool lightweight gaming mouse",
        language="en",
    )

    assert score == 1.0
    assert matched_terms == ["Logicool", "lightweight"]
    assert missing_terms == []


def test_calculate_price_score_uses_explicit_price_range() -> None:
    attrs = ProductAttributes(
        estimated_product_name_ja="マウス",
        min_price_jpy=5000,
        max_price_jpy=10000,
    )

    assert (
        calculate_price_score(attrs, NormalizedAmazonProduct(title="cheap", price_jpy=3000)) == 0.6
    )
    assert (
        calculate_price_score(attrs, NormalizedAmazonProduct(title="in range", price_jpy=7000))
        == 1.0
    )
    assert (
        round(
            calculate_price_score(
                attrs, NormalizedAmazonProduct(title="expensive", price_jpy=12000)
            ),
            4,
        )
        == 0.8333
    )


def test_calculate_price_score_uses_target_price() -> None:
    attrs = ProductAttributes(
        estimated_product_name_ja="マウス",
        target_price_jpy=10000,
    )

    assert (
        calculate_price_score(attrs, NormalizedAmazonProduct(title="target", price_jpy=10000))
        == 1.0
    )
    assert (
        calculate_price_score(attrs, NormalizedAmazonProduct(title="lower", price_jpy=8000)) == 0.8
    )
    assert (
        round(
            calculate_price_score(attrs, NormalizedAmazonProduct(title="higher", price_jpy=12000)),
            4,
        )
        == 0.8333
    )
