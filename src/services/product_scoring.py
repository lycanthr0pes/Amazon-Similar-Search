import math
from typing import Sequence
from operator import attrgetter
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from src.schemas import ProductAttributes
from src.schemas import NormalizedAmazonProduct
from src.schemas import ProductScore
from src.services.text_processing import build_tfidf_text
from src.services.text_processing import clean_dupe_empty
from src.services.text_processing import term_matches_text
from src.utilities.json_editor import write_json
from src.config import settings


# Bonsaiが出力した商品情報から推定された商品名とカテゴリを取り出し, 重複と余計空白を削除してリスト化
# 言語で分ける
def build_title_query_terms(attrs: ProductAttributes, language: str | None = None) -> list[str]:
    if language == "en":
        return clean_dupe_empty([attrs.estimated_product_name_en, attrs.category_en])
    if language == "ja":
        return clean_dupe_empty([attrs.estimated_product_name_ja, attrs.category_ja])

    return clean_dupe_empty(
        [
            attrs.estimated_product_name_en,
            attrs.estimated_product_name_ja,
            attrs.category_en,
            attrs.category_ja,
        ]
    )


# Bonsaiが出力した商品情報から属性とカテゴリを取り出し, 重複と余計空白を削除してリスト化
# 言語で分ける
def build_attribute_terms(attrs: ProductAttributes, language: str | None = None) -> list[str]:
    if language == "en":
        return clean_dupe_empty([attrs.color_en, attrs.category_en, *attrs.features_en])
    if language == "ja":
        return clean_dupe_empty([attrs.color_ja, attrs.category_ja, *attrs.features_ja])

    return clean_dupe_empty(
        [
            attrs.color_en,
            attrs.color_ja,
            attrs.category_en,
            attrs.category_ja,
            *attrs.features_en,
            *attrs.features_ja,
        ]
    )


# 設定した重み付けに応じて, 一致度・類似度計算に使う語句リストにおけるその語句の頻度を増やす
def repeat_terms(terms: Sequence[str | None], weight: int) -> list[str]:
    repeated_terms = []
    for term in clean_dupe_empty(terms):
        repeated_terms.extend([term] * weight)
    return repeated_terms


# Bonsaiが出力した商品情報の重要語句, 優先語句, 関連語句をそれぞれリスト化
# 設定した重み付けに応じて, リストにおけるその語句の頻度を増やす
# 言語で分ける
def build_weighted_ranking_terms(
    attrs: ProductAttributes,
    language: str | None = None,
) -> list[str]:
    if language == "en":
        required_terms = attrs.required_terms_en
        preferred_terms = attrs.preferred_terms_en
        related_terms = attrs.related_terms_en
    elif language == "ja":
        required_terms = attrs.required_terms_ja
        preferred_terms = attrs.preferred_terms_ja
        related_terms = attrs.related_terms_ja
    else:
        required_terms = [*attrs.required_terms_en, *attrs.required_terms_ja]
        preferred_terms = [*attrs.preferred_terms_en, *attrs.preferred_terms_ja]
        related_terms = [*attrs.related_terms_en, *attrs.related_terms_ja]

    return [
        *repeat_terms(required_terms, settings.required_term_weight),
        *repeat_terms(preferred_terms, settings.preferred_term_weight),
        *repeat_terms(related_terms, settings.related_term_weight),
    ]


# Bonsaiが出力した, ユーザが避けたい語句をリスト化
def build_negative_terms(attrs: ProductAttributes) -> list[str]:
    return clean_dupe_empty([*attrs.negative_conditions_en, *attrs.negative_conditions_ja])


# Bonsaiが出力した商品情報からスコアリングで重視したい条件語を, 重み(繰り返し回数)付きリストに変換
# デフォルト: 必須語 > 色 > 特徴 > 優先語 > 関連語
def weighted_condition_terms(
    attrs: ProductAttributes,
    language: str | None = None,
) -> list[tuple[str, int]]:
    weighted_terms = []
    # 英語でのみ評価する場合
    if language == "en":
        weighted_groups = [
            (attrs.required_terms_en, settings.required_term_weight),
            ([attrs.color_en], settings.color_term_weight),
            (attrs.features_en, settings.feature_term_weight),
            (attrs.preferred_terms_en, settings.preferred_term_weight),
            (attrs.related_terms_en, settings.related_term_weight),
        ]
    # 日本語でのみ評価する場合
    elif language == "ja":
        weighted_groups = [
            (attrs.required_terms_ja, settings.required_term_weight),
            ([attrs.color_ja], settings.color_term_weight),
            (attrs.features_ja, settings.feature_term_weight),
            (attrs.preferred_terms_ja, settings.preferred_term_weight),
            (attrs.related_terms_ja, settings.related_term_weight),
        ]
    # 両方で評価する場合
    else:
        weighted_groups = [
            ([*attrs.required_terms_en, *attrs.required_terms_ja], settings.required_term_weight),
            ([attrs.color_en, attrs.color_ja], settings.color_term_weight),
            ([*attrs.features_en, *attrs.features_ja], settings.feature_term_weight),
            (
                [*attrs.preferred_terms_en, *attrs.preferred_terms_ja],
                settings.preferred_term_weight,
            ),
            ([*attrs.related_terms_en, *attrs.related_terms_ja], settings.related_term_weight),
        ]

    # 語句から重複と余計な空白を削除し, 最初に出た重み付け語句だけを採用する
    seen_terms = set()
    for terms, weight in weighted_groups:
        for term in clean_dupe_empty(terms):
            normalized = term.casefold()
            if normalized in seen_terms:
                continue
            weighted_terms.append((term, weight))
            seen_terms.add(normalized)

    return weighted_terms


# Bonsaiが出力した商品情報と, Outscraperが出力した商品情報の一致度を単語分割して重み付きで計算する
# 日本語と英語で分ける
def calculate_weighted_condition_match_score(
    attrs: ProductAttributes,
    product_text: str,
    language: str | None = None,
) -> tuple[float, list[str], list[str]]:
    # Bonsaiが出力した商品情報からスコアリングで重視したい条件語を, 重み(繰り返し回数)付きリストに変換
    weighted_terms = weighted_condition_terms(attrs, language=language)
    if not weighted_terms:
        return 0.0, [], []

    # 重みの合計
    total_weight = sum(weight for _, weight in weighted_terms)
    # 一致した語の重み合計
    matched_weight = 0
    matched_terms = []
    missing_terms = []
    seen_matched = set()
    seen_missing = set()

    for term, weight in weighted_terms:
        # 単語分割し, 新しい語句が含まれていたら重み追加
        if term_matches_text(term, product_text):
            matched_weight += weight
            normalized = term.casefold()
            if normalized not in seen_matched:
                matched_terms.append(term)
                seen_matched.add(normalized)
        else:
            normalized = term.casefold()
            if normalized not in seen_missing:
                missing_terms.append(term)
                seen_missing.add(normalized)

    # 一致した語句の重み合計 / 全重みの合計で一致度スコアを返す
    return matched_weight / total_weight, matched_terms, missing_terms


# Outscraperが出力した, 分割されたスコア計算に使う商品の要素を空白区切りで結合する
def combined_product_text(product: NormalizedAmazonProduct) -> str:
    return " ".join(value for value in product_text_parts(product) if value)


# Outscraperが出力した商品情報からスコア計算に使う商品の要素を取り出す
# 商品名, ブランド(ストア)名, (推定)カテゴリ一覧, 商品説明
def product_text_parts(product: NormalizedAmazonProduct) -> list[str]:
    categories = product.categories
    category_text = ""
    if isinstance(categories, list):
        category_text = " ".join(item for item in categories if isinstance(item, str))

    return [
        str(product.title or ""),
        str(product.brand_or_store or ""),
        category_text,
        str(product.description or ""),
    ]


"""
Bonsaiが出力した商品情報の重要語句, 優先語句, 関連語句のリストと,
推定された商品名とカテゴリのリストを結合→リストを単語分割し, 空白区切りの文字列で返す
"""


def build_title_query_text(attrs: ProductAttributes, language: str | None = None) -> str:
    return build_tfidf_text(
        [
            *build_title_query_terms(attrs, language=language),
            *build_weighted_ranking_terms(attrs, language=language),
        ],
        dedupe=False,
    )


"""
Bonsaiが出力した商品情報の重要語句, 優先語句, 関連語句のリストと,
色, カテゴリ, 機能のリストを結合→リストを単語分割し, 空白区切りの文字列で返す
"""


def build_attribute_query_text(attrs: ProductAttributes, language: str | None = None) -> str:
    return build_tfidf_text(
        [
            *build_attribute_terms(attrs, language=language),
            *build_weighted_ranking_terms(attrs, language=language),
        ],
        dedupe=False,
    )


# Outscraperが出力した商品情報を単語分割したあと, また空白区切りの文字列で返す
# 商品名, ブランド(ストア)名, (推定)カテゴリ一覧, 商品説明
def build_product_tfidf_text(product: NormalizedAmazonProduct) -> str:
    return build_tfidf_text([combined_product_text(product)])


# Outscraperが出力した商品情報から商品名を単語分割したあと, また空白区切りの文字列で返す
def build_product_title_tfidf_text(product: NormalizedAmazonProduct) -> str:
    return build_tfidf_text([product.title or ""])


"""
Bonsaiが出力したユーザ入力の商品単語情報(文字列)とOutscraperが出力したAmazonの商品単語情報を比較し,
TfidfVectorizerで類似度を計算する→リストで返す
"""


def calculate_tfidf_similarities(query_text: str, document_texts: list[str]) -> list[float]:
    if not query_text or not document_texts:
        return [0.0 for _ in document_texts]

    # BonsaiとOutscraper出力の分割された単語を結合する
    documents = [query_text, *document_texts]
    if not any(document.strip() for document in documents):
        return [0.0 for _ in document_texts]

    # 単語単位, 1文字以上の単語, 小文字化なし(事前にしているので)
    vectorizer = TfidfVectorizer(
        analyzer="word",
        token_pattern=r"(?u)\b\w+\b",
        lowercase=False,
    )
    # IDF学習
    try:
        vectorizer.fit(documents)
        query_vector = vectorizer.transform([documents[0]])
        document_vectors = vectorizer.transform(documents[1:])
    except ValueError:
        return [0.0 for _ in document_texts]

    # ベクトル計算
    return [float(score) for score in cosine_similarity(query_vector, document_vectors).ravel()]


# Bonsaiの属性とカテゴリがOutscraperが出力した商品情報に含まれているかそれぞれ単語分割して確認する
# 何個含まれていたかも返す
def calculate_term_match_score(terms: list[str], text: str) -> tuple[float, list[str], list[str]]:
    if not terms:
        return 0.0, [], []

    # 含まれているかいないかで分類する
    matched_terms = [term for term in terms if term_matches_text(term, text)]
    missing_terms = [term for term in terms if term not in matched_terms]
    return len(matched_terms) / len(terms), matched_terms, missing_terms


"""
Bonsaiが出力したユーザ入力の商品名単語(文字列)とOutscraperが出力したAmazonの商品名単語を比較し,
TfidfVectorizerで類似度を計算する→リストの中身を取り出して返す
"""


def calculate_title_similarity(
    attrs: ProductAttributes,
    product: NormalizedAmazonProduct,
    language: str | None = None,
) -> float:
    return calculate_tfidf_similarities(
        build_title_query_text(attrs, language=language), [build_product_title_tfidf_text(product)]
    )[0]


"""
Bonsaiが出力したユーザ入力の商品属性単語(文字列)とOutscraperが出力したAmazonの商品属性単語を比較し,
TfidfVectorizerで類似度を計算する→類似度, マッチ語句リスト, マッチしない語句リストを返す
"""


def calculate_attribute_similarity(
    attrs: ProductAttributes,
    product: NormalizedAmazonProduct,
    language: str | None = None,
) -> tuple[float, list[str], list[str]]:
    # Outscraperが出力した, 分割されたスコア計算に使う商品の要素を結合する
    product_text = combined_product_text(product)
    # Bonsaiが出力した商品情報と, Outscraperが出力した商品情報の一致度を重み付きで計算する
    condition_score, matched_terms, missing_terms = calculate_weighted_condition_match_score(
        attrs,
        product_text,
        language=language,
    )
    score = calculate_tfidf_similarities(
        build_attribute_query_text(attrs, language=language), [build_product_tfidf_text(product)]
    )[0]
    return max(score, condition_score), matched_terms, missing_terms


def select_attribute_language(
    attrs: ProductAttributes,
    english_score: float,
    japanese_score: float,
) -> str:
    if english_score > japanese_score:
        return "en"
    if japanese_score > english_score:
        return "ja"

    # 同点では、条件が存在しない言語が優先されて不足条件が空になることを防ぐ
    english_has_conditions = bool(weighted_condition_terms(attrs, language="en"))
    japanese_has_conditions = bool(weighted_condition_terms(attrs, language="ja"))
    if japanese_has_conditions and not english_has_conditions:
        return "ja"
    return "en"


def positive_price(value: int | None) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        return None
    return value


# Outscraperが出力した商品価格とBonsaiが出力したユーザ指定価格の類似度を返す
# 最大値1.0
def calculate_price_score(attrs: ProductAttributes, product: NormalizedAmazonProduct) -> float:
    price = positive_price(product.price_jpy)
    if price is None:
        return 0.0

    target_price = positive_price(attrs.target_price_jpy)
    minimum_price = positive_price(attrs.min_price_jpy)
    maximum_price = positive_price(attrs.max_price_jpy)
    if minimum_price is not None and maximum_price is not None:
        minimum_price, maximum_price = sorted((minimum_price, maximum_price))

    # 「A円前後」のように目標価格が具体的に決められているとき
    if target_price is not None:
        return min(price, target_price) / max(price, target_price)

    # 「A円からB円まで」のように価格範囲が具体的に決められているとき
    if minimum_price is not None and maximum_price is not None:
        if minimum_price <= price <= maximum_price:
            return 1.0
        if price < minimum_price:
            return price / minimum_price
        return maximum_price / price

    # 価格の下限が具体的に決められているとき
    if minimum_price is not None:
        return min(1.0, price / minimum_price)

    # 価格の上限が具体的に決められているとき
    if maximum_price is not None:
        return min(1.0, maximum_price / price)

    # 価格の上限が決められていないとき(対数関数で緩やかな推移にする)
    price_preference = (attrs.price_preference or "none").casefold()
    # 安いものが指定されているとき
    if price_preference == "cheap":
        reference_price = positive_price(attrs.expected_price_max_jpy)
        if reference_price is not None:
            return min(1.0, reference_price / price)
        return 0.5
    # 高いものが指定されているとき
    if price_preference == "premium":
        reference_price = positive_price(attrs.expected_price_min_jpy)
        if reference_price is not None:
            return min(1.0, 0.5 + 0.5 * math.log10(max(0.0, price / reference_price) + 1.0))
        return 0.5
    # 価格への言及がないとき
    return 0.5


"""
Bonsaiの避けるべき語句がOutscraperが出力した商品情報に含まれているか確認し,
一致がある場合は、1語につき0.2減点する(最大減点は0.5)
"""


def calculate_negative_penalty(
    attrs: ProductAttributes, product: NormalizedAmazonProduct
) -> tuple[float, list[str]]:
    # Outscraperが出力した, 分割されたスコア計算に使う商品の要素を結合する
    product_text = combined_product_text(product)
    # 一致確認
    negative_matches = [
        term for term in build_negative_terms(attrs) if term_matches_text(term, product_text)
    ]
    if not negative_matches:
        return 0.0, []

    # 減点
    penalty = min(0.5, 0.2 * len(negative_matches))
    return penalty, negative_matches


# 商品1件の類似度を計算し, ProductScoreオブジェクトを作成して返す
# 英語の類似度と日本語の類似度(TF-IDF)を比較し, より高い方を採用する
def score_product(
    attrs: ProductAttributes,
    product: NormalizedAmazonProduct,
    *,
    title_similarity: float | None = None,
    attribute_similarity: float | None = None,
    attribute_language: str | None = None,
    title_weight: float = settings.title_score_weight,
    attribute_weight: float = settings.attribute_score_weight,
    price_weight: float = settings.price_score_weight,
) -> ProductScore:
    # 商品名の言語毎の類似度を比較する
    if title_similarity is None:
        title_similarity = max(
            calculate_title_similarity(attrs, product, language="en"),
            calculate_title_similarity(attrs, product, language="ja"),
        )
    # 商品属性の言語毎の類似度を比較する
    if attribute_similarity is None:
        attribute_en = calculate_attribute_similarity(attrs, product, language="en")
        attribute_ja = calculate_attribute_similarity(attrs, product, language="ja")
        attribute_language = select_attribute_language(
            attrs,
            attribute_en[0],
            attribute_ja[0],
        )
        # 選択した言語のスコアと条件表示を同じタプルから取得する
        attribute_similarity, matched_terms, missing_terms = (
            attribute_en if attribute_language == "en" else attribute_ja
        )
    else:
        # すでに類似度が指定されている場合に, 一致する語句を確認する
        # Bonsaiが出力した商品情報と, Outscraperが出力した商品情報の一致度を単語分割して重み付きで計算する
        _, matched_terms, missing_terms = calculate_weighted_condition_match_score(
            attrs,
            combined_product_text(product),
            language=attribute_language,
        )

    # Outscraperが出力した商品価格とBonsaiが出力したユーザ指定価格の類似度を返す
    price_score = calculate_price_score(attrs, product)
    # Bonsaiの避けるべき語句がOutscraperが出力した商品情報に含まれていれば減点
    negative_penalty, negative_matches = calculate_negative_penalty(attrs, product)

    # 総合スコアを計算
    total_score = (
        title_similarity * title_weight
        + attribute_similarity * attribute_weight
        + price_score * price_weight
        - negative_penalty
    )

    # ProductScoreオブジェクトを作成して返す
    return ProductScore(
        asin=product.asin,
        title=str(product.title or ""),
        price_jpy=product.price_jpy,
        rating=product.rating,
        review_count=product.review_count,
        image_url=product.image_url,
        product_url=product.product_url,
        title_similarity=round(title_similarity, 4),
        attribute_similarity=round(attribute_similarity, 4),
        price_score=round(price_score, 4),
        negative_penalty=round(negative_penalty, 4),
        total_score=round(max(0.0, min(1.0, total_score)), 4),
        matched_terms=matched_terms,
        missing_terms=missing_terms,
        negative_matches=negative_matches,
    )


# 各商品の類似度を計算し, ProductScoreオブジェクトを作成してリストに入れ, 類似度スコア順にソートして返す
# TF-IDFと語句の一致度はより高い方を採用する
def score_products(
    attrs: ProductAttributes,
    products: list[NormalizedAmazonProduct],
) -> list[ProductScore]:
    # Outscraperが出力し, 正規化した商品名を単語区切りにしてリスト化
    product_title_texts = [build_product_title_tfidf_text(product) for product in products]
    # Outscraperが出力し, 正規化した商品情報を単語区切りしてリスト化
    product_attribute_texts = [build_product_tfidf_text(product) for product in products]

    # Bonsaiの推定商品名と, Outscraperが取得した商品名を言語別に比較してスコアを返す
    title_scores_en = calculate_tfidf_similarities(
        build_title_query_text(attrs, language="en"),
        product_title_texts,
    )
    title_scores_ja = calculate_tfidf_similarities(
        build_title_query_text(attrs, language="ja"),
        product_title_texts,
    )

    # Bonsaiの商品属性と, Outscraperが取得した商品属性を言語別に比較してスコアを返す
    attribute_scores_en = calculate_tfidf_similarities(
        build_attribute_query_text(attrs, language="en"),
        product_attribute_texts,
    )
    attribute_scores_ja = calculate_tfidf_similarities(
        build_attribute_query_text(attrs, language="ja"),
        product_attribute_texts,
    )

    # 各商品の類似度を計算し, ProductScoreオブジェクトを作成してリストに入れる
    scored_products = []
    for product, title_score_en, title_score_ja, attribute_score_en, attribute_score_ja in zip(
        products,
        title_scores_en,
        title_scores_ja,
        attribute_scores_en,
        attribute_scores_ja,
        strict=True,
    ):
        # Outscraperが出力した, 分割されたスコア計算に使う商品の要素を空白区切りで結合する
        product_text = combined_product_text(product)
        # Bonsaiが出力した商品情報と, Outscraperが出力した商品情報の一致度を単語分割して重み付きで計算する
        condition_score_en, _, _ = calculate_weighted_condition_match_score(
            attrs, product_text, language="en"
        )
        condition_score_ja, _, _ = calculate_weighted_condition_match_score(
            attrs, product_text, language="ja"
        )
        # TF-IDFと語句の一致度はより高い方を採用する
        attribute_score_en = max(attribute_score_en, condition_score_en)
        attribute_score_ja = max(attribute_score_ja, condition_score_ja)
        # 一致する語句を確認するための採用言語を取得
        attribute_language = select_attribute_language(
            attrs,
            attribute_score_en,
            attribute_score_ja,
        )

        scored_products.append(
            score_product(
                attrs,
                product,
                title_similarity=max(title_score_en, title_score_ja),
                attribute_similarity=max(attribute_score_en, attribute_score_ja),
                attribute_language=attribute_language,
            )
        )

    # 類似度スコア順にソートして返す
    return sorted(scored_products, key=attrgetter("total_score"), reverse=True)


# 各商品の類似度を計算し, ProductScoreオブジェクトのリストを作成し, 類似度スコア順にソートして返す
# JSONにも書き込む
def scoring(
    attrs: ProductAttributes, products: list[NormalizedAmazonProduct], query_hash: str
) -> list[ProductScore]:
    scored_products = score_products(attrs, products)

    # JSONに書き込む
    scored_dump = [product.model_dump() for product in scored_products]
    output_path = settings.cache_dir / "outscraper" / "scored" / f"{query_hash}.json"
    write_json(output_path, scored_dump)
    print(f"Scored products written to: {output_path}")

    return scored_products
