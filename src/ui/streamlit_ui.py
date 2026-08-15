from __future__ import annotations

import logging
import secrets

import streamlit as st

from src.config import settings
from src.main.run import run_product_search
from src.clients.bonsai_client import is_bonsai_running
from src.schemas import ProductScore


LOGGER = logging.getLogger(__name__)


# 内部処理用のint価格を表示用のstrに変換する
def format_price(price_jpy: int | None) -> str:
    if price_jpy is None:
        return "価格不明"
    return f"{price_jpy:,}円"


# 内部処理用のfloat評価を表示用のstrに変換する
def format_rating(rating: float | None, review_count: int | None) -> str:
    if rating is None:
        return "評価なし"
    if review_count is None:
        return f"{rating:.1f}"
    return f"{rating:.1f} / {review_count:,}件"


@st.cache_data(ttl=5, show_spinner=False)
def bonsai_is_available() -> bool:
    return is_bonsai_running()


# Streamlitの画面のサイドバーに設定情報を表示する
def render_status_panel() -> None:
    st.sidebar.header("設定")
    st.sidebar.caption(f"Bonsai: {settings.bonsai_base_url}")
    st.sidebar.caption(f"Amazon: {settings.outscraper_domain} / {settings.outscraper_language}")
    st.sidebar.caption(f"取得件数: {settings.outscraper_limit}")

    # APIキーが存在するかどうか
    if settings.outscraper_api_key:
        st.sidebar.success("Outscraper API key: existing")
    else:
        st.sidebar.warning("Outscraper API key: missing")

    # Bonsaiサーバが起動しているかどうか
    if bonsai_is_available():
        st.sidebar.success("Bonsai Server: running")
    else:
        st.sidebar.warning("Bonsai Server: not running")

    # デバッグが有効になっている場合はスコア計算の要素を表示する
    if settings.show_debug_info:
        st.sidebar.json(
            {
                "title_score_weight": settings.title_score_weight,
                "attribute_score_weight": settings.attribute_score_weight,
                "price_score_weight": settings.price_score_weight,
                "required_term_weight": settings.required_term_weight,
                "preferred_term_weight": settings.preferred_term_weight,
                "related_term_weight": settings.related_term_weight,
                "color_term_weight": settings.color_term_weight,
                "feature_term_weight": settings.feature_term_weight,
            }
        )


# ラベルと, ラベルに合う要素の一覧を表示する
def render_terms(label: str, terms: list[str]) -> None:
    if not terms:
        return
    st.caption(label)
    st.write(" / ".join(terms))


# 結果の中身を表示
def render_product(product: ProductScore, rank: int) -> None:
    with st.container(border=True):
        # 商品のサムネと詳細を水平に1:3で表示
        image_column, detail_column = st.columns([1, 3], vertical_alignment="top")

        # 設定した比率に合わせてサムネを表示
        with image_column:
            if product.image_url:
                st.image(product.image_url, use_container_width=True)
            else:
                st.info("画像なし")

        # 設定した比率に合わせて総合スコアと各類似度を表示(4列)
        with detail_column:
            st.subheader(f"{rank}. {product.title}")
            metric_columns = st.columns(4)
            # 総合スコアと各類似度を表示
            metric_columns[0].metric("総合", f"{product.total_score:.3f}")
            metric_columns[1].metric("商品名", f"{product.title_similarity:.3f}")
            metric_columns[2].metric("属性", f"{product.attribute_similarity:.3f}")
            metric_columns[3].metric("価格", f"{product.price_score:.3f}")

            # 総合スコアのバーを表示
            st.progress(product.total_score)

            # 価格と評価を表示
            st.write(f"**価格:** {format_price(product.price_jpy)}")
            st.write(f"**評価:** {format_rating(product.rating, product.review_count)}")

            # 商品のリンクを表示
            if product.product_url:
                st.link_button("Amazonで開く", product.product_url)

            # 各条件を表示
            render_terms("一致した条件", product.matched_terms)
            render_terms("不足している条件", product.missing_terms)
            render_terms("避けたい条件に一致", product.negative_matches)


# 結果を表示
def render_results(products: list[ProductScore], display_limit: int) -> None:
    if not products:
        st.info("表示できる検索結果がありません。")
        return

    # 区切り線を表示
    st.divider()
    # 結果の中身を表示
    st.caption(f"{len(products)}件中 {min(display_limit, len(products))}件を表示")
    for rank, product in enumerate(products[:display_limit], start=1):
        render_product(product, rank)


# 実行部分
def main() -> None:
    # ページ構成
    st.set_page_config(
        page_title="Amazon Product Search",
        layout="wide",
    )

    # タイトル表示
    st.title("Amazon類似度検索")

    # サイドパネル表示
    render_status_panel()

    # 表示件数スライダー
    display_limit = st.sidebar.slider(
        "表示件数",
        min_value=1,
        max_value=30,
        # 初期値
        value=min(settings.search_result_display_limit, 30),
    )

    # 最初の実行なら結果表示用の空リストを作る
    # st.session_stateは保存された設定した値全て
    if "scored_products" not in st.session_state:
        st.session_state.scored_products = []
    if "cache_scope" not in st.session_state:
        st.session_state.cache_scope = secrets.token_hex(16)

    # 入力フォームを作る
    with st.form("product_search_form"):
        user_input = st.text_area(
            "商品を検索",
            height=120,
        )
        # 検索ボタンを表示
        submitted = st.form_submit_button("検索")

    # 検索ボタンが押されたとき
    if submitted:
        if not user_input.strip():
            st.warning("検索条件を入力してください。")
        else:
            try:
                with st.spinner("商品候補を取得してスコアリングしています。"):
                    # 入力された自然言語をバックエンド実行部に渡し, 結果を返す
                    # 返るまで待機
                    st.session_state.scored_products = run_product_search(
                        user_input.strip(),
                        cache_scope=st.session_state.cache_scope,
                    )
            except Exception:
                LOGGER.exception("Product search failed")
                st.error("検索に失敗しました。設定と外部サービスの状態を確認してください。")

    # 帰った結果の内, 表示上限まで表示
    render_results(st.session_state.scored_products, display_limit)


if __name__ == "__main__":
    main()
