from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import TYPE_CHECKING

# Path(__file__).resolve().parents[2] = ルートディレクトリ
PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_ROOT = PROJECT_ROOT / "src"
# ルートディレクトリからimportするプログラムを探せるようにする
for import_path in (PROJECT_ROOT, SRC_ROOT):
    if str(import_path) not in sys.path:
        sys.path.insert(0, str(import_path))

# テスト用
if TYPE_CHECKING:
    from src.schemas import ProductAttributes
    from src.schemas import ProductScore


# ユーザの自然言語入力に対してbonsaiが返した商品属性JSONを保存する
def write_product_attributes(attrs: "ProductAttributes", query_hash: str) -> Path:
    from src.utilities.json_editor import write_json

    output_path = Path(f"cache/product_attributes/product_attributes_{query_hash}.json")
    write_json(output_path, attrs.model_dump())
    print(f"Product attributes written to: {output_path}")
    return output_path


# 実行部本体
# 最初にユーザーが入力した自然言語を受け取る
def run_product_search(user_input: str) -> list["ProductScore"]:
    from src.clients.bonsai_client import call_bonsai
    from src.clients.outscraper_client import call_outscraper
    from src.services.amazon_product_normalization import normalize
    from src.services.outscraper_search_select import select_outscraper_query
    from src.services.product_scoring import scoring
    from src.services.user_attribute_extraction import extract_product_attributes
    from src.utilities.build_hash import build_query_hash

    print("Step 1/4: Bonsaiで商品属性を抽出します")
    # ユーザが入力した自然言語をBonsaiへ送る
    raw_attributes = call_bonsai(user_input)
    # Bonsaiの返答JSONを正規化してProductAttributesに変換する
    attrs = extract_product_attributes(raw_attributes, user_input)

    print("Step 2/4: Outscraperへ渡す検索クエリを選択します")
    # Outscraperに渡すための検索クエリを選ぶ
    query = select_outscraper_query(attrs)
    # JSONファイル名用のハッシュを作る
    query_hash = build_query_hash(query)
    print(f"Search query: {query}")
    # ユーザの自然言語入力に対してbonsaiが返した商品属性JSONを保存する
    write_product_attributes(attrs, query_hash)

    print("Step 3/4: OutscraperでAmazon商品候補を取得します")
    # OutscraperでAmazon商品を取得する
    raw_products_path = call_outscraper(query, query_hash)
    # 取得したAmazon商品のデータを商品リストに正規化する
    normalize_products = normalize(raw_products_path, query_hash)

    # 商品候補にスコアを付けて並べる
    print("Step 4/4: 商品候補をスコアリングします")
    return scoring(attrs, normalize_products, query_hash)


# スコアリング済みの上位n件を標準出力する(テスト用)
def print_top_results(scored_products: list["ProductScore"], *, limit: int) -> None:
    print(f"Top {min(limit, len(scored_products))} results:")
    for index, product in enumerate(scored_products[:limit], start=1):
        price = f"{product.price_jpy}円" if product.price_jpy is not None else "価格不明"
        print(f"{index}. score={product.total_score:.4f} {price} {product.title}")
        if product.product_url:
            print(f"   {product.product_url}")


# テスト用
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="第1段階から第4段階までの商品検索処理をまとめて実行する",
    )
    parser.add_argument(
        "user_input",
        help="欲しい商品の自然言語説明",
    )
    parser.add_argument(
        "--display-limit",
        type=int,  # pyright: ignore[reportArgumentType]
        default=10,
        help="標準出力に表示する上位件数。デフォルトは10",
    )
    return parser.parse_args()


# テスト用
def main() -> None:
    args = parse_args()
    scored_products = run_product_search(args.user_input)
    print_top_results(scored_products, limit=args.display_limit)


# テスト用
if __name__ == "__main__":
    main()
