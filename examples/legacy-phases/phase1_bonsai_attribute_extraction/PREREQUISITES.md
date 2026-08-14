# 第一段階：自然言語入力から商品属性抽出

## 1. 目的

第一段階では、Amazon検索、ランキング、Streamlit UI、ComfyUI連携は実装対象外とする。

対象範囲は以下に限定する。

```text
自然言語入力
  ↓
Bonsai 8B local server
  ↓
商品属性JSON
```

この段階の目的は、ユーザーの曖昧な商品イメージを、後続のAmazon検索で利用できる構造化データへ変換できることを確認することである。

## 2. 前提条件

ラップトップ側で以下を満たすこと。

- Python 3.10以上を利用できる
- `uv` を利用できる
- Bonsai 8B GGUFファイルをローカルに配置済みである
- `llama-server` またはOpenAI互換APIを提供できるLLMサーバを利用できる
- BonsaiのAPIは外部公開せず、`127.0.0.1` に限定して起動する
- 第一段階ではOutscraper APIキー、ComfyUI、SSH接続は不要とする

最小依存パッケージは以下とする。

```text
requests
pydantic
python-dotenv
```

開発用に `ruff` と `pytest` を追加してもよいが、第一段階の疎通確認だけであれば必須ではない。

## 3. 環境変数

`.env` またはシェル環境変数で以下を設定する。

```env
BONSAI_BASE_URL=http://127.0.0.1:8080/v1
BONSAI_MODEL=Bonsai-8B
```

未設定の場合、サンプルコードは上記の値をデフォルトとして使う。

## 4. Bonsai起動

BonsaiをOpenAI互換サーバとして起動する。

```bash
llama-server \
  -m /path/to/Bonsai-8B.gguf \
  --host 127.0.0.1 \
  --port 8080
```

疎通確認は以下で行う。

```bash
curl http://127.0.0.1:8080/v1/models
```

## 5. 商品属性スキーマ

第一段階の出力は以下のスキーマに固定する。

```python
from pydantic import BaseModel, Field


class ProductAttributes(BaseModel):
    estimated_product_name_ja: str = Field(description="UI表示に使う日本語の推定商品名")
    estimated_product_name_en: str | None = Field(default=None, description="Outscraper検索と英語商品名照合に使う英語の推定商品名")
    category_ja: str | None = Field(default=None, description="UI表示に使う日本語の商品カテゴリ")
    category_en: str | None = Field(default=None, description="英語商品名照合に使う英語の商品カテゴリ")
    color_ja: str | None = Field(default=None, description="UI表示に使う日本語の主要な色")
    color_en: str | None = Field(default=None, description="英語商品名照合に使う英語の主要な色")
    features_ja: list[str] = Field(default_factory=list, description="UI表示に使う日本語の商品特徴")
    features_en: list[str] = Field(default_factory=list, description="Outscraper検索と英語商品名照合に使う英語の商品特徴")
    negative_conditions_ja: list[str] = Field(default_factory=list, description="UI表示に使う日本語の除外条件")
    negative_conditions_en: list[str] = Field(default_factory=list, description="英語商品名照合に使う英語の除外条件")
    search_queries_ja: list[str] = Field(default_factory=list, description="日本語Amazon検索クエリ候補")
    search_queries_en: list[str] = Field(default_factory=list, description="Outscraper検索に優先して使う英語Amazon検索クエリ候補")
    image_prompt: str | None = Field(default=None, description="画像生成用英語プロンプト")
    price_preference: str | None = Field(default=None, description="cheap / premium / none")
    max_price_jpy: int | None = Field(default=None, description="上限価格")
```

`search_queries_en` はOutscraper検索に優先して使う。`search_queries_ja` が空の場合、サンプルコードではユーザー入力をそのまま日本語検索語として使う。

## 6. プロンプト方針

Bonsaiには、説明文やMarkdownを返させず、JSONのみを返させる。

```text
あなたはEC商品検索用の商品属性抽出器です。
ユーザーの自然言語入力から、Amazon検索に使う商品属性を抽出してください。

制約:
- 出力はJSONのみ
- Markdownや説明文は禁止
- 不明な項目は null または [] を使う
- *_ja フィールドは日本語で出力する
- *_en フィールドは自然な英語で出力する
- search_queries_ja は日本語で1から3件
- search_queries_en はOutscraper検索に使える英語で1から3件
- image_prompt は英語の商品写真プロンプト
- price_preference は cheap / premium / none のいずれか

JSONキー:
estimated_product_name_ja, estimated_product_name_en,
category_ja, category_en, color_ja, color_en,
features_ja, features_en, negative_conditions_ja, negative_conditions_en,
search_queries_ja, search_queries_en, image_prompt, price_preference, max_price_jpy
```

## 7. 実行方法

依存パッケージを入れる。

```bash
uv sync
```

Bonsaiを起動した状態で、サンプルコードを実行する。

```bash
uv run python phase1_bonsai_attribute_extraction/extract_product_attributes.py
```

## 8. 期待出力例

```json
{
  "estimated_product_name_ja": "ノイズキャンセリング 小型ワイヤレスイヤホン ブラック",
  "estimated_product_name_en": "compact black noise cancelling wireless earbuds",
  "category_ja": "ワイヤレスイヤホン",
  "category_en": "wireless earbuds",
  "color_ja": "ブラック",
  "color_en": "black",
  "features_ja": ["ノイズキャンセリング", "小型", "丸型ケース"],
  "features_en": ["noise cancelling", "compact", "small round case"],
  "negative_conditions_ja": [],
  "negative_conditions_en": [],
  "search_queries_ja": [
    "ノイズキャンセリング 小型 ワイヤレスイヤホン ブラック"
  ],
  "search_queries_en": [
    "compact black noise cancelling wireless earbuds"
  ],
  "image_prompt": "black compact wireless earbuds with noise cancelling, small rounded charging case, product photo, white background",
  "price_preference": "cheap",
  "max_price_jpy": null
}
```

## 9. 完了条件

- Bonsai local serverへHTTP接続できる
- 自然言語入力からJSONのみを取得できる
- Pydanticで商品属性スキーマを検証できる
- `search_queries_ja` が1件以上になる
- `search_queries_en` または `estimated_product_name_en` が1件以上になる
- JSONが壊れた場合に失敗理由を明示できる
