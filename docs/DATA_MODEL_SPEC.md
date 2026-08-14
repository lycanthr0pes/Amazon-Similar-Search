# データモデル仕様

## 1. 目的

BonsaiとOutscraperの可変な応答を、後段が扱えるPydanticモデルへ変換する。現行モデルの正は `src/schemas.py` である。

```text
利用者入力
  -> Bonsai応答文字列
  -> ProductAttributes
  -> Outscraper生レスポンス辞書
  -> list[NormalizedAmazonProduct]
  -> list[ProductScore]
```

## 2. `ProductAttributes`

自然文から抽出した検索条件である。

| フィールド | 型 | 既定値 |
|---|---|---|
| `estimated_product_name_ja` | `str` | 必須 |
| `estimated_product_name_en` | `str | None` | `None` |
| `category_ja` | `str | None` | `None` |
| `category_en` | `str | None` | `None` |
| `color_ja` | `str | None` | `None` |
| `color_en` | `str | None` | `None` |
| `features_ja` | `list[str]` | 空リスト |
| `features_en` | `list[str]` | 空リスト |
| `negative_conditions_ja` | `list[str]` | 空リスト |
| `negative_conditions_en` | `list[str]` | 空リスト |
| `search_queries_ja` | `list[str]` | 空リスト |
| `search_queries_en` | `list[str]` | 空リスト |
| `required_terms_ja` | `list[str]` | 空リスト |
| `required_terms_en` | `list[str]` | 空リスト |
| `preferred_terms_ja` | `list[str]` | 空リスト |
| `preferred_terms_en` | `list[str]` | 空リスト |
| `related_terms_ja` | `list[str]` | 空リスト |
| `related_terms_en` | `list[str]` | 空リスト |
| `price_preference` | `str | None` | `None` |
| `min_price_jpy` | `int | None` | `None` |
| `max_price_jpy` | `int | None` | `None` |
| `target_price_jpy` | `int | None` | `None` |
| `expected_price_min_jpy` | `int | None` | `None` |
| `expected_price_max_jpy` | `int | None` | `None` |

### 現行の前処理

- リスト項目の `null` は空リストにする
- リスト項目の文字列は1要素リストにする
- 通貨記号、`JPY`、桁区切りを含む正の整数価格を整数にし、0・負数・非整数・非有限値は `None` にする
- Markdownコードフェンスを除き、最初のJSONオブジェクト候補を取り出す
- 根拠の薄いカテゴリを除き、日本語・英語の検索語を再構成する
- 明示価格帯と推定価格帯の上下限が逆なら、それぞれ小さい方を下限へ入れ替える

### 現行の制約

`price_preference` の列挙値とリスト件数にはPydantic制約がない。価格の正数化と上下関係は属性抽出サービスで補正するため、`ProductAttributes` を別経路から直接生成する場合は同じ保証を持たない。

## 3. `NormalizedAmazonProduct`

Outscraperの商品1件を内部形式へそろえたモデルである。

| フィールド | 型 | 既定値・条件 |
|---|---|---|
| `source` | `str` | `amazon` |
| `asin` | `str | None` | `None` |
| `title` | `str` | 必須。空タイトルの商品は除外 |
| `brand_or_store` | `str | None` | `None` |
| `price_jpy` | `int | None` | `None` |
| `list_price_jpy` | `int | None` | `None` |
| `currency` | `str | None` | `None` |
| `rating` | `float | None` | `None` |
| `review_count` | `int | None` | `None` |
| `categories` | `list[str]` | 空リスト |
| `image_url` | `str | None` | `None` |
| `image_urls` | `list[str]` | 空リスト |
| `product_url` | `str | None` | `None` |
| `short_url` | `str | None` | `None` |
| `is_prime` | `bool` | `False` |
| `availability` | `str | None` | `None` |
| `shipping` | `str | None` | `None` |
| `source_query` | `str | None` | `None` |
| `position` | `int | None` | `None` |
| `description` | `str | None` | `None` |

### 現行の正規化

- 文字列は前後空白を除く
- JPYとUSDを認識し、その他の明示通貨は商品ごと除外する
- 通貨記号・桁区切り・小数を含む最初の有限数値を価格・評価・件数から取り出す
- USDは `USD_TO_JPY_RATE` を掛けて整数へ変換し、JPYは小数点以下を切り捨てる
- Primeはbool、数値1、文字列 `1`、`true`、`yes`、`y` を真として扱う
- 高解像度画像、`image_1` から `image_10` の順で画像URLを集める
- ASIN、短縮URL、商品URL、タイトルの順で最初に存在する値を重複キーにする
- `data` が想定したリストでなければ商品0件にする

外部レスポンスのURLスキーム、評価範囲、価格の非負、文字列の長さは現行モデルで制約していない。

## 4. `ProductScore`

UIとCLIへ返す採点済み商品である。

| フィールド | 型 | 説明 |
|---|---|---|
| `asin` | `str | None` | 商品識別子 |
| `title` | `str` | 商品名 |
| `price_jpy` | `int | None` | 円換算価格 |
| `rating` | `float | None` | 評価 |
| `review_count` | `int | None` | レビュー件数 |
| `image_url` | `str | None` | 表示画像 |
| `product_url` | `str | None` | 商品URL |
| `title_similarity` | `float` | 商品名側の類似度 |
| `attribute_similarity` | `float` | 属性TF-IDFまたは条件一致率 |
| `price_score` | `float` | 価格条件への近さ |
| `negative_penalty` | `float` | 否定条件の減点 |
| `total_score` | `float` | 0から1へ制限した総合値 |
| `matched_terms` | `list[str]` | 採用言語で一致した条件 |
| `missing_terms` | `list[str]` | 採用言語で不足した条件 |
| `negative_matches` | `list[str]` | 一致した除外語 |

総合値:

```text
clamp(
  title_similarity * 0.45
  + attribute_similarity * 0.35
  + price_score * 0.20
  - negative_penalty,
  0.0,
  1.0
)
```

類似度とスコアは小数4桁へ丸める。否定条件は一致1件につき0.2、最大0.5である。

## 5. ファイル境界

- 各段階のキャッシュキーはStreamlitセッションまたはCLIの `cache_scope` で分離する
- `ProductAttributes` は `model_dump()` して `cache/product_attributes/<key>.json` へ保存する
- Outscraper生レスポンスはモデル化前にそのままJSON保存する
- `NormalizedAmazonProduct` のリストは `cache/outscraper/normalized/<key>.json` へ保存する
- `ProductScore` のリストは `cache/outscraper/scored/<key>.json` へ保存する
- キャッシュ再利用時は各辞書を対応するPydanticモデルで再検証する

JSONは一時ファイルへ書いた後に置換する。属性抽出・正規化・採点のキーには実装版を含めるが、JSON payload自体を包む共通エンベロープとスキーマ版フィールドはない。

## 6. 設計候補（未実装）

本番用途では次の追加モデルを検討できる。

- `SearchResult`: 検索ID、採点結果、件数、作成時刻、設定バージョン
- `SearchJobStatus`: queued、running、succeeded、failed、timed_out
- `ExternalApiError`: API種別、再試行可否、HTTP状態、相関ID
- `CacheEnvelope`: スキーマ版、作成時刻、期限、キー材料、payload
- 認証ユーザーまたはテナントに結び付く永続キャッシュscope

追加するまでは、これらを現在の入出力仕様として扱わない。
