# データ保存と論理スキーマ

## 1. 現在の永続化方式

amazon-explorer はRDBを採用していない。データベースサーバー、SQLスキーマ、マイグレーション、ORMは存在せず、処理途中と最終結果をローカルファイルシステム上のJSONキャッシュへ保存する。

この文書の「論理スキーマ」は、`src/schemas.py` のPydanticモデルとJSONファイルの配置規約を指す。アーキテクチャは [DESIGN.md](DESIGN.md)、処理の詳細は [BACKEND.md](BACKEND.md)、保存上の制約は [CONSTRAINTS.md](CONSTRAINTS.md)を参照する。

## 2. データフロー

```text
user_input: str
  -> Bonsai response content: str
  -> ProductAttributes
  -> Outscraper raw response: JSON object
  -> list[NormalizedAmazonProduct]
  -> list[ProductScore]
```

Pydanticモデルの正は `src/schemas.py` である。JSONから再利用する際は、属性、正規化商品、採点商品を対応するモデルで再検証する。

## 3. ファイル配置

`CACHE_DIR` の既定値はリポジトリルートの `cache/` である。相対パスを設定した場合もプロジェクトルートを基準に絶対パスへ解決する。

```text
cache/
  product_attributes/
    <attributes_key>.json
  outscraper/
    raw/
      <raw_key>.json
    normalized/
      <normalized_key>.json
    scored/
      <scored_key>.json
```

| 論理コレクション | namespace | JSONルート | 内容 |
|---|---|---|---|
| 属性 | `product_attributes` | object | `ProductAttributes.model_dump()` |
| 生レスポンス | `outscraper/raw` | object | Outscraperの成功レスポンス |
| 正規化商品 | `outscraper/normalized` | array | `NormalizedAmazonProduct.model_dump()` の配列 |
| 採点商品 | `outscraper/scored` | array | `ProductScore.model_dump()` の配列 |

`cache/` は `.gitignore` 対象である。ここは永続的な業務データベースではなく、再計算可能なアプリケーション生成物の置場である。

## 4. `ProductAttributes`

自然文から抽出・補正した検索条件を表す。

| フィールド | JSON型 | 必須 | 既定値・意味 |
|---|---|---:|---|
| `estimated_product_name_ja` | string | はい | 推定した日本語商品名 |
| `estimated_product_name_en` | string / null | いいえ | 英語商品名 |
| `category_ja` | string / null | いいえ | 根拠のある日本語カテゴリ |
| `category_en` | string / null | いいえ | 根拠のある英語カテゴリ |
| `color_ja` | string / null | いいえ | 日本語の色 |
| `color_en` | string / null | いいえ | 英語の色 |
| `features_ja` | array[string] | いいえ | 空配列。日本語の特徴 |
| `features_en` | array[string] | いいえ | 空配列。英語の特徴 |
| `negative_conditions_ja` | array[string] | いいえ | 空配列。日本語の除外条件 |
| `negative_conditions_en` | array[string] | いいえ | 空配列。英語の除外条件 |
| `search_queries_ja` | array[string] | いいえ | 空配列。Outscraper候補の日本語検索語 |
| `search_queries_en` | array[string] | いいえ | 空配列。英語検索語 |
| `required_terms_ja` | array[string] | いいえ | 空配列。日本語の必須語 |
| `required_terms_en` | array[string] | いいえ | 空配列。英語の必須語 |
| `preferred_terms_ja` | array[string] | いいえ | 空配列。日本語の優先語 |
| `preferred_terms_en` | array[string] | いいえ | 空配列。英語の優先語 |
| `related_terms_ja` | array[string] | いいえ | 空配列。日本語の関連語 |
| `related_terms_en` | array[string] | いいえ | 空配列。英語の関連語 |
| `price_preference` | string / null | いいえ | `cheap`、`premium`、`none` をプロンプトで要求 |
| `min_price_jpy` | integer / null | いいえ | 明示された下限 |
| `max_price_jpy` | integer / null | いいえ | 明示された上限 |
| `target_price_jpy` | integer / null | いいえ | 明示された目標価格 |
| `expected_price_min_jpy` | integer / null | いいえ | 推定相場の下限 |
| `expected_price_max_jpy` | integer / null | いいえ | 推定相場の上限 |

### 4.1 保存前の補正

- リスト項目の `null` は空配列、文字列は1要素配列にする
- 価格は正の整数だけを残す
- 通貨記号、`JPY`、桁区切りを含む整数表現を受け付ける
- 0、負数、非整数、非有限値、不明な型は `null` にする
- 明示価格帯と推定相場の上下限が逆なら入れ替える
- 根拠の薄いカテゴリを `null` にする
- 検索語を商品名、色、特徴、根拠のあるカテゴリから再構成する

### 4.2 モデル上の注意

`price_preference` の列挙値や各配列の最大件数はPydanticモデル自体では制約していない。価格補正と範囲整合は属性抽出サービスで行うため、別経路で `ProductAttributes` を直接生成すると同じ保証は得られない。

## 5. Outscraper生レスポンス

生レスポンスはPydanticモデルで包まず、JSON objectのまま保存する。完了結果では `data` が配列であることをクライアント境界で検証する。

正規化で参照する主な外部フィールド:

```text
data
name, asin, store_title
price_parsed, price, old_price_parsed, strike_price_parsed
old_price, strike_price, delivery_price, currency
rating, reviews, categories, description
high_res_images, image_1 ... image_10
url, short_url, prime, availability, shipping
query, position
```

APIキーは生レスポンスpayloadへ追加しない。

## 6. `NormalizedAmazonProduct`

Outscraper商品1件を後段で扱う形式へそろえたモデルである。

| フィールド | JSON型 | 必須 | 既定値・意味 |
|---|---|---:|---|
| `source` | string | いいえ | `amazon` |
| `asin` | string / null | いいえ | 商品識別子 |
| `title` | string | はい | 商品名。空タイトルは保存前に除外 |
| `brand_or_store` | string / null | いいえ | ブランドまたはストア名 |
| `price_jpy` | integer / null | いいえ | JPYへ換算済みの価格 |
| `list_price_jpy` | integer / null | いいえ | JPYへ換算済みの旧価格等 |
| `currency` | string / null | いいえ | 検出した元通貨 `JPY` または `USD` |
| `rating` | number / null | いいえ | 評価 |
| `review_count` | integer / null | いいえ | レビュー件数 |
| `categories` | array[string] | いいえ | 空配列 |
| `image_url` | string / null | いいえ | 表示用の先頭画像 |
| `image_urls` | array[string] | いいえ | 空配列。重複除去済み画像 |
| `product_url` | string / null | いいえ | 商品URL |
| `short_url` | string / null | いいえ | 短縮URL |
| `is_prime` | boolean | いいえ | `false` |
| `availability` | string / null | いいえ | 在庫情報 |
| `shipping` | string / null | いいえ | 配送情報 |
| `source_query` | string / null | いいえ | 外部レスポンス内の検索語 |
| `position` | integer / null | いいえ | 元検索順位 |
| `description` | string / null | いいえ | 商品説明 |

### 6.1 正規化規則

- `data` の辞書と1段ネストした辞書配列を候補として取り出す
- 文字列の前後空白を除く
- 通貨が明示されていればJPY・USDだけを許可する
- USDは `USD_TO_JPY_RATE` を掛けて整数化する
- JPYは数値の小数部分を切り捨てる
- 負の価格は `null` にする
- Primeはbool、数値1、文字列 `1`、`true`、`yes`、`y` を真とする
- 高解像度画像、`image_1` から `image_10` の順に重複を除く
- ASIN、短縮URL、商品URL、タイトルの順で重複キーを選ぶ

URLスキーム、文字列長、評価範囲、レビュー件数の非負性は現行Pydanticモデルで制約していない。

## 7. `ProductScore`

UIとCLIへ返す採点済み商品の形式である。

| フィールド | JSON型 | 必須 | 意味 |
|---|---|---:|---|
| `asin` | string / null | いいえ | 商品識別子 |
| `title` | string | はい | 商品名 |
| `price_jpy` | integer / null | いいえ | 円換算価格 |
| `rating` | number / null | いいえ | 評価 |
| `review_count` | integer / null | いいえ | レビュー件数 |
| `image_url` | string / null | いいえ | 表示画像 |
| `product_url` | string / null | いいえ | 商品URL |
| `title_similarity` | number | はい | 商品名類似度 |
| `attribute_similarity` | number | はい | 属性TF-IDFまたは条件一致率 |
| `price_score` | number | はい | 価格条件への近さ |
| `negative_penalty` | number | はい | 除外条件による減点 |
| `total_score` | number | はい | 0.0以上1.0以下の総合値 |
| `matched_terms` | array[string] | いいえ | 採用言語で一致した条件 |
| `missing_terms` | array[string] | いいえ | 採用言語で不足した条件 |
| `negative_matches` | array[string] | いいえ | 一致した除外語 |

類似度とスコアは小数4桁へ丸める。保存順は `total_score` の降順である。

## 8. キャッシュキーの論理スキーマ

キー材料をキー名順のコンパクトJSONにし、SHA-256の16進表現の先頭24桁をファイル名にする。

### 8.1 属性キー

```text
type, version, cache_scope, user_input,
bonsai_base_url, bonsai_model, prompt_sha256,
temperature, max_tokens
```

入力は前後空白除去後の文字列を使う。プロンプト本文は保存せずSHA-256全体を材料にする。

### 8.2 生レスポンスキー

```text
type, cache_scope, query, endpoint,
domain, language, postal_code, limit
```

APIキーは含めない。

### 8.3 正規化キー

```text
type, version, cache_scope,
usd_to_jpy_rate, raw_response
```

生レスポンス全体を材料に含める。

### 8.4 採点キー

```text
type, version, attributes, normalized_cache_key,
title_score_weight, attribute_score_weight, price_score_weight,
required_term_weight, color_term_weight, feature_term_weight,
preferred_term_weight, related_term_weight
```

`normalized_cache_key` がscopeを含むため、採点もscopeごとに分かれる。

### 8.5 実装版

現行の属性、正規化、採点キャッシュ版はそれぞれ文字列 `"2"` である。変換結果が変わる非互換変更では該当版を更新し、旧ファイルをキャッシュミスにする。

## 9. scopeによる分離

- Streamlitはセッション開始時に `secrets.token_hex(16)` でscopeを作る
- 同じ画面セッション内では同じscopeを再利用する
- 別セッションは同じ入力でも異なるキーになる
- CLIとscope未指定のPython呼出は `local-cli` を継続利用する
- scopeは1文字以上128文字以下である

scopeは認証ユーザーID、秘密情報、アクセス制御境界ではない。すべてのファイルは同じ `CACHE_DIR` 配下に置かれる。

## 10. TTL

| コレクション | 設定 | 既定値 | 判定方法 |
|---|---|---:|---|
| 属性 | `LLM_CACHE_TTL_SECONDS` | 86400秒 | ファイルmtimeからの経過時間 |
| 生レスポンス | `OUTSCRAPER_CACHE_TTL_SECONDS` | 3600秒 | ファイルmtimeからの経過時間 |
| 正規化商品 | なし | 無期限 | キー一致とモデル検証 |
| 採点商品 | なし | 無期限 | キー一致とモデル検証 |

期限切れファイルはキャッシュミスになるが削除されない。`ENABLE_CACHE=false`、`use_cache=False`、`--no-cache` は読込を止めるだけで、保存は継続する。

## 11. 原子的書込

すべてのキャッシュ保存は `src/utilities/json_editor.py` の `write_json()` を通る。

1. 保存先ディレクトリを作成する。
2. 保存先と同じディレクトリに名前付き一時ファイルを作る。
3. UTF-8、インデント2、末尾改行付きでJSONを書く。
4. `flush()` と `os.fsync()` を実行する。
5. `Path.replace()` で目的ファイルへ置換する。
6. 失敗時に残った一時ファイルを削除する。

同一ファイルを読者が途中まで読む危険は減らせるが、複数プロセス間の相互排他ロックはない。

## 12. 読込と破損時の扱い

`JsonCacheRepository` は次をキャッシュミスとして返す。

- ファイルが存在しない
- TTLを超えている
- 読込時のOSエラー
- UTF-8デコードエラー
- JSON構文エラー

namespaceが絶対パスまたは `..` を含む場合は拒否する。キーは空でない小文字16進数だけを許可する。属性、正規化商品、採点商品はさらにPydantic検証を行い、不一致なら再計算する。破損ファイルの隔離、削除、通知は現時点で行わない。

## 13. 共通エンベロープを持たないこと

各JSONはpayloadそのものを保存し、次の共通メタデータを持たない。

- schema version
- created_at / expires_at
- cache scope
- キー材料
- producer version
- integrity checksum

版と設定はファイル名を決めるキー材料にだけ含まれる。作成時刻とTTLはファイルmtimeへ依存する。

## 14. 保存データと保護

キャッシュには利用者入力から抽出した条件、商品タイトル、説明、価格、評価、画像URL、商品URL、一致・不足・否定条件が保存され得る。APIキーはキャッシュキーとpayloadへ含めない。

- `cache/` をGitや公開Webルートへ含めない
- 共有ホストではOSのディレクトリ権限で保護する
- キャッシュ内容をログ、Issue、完了報告へ貼り付けない
- scopeを認証や秘密保持の代替にしない

詳細は [SECURITY.md](SECURITY.md)を参照する。

## 15. RDB等へ移行する判断条件（未実装）

次のいずれかが必要になった場合、ローカルJSON継続かRDB・オブジェクトストレージ移行かをExecution Planで決める。

- 複数ワーカーから同じデータを安全に更新する
- 利用者・テナント単位の認可を永続的に適用する
- 検索ジョブの状態遷移、再開、監査履歴を保持する
- 容量上限、期限削除、検索、集計を運用要件にする
- 破損検知、バックアップ、復旧目標を保証する

候補モデルは `SearchResult`、`SearchJobStatus`、`ExternalApiError`、`CacheEnvelope` だが、現行入出力には存在しない。
