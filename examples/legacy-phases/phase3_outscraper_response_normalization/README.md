# 第三段階：Outscraperレスポンスの商品候補正規化

## 1. 目的

第三段階では、Outscraper Amazon Products ScraperのレスポンスJSONを解析し、ランキングやUI表示で扱いやすい商品候補リストへ正規化する。

この段階では、Outscraper APIへのリクエスト、商品ランキング、Streamlit UI、ComfyUI連携は実装対象外とする。

対象範囲は以下に限定する。

```text
OutscraperレスポンスJSON
  ↓
商品配列の取り出し
  ↓
価格、画像URL、レビュー、カテゴリなどの正規化
  ↓
正規化済み商品候補JSON
```

## 2. サンプルレスポンス

実際のOutscraperレスポンスをもとに、サンプル用のダミーレスポンスを以下に用意している。

```text
cache/outscraper/amazon_products_dummy_response.json
```

実APIのレスポンスには商品URL、画像URL、商品名、価格などが含まれるため、サンプルでは値をダミー化している。JSON構造は、第二段階で取得したレスポンスと同じく `data` の中に商品配列が入る形式を想定する。

## 3. 実行方法

依存パッケージを入れる。

```sh
uv sync
```

サンプルレスポンスを正規化する。

```sh
uv run python phase3_outscraper_response_normalization/normalize_amazon_products.py
```

第二段階で保存したレスポンスJSONを指定して実行することもできる。

```sh
uv run python phase3_outscraper_response_normalization/normalize_amazon_products.py \
  --input cache/outscraper/amazon_sample_response.json
```

正規化結果をファイルに保存する場合は `--output` を指定する。

```sh
uv run python phase3_outscraper_response_normalization/normalize_amazon_products.py \
  --output cache/outscraper/amazon_products_normalized_sample.json
```

## 4. 正規化する項目

主な出力項目は以下とする。

| 項目 | 内容 |
|---|---|
| `asin` | Amazonの商品ID |
| `title` | 商品名 |
| `brand_or_store` | ストア名またはブランド名として扱う値 |
| `price_jpy` | 現在価格。数値化できない場合は `null` |
| `list_price_jpy` | 旧価格または取り消し線価格。数値化できない場合は `null` |
| `rating` | レビュー評価 |
| `review_count` | レビュー件数 |
| `categories` | カテゴリ階層 |
| `image_url` | 代表画像URL |
| `image_urls` | 商品画像URL一覧 |
| `product_url` | 商品ページURL |
| `short_url` | 短縮商品URL |
| `is_prime` | Prime対象かどうか |
| `availability` | 在庫状態 |
| `shipping` | 配送情報 |
| `source_query` | Outscraperへ渡した検索語 |
| `position` | 検索結果上の順位 |
| `description` | 商品説明 |

## 5. 完了条件

- ダミーレスポンスJSONを参照して正規化処理を実行できる
- `data` 配下の商品配列を取り出せる
- 価格、評価、レビュー件数を数値として扱える
- `high_res_images` と `image_1` 以降から画像URL一覧を作れる
- `asin` などを使って重複商品を除外できる

## 6. 関数詳細

### `string_list()`

Pydanticモデルでリスト型フィールドのデフォルト値を作るための補助関数。`Field(default_factory=list)` を返し、商品ごとに独立したリストを持てるようにする。

### `NormalizedAmazonProduct`

Outscraperの商品1件を、後続処理で扱いやすい形式へそろえるPydanticモデル。商品名、価格、レビュー、画像URL、商品URL、カテゴリ、在庫、配送情報などを保持する。

`title` は必須であり、商品名が取れない商品は `normalize_product()` で除外する。

### `read_json(path)`

指定したJSONファイルをUTF-8で読み込み、辞書として返す。第三段階では、OutscraperレスポンスJSONの読み込みに使う。

### `write_json(path, data)`

正規化済み商品候補をJSONファイルへ保存する。親ディレクトリがない場合は作成し、UTF-8、インデント付き、非ASCII文字を読める形式で出力する。

### `as_int(value)`

価格、レビュー件数、検索順位などを整数へ変換する。`int` はそのまま返し、`float` は小数部分を切り捨てる。文字列の場合は数字だけを抽出して整数化する。

`bool` と `None` は数値として扱わず `None` を返す。変換できない値も `None` にする。

### `as_float(value)`

レビュー評価などを浮動小数点数へ変換する。`bool` と `None` は `None` を返す。文字列、整数、小数はいったん `float()` に渡し、変換できない場合は `None` にする。

### `as_non_empty_string(value)`

値が文字列であれば前後空白を取り除き、空でなければ返す。文字列でない値や空文字は `None` にする。

### `as_string_list(value)`

Outscraperレスポンス内のカテゴリなどを文字列リストへ変換する。入力がリストでない場合は空リストを返す。リスト内では、文字列かつ空でない値だけを残す。

### `unique_strings(values)`

文字列リストから `None` と重複を除き、入力順を保って返す。画像URL一覧の重複除去に使う。

### `collect_image_urls(item)`

Outscraperの商品データから画像URL一覧を作る。まず `high_res_images` のURLを集め、続けて `image_1` から `image_10` までを確認する。

空値や重複は除外する。戻り値の先頭は代表画像 `image_url` として使われる。

### `iter_product_items(response)`

Outscraperレスポンスの `data` から商品辞書だけを取り出す。`data` の中に商品辞書が直接入っている場合と、商品辞書リストが入っている場合の両方に対応する。

`data` がリストでない場合は空リストを返す。

### `normalize_product(item)`

Outscraperの商品1件を `NormalizedAmazonProduct` へ変換する。商品名、ASIN、ストア名、価格、旧価格、通貨、評価、レビュー件数、カテゴリ、画像URL、商品URL、Prime対象、在庫、配送情報、検索語、順位、説明を正規化する。

商品名 `name` が空の場合は、後続で扱う最低限の情報がないため `None` を返す。

### `normalize_amazon_products_response(response)`

Outscraperレスポンス全体を正規化済み商品候補リストへ変換する。`iter_product_items()` で商品候補を取り出し、`normalize_product()` で1件ずつ正規化する。

重複判定には `asin`、`short_url`、`product_url`、`title` の順で利用する。すでに見たキーの商品は追加しない。

### `parse_args()`

CLI引数を定義する。入力JSONファイルと出力JSONファイルを受け取る。入力未指定時はダミーレスポンスを使い、出力未指定時は標準出力へ表示する。

### `main()`

CLI実行時の入口。入力JSONを読み込み、`normalize_amazon_products_response()` で正規化し、Pydanticモデルを辞書へ変換する。

`--output` が指定されていればファイルへ保存し、未指定なら標準出力へJSONを表示する。
