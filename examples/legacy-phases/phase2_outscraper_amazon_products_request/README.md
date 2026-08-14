# 第二段階：Outscraper Amazon Products Scraper疎通確認

## 1. 目的

第二段階では、第一段階で生成するAmazon検索語を、Outscraper Amazon Products Scraperへ渡し、レスポンスJSONを受け取れることを確認する。

この段階では、商品候補正規化、ランキング、Streamlit UI、ComfyUI連携は実装対象外とする。

対象範囲は以下に限定する。

```text
Amazon検索語
  ↓
Outscraper Amazon Products Scraper
  ↓
非同期ジョブ作成
  ↓
results_locationをポーリング
  ↓
レスポンスJSON
```

## 2. 前提条件

- Python 3.10以上を利用できる
- `uv` を利用できる
- Outscraper APIキーを保持している
- `OUTSCRAPER_API_KEY` を `.env` またはシェル環境変数で設定している

```env
OUTSCRAPER_API_KEY=xxxxxxxx
```

APIキーは `X-API-KEY` ヘッダーで送る。検索語やURLクエリにはAPIキーを含めない。

このサンプルでは、入力値をAmazon URLではなく検索語に限定する。`http://` または `https://` で始まる値を渡した場合はエラーにする。

## 3. 実行方法

依存パッケージを入れる。

```sh
uv sync
```

サンプル検索語で実行する。

```sh
uv run python phase2_outscraper_amazon_products_request/fetch_amazon_products.py \
  --limit 10
```

サンプル検索語は以下とする。

```text
ノイズキャンセリング 小型 ワイヤレスイヤホン ブラック
```

検索語を指定して実行することもできる。

```sh
uv run python phase2_outscraper_amazon_products_request/fetch_amazon_products.py \
  "wireless earbuds noise cancelling black" \
  --limit 10
```

レスポンスJSONをファイルに保存する場合は `--output` を指定する。

```sh
uv run python phase2_outscraper_amazon_products_request/fetch_amazon_products.py \
  "wireless earbuds noise cancelling black" \
  --limit 10 \
  --output cache/outscraper/amazon_wireless_earbuds_sample.json
```

ジョブが長く待機する場合は、ポーリング間隔と確認回数を調整する。

```sh
uv run python phase2_outscraper_amazon_products_request/fetch_amazon_products.py \
  --limit 1 \
  --poll-interval 30 \
  --max-polls 50
```

Outscraper Amazon Products Scraperのレスポンスは、7分から25分程度かかる場合がある。標準設定では、30秒間隔で50回確認し、最大約25分待機する。

指定した回数内に完了しない場合は、例外で終了せず、`status: Pending` と `results_location` を含むJSONを返す。

## 4. パラメータ

標準値は以下とする。

| 項目 | 値 |
|---|---|
| endpoint | `https://api.outscraper.cloud/amazon-products` |
| domain | `amazon.co.jp` |
| language | `ja` |
| limit | `10` |
| async | `true` |
| poll interval | `30` 秒 |
| max polls | `50` 回 |

endpointを変更する場合は、環境変数または `--endpoint` で指定する。

```env
OUTSCRAPER_AMAZON_PRODUCTS_ENDPOINT=https://api.outscraper.cloud/amazon-products
```

## 5. 完了条件

- `Request URL:` としてOutscraperへ送る検索語入りURLを確認できる
- `Request ID:` と `Results location:` を確認できる
- `OUTSCRAPER_API_KEY` をコードに直書きせずに送信できる
- OutscraperからJSONレスポンスを受け取れる
- 必要に応じてレスポンスJSONをファイルへ保存できる

## 6. 関数詳細

### `validate_search_query(query)`

検索語の前後空白を取り除き、空文字でないことを確認する。`http://` または `https://` で始まる値はAmazon URLとみなし、検索語ではないため `ValueError` にする。

戻り値は正規化済みの検索語であり、以降のリクエスト生成ではこの値を使う。

### `build_amazon_products_params(query, domain, language, limit, async_request)`

Outscraper Amazon Products Scraperへ渡すURLクエリパラメータを作る。`query` は `validate_search_query()` で検証する。

返す辞書には以下を含める。

| キー | 内容 |
|---|---|
| `query` | Amazon検索語 |
| `domain` | 対象Amazonドメイン |
| `language` | 表示言語 |
| `limit` | 取得件数の上限 |
| `async` | 非同期リクエストにするかどうか |

`async` はOutscraper APIへ渡しやすいように、Pythonの真偽値ではなく `"true"` または `"false"` の文字列に変換する。

### `build_amazon_products_request_url(query, endpoint, domain, language, limit, async_request)`

確認用のリクエストURLを作る。`build_amazon_products_params()` の結果を `urlencode()` でエンコードし、endpointの後ろに付与する。

このURLにはAPIキーを含めない。APIキーは実リクエスト時に `X-API-KEY` ヘッダーで送る。

### `submit_amazon_products_request(query, api_key, endpoint, domain, language, limit, timeout)`

Outscraper Amazon Products Scraperへ非同期リクエストを送信する。内部では `async_request=True` のパラメータを作り、`requests.get()` で送信する。

HTTPステータスがエラーの場合は `raise_for_status()` で例外にする。成功時はJSONレスポンスを辞書として返す。

レスポンスに `results_location` が含まれる場合、後続のポーリング対象になる。

### `fetch_request_result(results_location, api_key, timeout)`

`submit_amazon_products_request()` で得た `results_location` にGETリクエストを送り、現在のジョブ結果を取得する。APIキーはここでも `X-API-KEY` ヘッダーで送る。

成功時はJSONレスポンスを辞書として返す。

### `is_pending_result(data)`

Outscraperのレスポンスがまだ処理中かを判定する。`status` を小文字化し、`pending`、`in progress`、`in_progress`、`processing` のいずれかであれば `True` を返す。

この関数により、Outscraper側の表記ゆれを吸収する。

### `fetch_amazon_products(query, api_key, endpoint, domain, language, limit, request_timeout, poll_interval, max_polls)`

第二段階の中心処理。まず `submit_amazon_products_request()` でジョブを作成し、`results_location` が返った場合は `fetch_request_result()` を繰り返して完了を待つ。

処理の流れは以下とする。

```text
検索語を送信
  ↓
results_locationを取得
  ↓
指定間隔でポーリング
  ↓
pendingでなくなったら結果を返す
```

`results_location` がない場合は、送信時レスポンスをそのまま返す。最大ポーリング回数を超えても処理中の場合は例外にせず、最後のレスポンスに `results_location` と説明文を追加して返す。

### `write_json(path, data)`

レスポンスJSONをファイルへ保存する。親ディレクトリが存在しない場合は作成し、UTF-8、インデント付き、非ASCII文字をそのまま読める形式で出力する。

### `parse_args()`

CLI引数を定義する。検索語、取得件数、Amazonドメイン、表示言語、endpoint、出力先、ポーリング間隔、最大ポーリング回数、リクエストタイムアウトを受け取る。

### `main()`

CLI実行時の入口。`.env` を読み込み、引数を解析し、`OUTSCRAPER_API_KEY` を取得する。APIキーが未設定の場合は `RuntimeError` にする。

その後、確認用の `Request URL:` を表示し、`fetch_amazon_products()` でレスポンスを取得する。`--output` が指定されていればファイルへ保存し、未指定なら標準出力へJSONを表示する。
