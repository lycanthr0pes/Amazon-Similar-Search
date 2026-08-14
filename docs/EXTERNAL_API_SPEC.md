# 外部API仕様

## 1. 対象範囲

現行実装が直接利用する外部HTTP APIは次の2つである。

- ローカル Bonsai 8B の OpenAI互換API
- Outscraper Amazon Products API

画像生成APIやアプリ独自のHTTP APIは現行実装に含まれない。追加する場合は設計候補として別仕様を作る。

## 2. Bonsai OpenAI互換API

### 2.1 接続設定

| 項目 | 現行値 |
|---|---|
| Base URL | `BONSAI_BASE_URL`。既定値 `http://127.0.0.1:8080/v1` |
| Model | `BONSAI_MODEL`。既定値 `Bonsai-8B.gguf` |
| Timeout | `BONSAI_TIMEOUT_SECONDS`。既定値60秒 |
| Temperature | `BONSAI_TEMPERATURE`。既定値0.1、許可範囲0から2 |
| Max tokens | `BONSAI_MAX_TOKENS`。既定値1000 |
| Prompt | `BONSAI_PROMPT_PATH`。既定値はプロジェクト内 `src/clients/bonsai_prompt.md` |

### 2.2 属性抽出

```http
POST {BONSAI_BASE_URL}/chat/completions
Content-Type: application/json
```

```json
{
  "model": "Bonsai-8B.gguf",
  "messages": [
    {"role": "system", "content": "商品属性抽出プロンプト"},
    {"role": "user", "content": "利用者の自然文"}
  ],
  "temperature": 0.1,
  "max_tokens": 1000
}
```

HTTP成功確認後、JSON object、非空の `choices`、object型の `message`、非空文字列の `content` を順に検証する。通信とHTTPエラーは `BonsaiRequestError`、JSONまたはレスポンス形状の不正は `BonsaiResponseError` とする。再試行はない。

応答を `ProductAttributes` にできない場合は固定文言の `ValueError` とし、生のモデル応答を例外メッセージへ含めない。

### 2.3 疎通確認

```http
GET {BONSAI_BASE_URL}/models
```

疎通確認のタイムアウトは3秒である。結果はStreamlit側で5秒間キャッシュする。

## 3. Outscraper Amazon Products API

### 3.1 接続設定

| 項目 | 現行値 |
|---|---|
| Endpoint | `OUTSCRAPER_ENDPOINT`。既定値 `https://api.outscraper.cloud/amazon-products` |
| API key | `OUTSCRAPER_API_KEY`。既定値なし、実行時必須 |
| Domain | `OUTSCRAPER_DOMAIN`。既定値 `amazon.co.jp` |
| Language | `OUTSCRAPER_LANGUAGE`。既定値 `ja` |
| Postal code | `OUTSCRAPER_POSTAL_CODE`。既定値 `100-0001` |
| Limit | `OUTSCRAPER_LIMIT`。既定値100 |
| HTTP timeout | `OUTSCRAPER_REQUEST_TIMEOUT_SECONDS`。既定値30秒 |
| Poll interval | `OUTSCRAPER_POLL_INTERVAL_SECONDS`。既定値30秒 |
| Max polls | `OUTSCRAPER_MAX_POLLS`。既定値50回 |
| Max attempts | `OUTSCRAPER_MAX_ATTEMPTS`。既定値3回 |
| Retry base delay | `OUTSCRAPER_RETRY_BACKOFF_SECONDS`。既定値1.0秒 |

### 3.2 タスク作成

```http
GET {OUTSCRAPER_ENDPOINT}?query=...&domain=amazon.co.jp&language=ja&limit=100&async=true&postal_code=100-0001
X-API-KEY: {OUTSCRAPER_API_KEY}
```

| パラメータ | 型 | 説明 |
|---|---|---|
| `query` | string | Bonsai属性から選択した検索語 |
| `domain` | string | Amazonドメイン |
| `language` | string | 表示言語 |
| `postal_code` | string | 配送地域。空なら送らない |
| `limit` | integer | 最大取得件数 |
| `async` | string | 現行検索では `true` |

APIキーが空ならHTTP要求前に `RuntimeError` とする。endpointはHTTPS、ホストあり、URL内認証情報なしであることを確認する。リダイレクトは許可しない。

### 3.3 状態分類

タスク作成レスポンスまたはポーリングレスポンスを次へ分類する。

| 内部状態 | 認識する値・条件 |
|---|---|
| pending | `pending`、`in progress`、`in_progress`、`processing` |
| failed | `failed`、`failure`、`error`、`cancelled`、`canceled` |
| success | `success`、`succeeded`、`complete`、`completed`、`done`、`finished`、`ok`、または `data` キーあり |
| unknown | 上記以外 |

`data=[]` は成功した0件として扱う。失敗は `OutscraperTaskFailedError`、不明または必要項目欠落は `OutscraperResponseError`、最大回数まで処理中なら `OutscraperTaskTimeoutError` とする。

### 3.4 結果URL

`results_location` へAPIキーを送る前に次を確認する。

- 文字列である
- HTTPSである
- ホストがある
- URL内にusernameとpasswordがない
- endpointとホスト・ポートが同じである

条件を満たさない場合は `OutscraperSecurityError` とする。結果取得でもリダイレクトは拒否する。

### 3.5 再試行

次だけを最大試行回数まで再試行する。

- `requests.Timeout`
- `requests.ConnectionError`
- HTTP 429
- HTTP 5xx

待機時間は `base_delay * 2 ** (attempt - 1)` である。その他の4xxは再試行せず `OutscraperRequestError` とする。最終試行後も一時障害なら同じ専用例外へ包む。

### 3.6 正規化で参照する主な項目

- `data`
- `name`、`asin`、`store_title`
- `price_parsed`、`price`、`old_price_parsed`、`strike_price_parsed`
- `currency`、`rating`、`reviews`
- `categories`、`description`
- `high_res_images`、`image_1` から `image_10`
- `url`、`short_url`、`prime`、`availability`、`shipping`
- `query`、`position`

レスポンス全体はJSON objectでなければ `OutscraperResponseError` とする。成功レスポンスの `data` が商品リストとして解釈できなければ、正規化結果は0件となる。

## 4. キャッシュとの関係

属性抽出は既定24時間、Outscraper生レスポンスは既定1時間再利用する。有効な生レスポンスがあればOutscraper APIを呼ばない。Streamlitはセッションごとのランダムscope、CLIは `local-cli` scopeをキーへ含める。CLIの `--no-cache` は読込を無効にするため、外部APIを再実行する。

APIキーはキャッシュキーとJSON payloadに含めない。

## 5. セキュリティと運用

- APIキーは `.env` または実行環境のシークレット機構で管理する
- `.env`、ヘッダー、APIキーをGitへ追加しない
- 利用者入力はBonsaiとOutscraperへ送られ、属性と商品結果はローカルJSONへ保存される
- 検索URL、結果URL、ポーリング状態は現行コードで標準出力される
- Streamlitは詳細例外をサーバーログへ記録し、利用者には固定メッセージを表示する

本番向けの設計候補（未実装）:

- 検索内容と結果URLをマスキングした構造化ログ
- Bonsaiの上限付き再試行
- 接続タイムアウトと読取タイムアウトの分離
- バックオフへのジッターと `Retry-After` 対応
- 非同期ジョブ、キャンセル、進捗API
- 利用者ごとのAPI利用量制限

## 6. 実装確認

外部通信を発生させない回帰確認:

```sh
uv run pytest tests/test_outscraper_client.py tests/test_run_pipeline.py
uv run ruff check .
```

実APIとの結合確認は、APIキー、利用料金、取得件数、タイムアウトを確認してから明示的に実施する。
