# 環境変数一覧

## 1. 基本方針

現行設定は `src/config.py` の `Settings` を正とする。Pydantic Settings がOS環境変数とプロジェクトルートの `.env` を読み込む。環境変数名はフィールド名を大文字にした名前を使う。

`.env` にはローカルの実値を設定し、Gitへ追加しない。`.env.example` は設定可能な名前を値なしで示す。

## 2. Bonsai

| 環境変数 | 既定値 | 制約・用途 |
|---|---|---|
| `BONSAI_BASE_URL` | `http://127.0.0.1:8080/v1` | OpenAI互換APIのbase URL |
| `BONSAI_MODEL` | `Bonsai-8B.gguf` | `/chat/completions` へ渡すモデル名 |
| `BONSAI_TIMEOUT_SECONDS` | `60` | 正数。属性抽出POSTのタイムアウト秒数 |
| `BONSAI_TEMPERATURE` | `0.1` | 0から2 |
| `BONSAI_MAX_TOKENS` | `1000` | 正数。応答の最大トークン数 |
| `BONSAI_PROMPT_PATH` | プロジェクト内 `src/clients/bonsai_prompt.md` | systemプロンプトのパス |

`/models` の疎通確認は環境変数ではなく、コード内で3秒のタイムアウトを使う。

## 3. Outscraper

| 環境変数 | 既定値 | 制約・用途 |
|---|---|---|
| `OUTSCRAPER_API_KEY` | 空 | `X-API-KEY` ヘッダー。検索実行時は必須 |
| `OUTSCRAPER_ENDPOINT` | `https://api.outscraper.cloud/amazon-products` | HTTPS endpoint |
| `OUTSCRAPER_DOMAIN` | `amazon.co.jp` | 対象Amazonドメイン |
| `OUTSCRAPER_LANGUAGE` | `ja` | Amazon表示言語 |
| `OUTSCRAPER_POSTAL_CODE` | `100-0001` | 配送地域 |
| `OUTSCRAPER_LIMIT` | `100` | 正数。取得件数上限 |
| `USD_TO_JPY_RATE` | `160` | 正数。USDからJPYへの固定換算レート |
| `OUTSCRAPER_POLL_INTERVAL_SECONDS` | `30` | 正数。結果確認間隔 |
| `OUTSCRAPER_MAX_POLLS` | `50` | 正数。最大結果確認回数 |
| `OUTSCRAPER_REQUEST_TIMEOUT_SECONDS` | `30` | 正数。1回のHTTP要求のタイムアウト秒数 |
| `OUTSCRAPER_MAX_ATTEMPTS` | `3` | 正数。1要求の最大試行回数 |
| `OUTSCRAPER_RETRY_BACKOFF_SECONDS` | `1.0` | 0以上。指数バックオフの基準秒数 |

APIキーはURL、キャッシュキー、JSON payload、標準出力へ含めない。固定為替レートは実勢レートを自動取得しない。

## 4. スコアリング

| 環境変数 | 既定値 | 制約・用途 |
|---|---:|---|
| `TITLE_SCORE_WEIGHT` | `0.45` | 0から1。商品名類似度の総合係数 |
| `ATTRIBUTE_SCORE_WEIGHT` | `0.35` | 0から1。属性類似度の総合係数 |
| `PRICE_SCORE_WEIGHT` | `0.20` | 0から1。価格スコアの総合係数 |
| `REQUIRED_TERM_WEIGHT` | `4` | 0以上。必須語の重み・繰り返し回数 |
| `COLOR_TERM_WEIGHT` | `3` | 0以上。色語の重み |
| `FEATURE_TERM_WEIGHT` | `2` | 0以上。特徴語の重み |
| `PREFERRED_TERM_WEIGHT` | `2` | 0以上。優先語の重み・繰り返し回数 |
| `RELATED_TERM_WEIGHT` | `1` | 0以上。関連語の重み・繰り返し回数 |

3つの総合係数は合計1.0でなければ起動時エラーになる。5つの条件語重みは、少なくとも1つを正にする。

## 5. キャッシュ

| 環境変数 | 既定値 | 制約・用途 |
|---|---|---|
| `CACHE_DIR` | プロジェクト内 `cache` | JSONキャッシュのルート |
| `ENABLE_CACHE` | `true` | 検索時のキャッシュ読込を有効化 |
| `LLM_CACHE_TTL_SECONDS` | `86400` | 正数。属性抽出キャッシュのTTL |
| `OUTSCRAPER_CACHE_TTL_SECONDS` | `3600` | 正数。生レスポンスキャッシュのTTL |

`ENABLE_CACHE=false` でも新しい結果は保存する。正規化・採点結果は入力内容と設定を含むキーで再利用し、現時点では個別TTLを持たない。

## 6. UIとログ

| 環境変数 | 既定値 | 制約・用途 |
|---|---|---|
| `APP_ENV` | `local` | 設定として定義済み。現行処理では未参照 |
| `LOG_LEVEL` | `INFO` | 設定として定義済み。現行処理では未参照 |
| `SEARCH_RESULT_DISPLAY_LIMIT` | `10` | 正数。Streamlit表示件数の初期値、画面上限30 |
| `SHOW_DEBUG_INFO` | `false` | bool。重みをサイドバーへ表示するか |

## 7. `.env.example`

リポジトリの `.env.example` は、任意項目をコメント化した空代入として列挙する。コピー後、設定する項目だけコメントを外す。

```sh
cp .env.example .env
chmod 600 .env
```

最小構成では次へ実値を入れる。

```dotenv
OUTSCRAPER_API_KEY=your_api_key
```

空文字を整数、float、bool、Pathの設定として有効化すると型変換に失敗する場合がある。利用しない任意項目はコメントのままにする。

## 8. 現行設定にない項目

次は現行 `Settings` に存在せず、設定しても参照されない。

- 正規化・採点キャッシュのTTL、容量上限、利用者名前空間
- 認証、レート制限、ジョブキュー
- 画像生成、画像類似度
- 構造化ログ出力先、メトリクス送信先

追加する場合は設計候補（未実装）として要件を確定し、`Settings`、`.env.example`、この文書、テストを同じ変更で更新する。

## 9. 管理上の注意

- `.env` の実値をコミットしない
- シークレットをコマンド履歴、スクリーンショット、例外メッセージへ残さない
- 本番ではファイルより実行環境のシークレット管理機構を優先する
- タイムアウト、取得件数、ポーリング回数、再試行回数を変更すると待ち時間とAPI利用量が変わる
- `CACHE_DIR` を共有場所へ変更する場合は、権限、利用者分離、容量上限を設計する
