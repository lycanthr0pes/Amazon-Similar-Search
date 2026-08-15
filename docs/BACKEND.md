# バックエンド設計

## 1. 目的と範囲

この文書は、amazon-explorer の検索パイプライン、外部API境界、正規化、ランキング、設定、キャッシュ制御を説明する。現行バックエンドは独立したWeb APIサーバーではなく、Streamlit UIとCLIから直接呼ばれるPythonモジュール群である。

全体方針は [DESIGN.md](DESIGN.md)、内部モデルと保存形式は [DB-SCHEMA.md](DB-SCHEMA.md)、利用条件は [REQUIREMENTS.md](REQUIREMENTS.md)、既知の制約は [CONSTRAINTS.md](CONSTRAINTS.md)を参照する。

## 2. エントリーポイント

### 2.1 共通パイプライン

`src/main/run.py` の次の関数がUIとCLIの共通入口である。

```python
run_product_search(
    user_input: str,
    *,
    use_cache: bool = True,
    cache_scope: str = "local-cli",
) -> list[ProductScore]
```

入力検証:

- `user_input` は前後空白を除いた後に非空でなければならない
- `cache_scope` は前後空白を除いた後に1文字以上128文字以下でなければならない
- Streamlitはセッションごとにランダムな32桁16進文字列をscopeへ渡す
- CLIとscope未指定のPython呼出は `local-cli` を使う

### 2.2 Streamlit

```sh
uv run streamlit run app.py
```

`app.py` は `src.ui.streamlit_ui.main()` を呼ぶだけの薄いエントリーポイントである。画面設計は [FRONTEND.md](FRONTEND.md) と [UI.md](UI.md)を参照する。

### 2.3 CLI

```sh
uv run python -m src.main.run "静かで軽い日本語配列のワイヤレスキーボード"
```

| 引数 | 意味 |
|---|---|
| `user_input` | 必須の自然文検索条件 |
| `--display-limit N` | 上位N件を表示する。1以上 |
| `--no-cache` | 既存キャッシュを読まずに処理する。新規結果は保存する |

## 3. パイプライン

### 3.1 第1段階: 属性抽出

1. 入力、scope、Bonsai設定、systemプロンプトのSHA-256、生成設定から属性キャッシュキーを作る。
2. キャッシュが有効でTTL内なら `ProductAttributes` として再検証する。
3. ミスの場合はBonsaiを呼ぶ。
4. 応答JSONを補正し、`ProductAttributes` に変換して保存する。

### 3.2 第2段階: 検索語選択

`select_outscraper_query()` は次の優先順で先頭の検索語を選ぶ。

1. `search_queries_ja[0]`
2. `search_queries_en[0]`
3. `estimated_product_name_ja`

日本語または英語の検索語を選ぶ場合、空文字と `http://` / `https://` で始まる値を拒否する。

### 3.3 第3段階: 商品取得と正規化

1. scope、検索語、Outscraper検索設定から生レスポンスキーを作る。
2. キャッシュが有効でTTL内のJSON objectがあれば再利用する。
3. ミスの場合はOutscraperの非同期タスクを作成し、完了までポーリングする。
4. scope、生レスポンス全体、換算レート、正規化版から正規化キーを作る。
5. キャッシュを `NormalizedAmazonProduct` のリストとして再検証する。
6. ミスの場合は生レスポンスを正規化し、保存する。

### 3.4 第4段階: 採点

1. `ProductAttributes` 全体、正規化キー、すべての採点設定、採点版からキーを作る。
2. キャッシュを `ProductScore` のリストとして再検証する。
3. ミスの場合は全商品を採点し、総合スコア降順へ並べて保存する。
4. UIまたはCLIへリストを返す。

## 4. 設定

現行設定の正は `src/config.py` の `Settings` である。Pydantic SettingsがOS環境変数とリポジトリルートの `.env` を読む。環境変数名はフィールド名の大文字表記であり、`.env.example` は設定可能な名前を示す。

### 4.1 Bonsai

| 環境変数 | 既定値 | 制約・用途 |
|---|---|---|
| `BONSAI_BASE_URL` | `http://127.0.0.1:8080/v1` | OpenAI互換APIのbase URL |
| `BONSAI_MODEL` | `Bonsai-8B.gguf` | chat completionsへ渡すモデル名 |
| `BONSAI_TIMEOUT_SECONDS` | `60` | 正数。POSTのタイムアウト秒数 |
| `BONSAI_TEMPERATURE` | `0.1` | 0以上2以下 |
| `BONSAI_MAX_TOKENS` | `1000` | 正数 |
| `BONSAI_PROMPT_PATH` | `src/clients/bonsai_prompt.md` | systemプロンプト。相対値はプロジェクト基準 |

`/models` の疎通確認は設定値ではなく3秒のタイムアウトを使用し、Streamlit側で結果を5秒間キャッシュする。

### 4.2 Outscraper

| 環境変数 | 既定値 | 制約・用途 |
|---|---|---|
| `OUTSCRAPER_API_KEY` | 空 | `X-API-KEY`。検索実行時に必須 |
| `OUTSCRAPER_ENDPOINT` | `https://api.outscraper.cloud/amazon-products` | HTTPSのタスク作成先 |
| `OUTSCRAPER_DOMAIN` | `amazon.co.jp` | Amazonドメイン |
| `OUTSCRAPER_LANGUAGE` | `ja` | 表示言語 |
| `OUTSCRAPER_POSTAL_CODE` | `100-0001` | 配送地域。空なら送信しない |
| `OUTSCRAPER_LIMIT` | `100` | 正数。取得上限 |
| `USD_TO_JPY_RATE` | `160` | 正数。固定換算レート |
| `OUTSCRAPER_POLL_INTERVAL_SECONDS` | `30` | 正数。ポーリング間隔 |
| `OUTSCRAPER_MAX_POLLS` | `50` | 正数。最大ポーリング回数 |
| `OUTSCRAPER_REQUEST_TIMEOUT_SECONDS` | `30` | 正数。1要求のタイムアウト |
| `OUTSCRAPER_MAX_ATTEMPTS` | `3` | 正数。1要求の最大試行回数 |
| `OUTSCRAPER_RETRY_BACKOFF_SECONDS` | `1.0` | 0以上。指数バックオフの基準秒数 |

### 4.3 スコアリング

| 環境変数 | 既定値 | 制約・用途 |
|---|---:|---|
| `TITLE_SCORE_WEIGHT` | `0.45` | 0以上1以下 |
| `ATTRIBUTE_SCORE_WEIGHT` | `0.35` | 0以上1以下 |
| `PRICE_SCORE_WEIGHT` | `0.20` | 0以上1以下 |
| `REQUIRED_TERM_WEIGHT` | `4` | 0以上 |
| `COLOR_TERM_WEIGHT` | `3` | 0以上 |
| `FEATURE_TERM_WEIGHT` | `2` | 0以上 |
| `PREFERRED_TERM_WEIGHT` | `2` | 0以上 |
| `RELATED_TERM_WEIGHT` | `1` | 0以上 |

総合係数3つの合計は1.0でなければならない。条件語重み5つは、少なくとも1つを正にする。

### 4.4 キャッシュ、UI、ログ

| 環境変数 | 既定値 | 制約・用途 |
|---|---|---|
| `CACHE_DIR` | `cache` | 相対値はプロジェクト基準 |
| `ENABLE_CACHE` | `true` | 既存キャッシュの読込可否 |
| `LLM_CACHE_TTL_SECONDS` | `86400` | 正数。属性キャッシュTTL |
| `OUTSCRAPER_CACHE_TTL_SECONDS` | `3600` | 正数。生レスポンスTTL |
| `APP_ENV` | `local` | 定義済みだが現行処理では未参照 |
| `LOG_LEVEL` | `INFO` | 定義済みだが現行処理では未参照 |
| `SEARCH_RESULT_DISPLAY_LIMIT` | `10` | 正数。UI初期表示数、画面上限30 |
| `SHOW_DEBUG_INFO` | `false` | サイドバーへ一部採点設定を表示 |

空文字を数値、bool、Pathの項目として有効化すると型変換に失敗し得る。`.env.example` をコピーした後、利用する行だけコメントを外す。

## 5. Bonsai OpenAI互換API

### 5.1 属性抽出要求

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

応答はJSON object、非空の `choices`、object型の `message`、非空文字列の `content` を順に検証する。HTTP通信またはHTTP状態の失敗は `BonsaiRequestError`、JSONまたは形状の不正は `BonsaiResponseError` である。現行実装に再試行はない。

### 5.2 属性JSON補正

- コードフェンスを除き、JSON object候補を抽出する
- リスト項目の `null` を空リスト、文字列を1要素リストにする
- 価格文字列から通貨記号、`JPY`、桁区切りを除き、正の整数だけを採用する
- 0、負数、非整数、非有限値は価格未指定として `None` にする
- 明示価格帯と推定価格帯の上下限が逆なら入れ替える
- カテゴリに推定商品名や特徴からの根拠がなければ除く
- 空要素と大小文字を無視した重複を除き、検索語を再構成する

変換できない場合は、生のLLM応答を含めない固定メッセージの `ValueError` を送出する。

## 6. Outscraper Amazon Products API

### 6.1 タスク作成

```http
GET {OUTSCRAPER_ENDPOINT}?query=...&domain=amazon.co.jp&language=ja&limit=100&async=true&postal_code=100-0001
X-API-KEY: {OUTSCRAPER_API_KEY}
```

APIキーが空ならHTTP要求前に停止する。endpointはHTTPS、ホストあり、URL内認証情報なしでなければならない。`requests` の `params` で検索パラメータを渡し、APIキーはヘッダーだけに入れる。

### 6.2 タスク状態

| 内部状態 | 認識する値・条件 |
|---|---|
| pending | `pending`、`in progress`、`in_progress`、`processing` |
| failed | `failed`、`failure`、`error`、`cancelled`、`canceled` |
| success | `success`、`succeeded`、`complete`、`completed`、`done`、`finished`、`ok`、または `data` キーあり |
| unknown | 上記以外 |

`data=[]` は正常終了した0件である。完了レスポンスの `data` はリストでなければならない。初回応答がpendingなら `results_location` が必要である。

### 6.3 結果URLの検証

`results_location` へAPIキーを送る前に次を確認する。

- 文字列である
- HTTPSである
- ホストがある
- username、passwordをURLへ含まない
- 設定endpointとホスト・実効ポートが同じである

タスク作成と結果取得のどちらでもリダイレクトを許可しない。違反は `OutscraperSecurityError` とする。

### 6.4 再試行

次だけを、1要求につき `OUTSCRAPER_MAX_ATTEMPTS` まで再試行する。

- `requests.Timeout`
- `requests.ConnectionError`
- HTTP 429
- HTTP 5xx

試行間の待機は `base_delay * 2 ** (attempt - 1)` 秒である。その他の4xxは再試行しない。`Retry-After`、ジッター、接続・読取タイムアウトの分離は未実装である。

### 6.5 ポーリング

結果取得ごとに状態を分類し、successなら商品リストを返し、failedまたはunknownなら即時終了する。pendingのまま最大回数に達すると `OutscraperTaskTimeoutError` とする。最後のポーリング後に余分なsleepは行わない。

## 7. 商品正規化

正規化で参照する主なOutscraper項目:

- 構造: `data`
- 識別・名称: `name`、`asin`、`store_title`
- 価格: `price_parsed`、`price`、`old_price_parsed`、`strike_price_parsed`、`old_price`、`strike_price`
- 通貨推定: `currency`、`delivery_price`
- 評価: `rating`、`reviews`
- 分類・説明: `categories`、`description`
- 画像: `high_res_images`、`image_1` から `image_10`
- URL: `url`、`short_url`
- 配送等: `prime`、`availability`、`shipping`
- 出所: `query`、`position`

`data` の各要素が辞書なら商品として使い、リストならその中の辞書を1段だけ展開する。タイトルが空の商品と、明示通貨がJPY・USD以外の商品は除外する。

数値はboolを除外し、数値型または文字列中の最初の有限数値を使う。価格は負数を欠損扱いにし、USDだけ固定レートを掛ける。通貨値が空の場合は価格文字列中の `USD`、`$`、`JPY`、`¥`、`￥`、`円` から補完する。

Primeは真のbool、数値1、文字列 `1`、`true`、`yes`、`y` だけを真とする。重複はASIN、短縮URL、商品URL、タイトルの順で最初の利用可能な値をキーにする。

## 8. テキスト処理とランキング

### 8.1 トークン化

- 文字列は `casefold()` で小文字相当に正規化する
- 英数字は正規表現 `[a-z0-9]+` で抽出する
- 日本語はSudachiPyのSplitMode Cで解析する
- 日本語トークンは名詞、動詞、形容詞、形状詞かつ日本語文字を含むものに限る
- 語句全体の部分一致を先に試し、失敗した場合は分割語がすべて存在するかを確認する

### 8.2 TF-IDF

クエリと候補商品群を同じ `TfidfVectorizer` で学習し、コサイン類似度を求める。商品名はタイトルだけ、属性はタイトル、ストア名、カテゴリ、説明を使う。空データや語彙を作れない場合は0.0とする。

### 8.3 条件一致

必須語、色、特徴、優先語、関連語を設定重み付きで評価する。同じ正規化語が複数グループにあれば最初のグループだけを採用する。属性スコアにはTF-IDFと重み付き一致率の高い方を使う。

### 8.4 価格スコア

- 商品価格が正の整数でなければ0.0
- 目標価格があれば `min(price, target) / max(price, target)`
- 範囲内なら1.0、範囲外なら近い境界との比率
- 下限だけなら価格が下限以上で1.0
- 上限だけなら価格が上限以下で1.0
- `cheap` は推定上限が正なら `min(1.0, expected_max / price)`、なければ0.5
- `premium` は推定下限が正なら `min(1.0, 0.5 + 0.5 * log10(price / expected_min + 1.0))`、なければ0.5
- 価格指定がなければ0.5

### 8.5 総合値

```text
total = clamp(
    title_similarity * TITLE_SCORE_WEIGHT
    + attribute_similarity * ATTRIBUTE_SCORE_WEIGHT
    + price_score * PRICE_SCORE_WEIGHT
    - negative_penalty,
    0.0,
    1.0,
)
```

否定語は一致1件につき0.2、最大0.5である。各値を小数4桁へ丸め、総合値の降順へ並べる。

## 9. キャッシュ境界

`JsonCacheRepository` はrootを絶対パスへ解決する。namespaceの絶対パスと `..` を拒否し、キーは非空の小文字16進文字だけを許可する。ファイル不在、期限切れ、OSエラー、Unicodeエラー、JSON不正はキャッシュミスとして扱う。

属性、正規化、採点の復元時はPydanticで再検証し、失敗したら再計算する。生レスポンスもJSON objectでなければ再取得する。詳細は [DB-SCHEMA.md](DB-SCHEMA.md)を参照する。

## 10. 例外と出力

| 例外 | 意味 |
|---|---|
| `BonsaiRequestError` | Bonsai通信またはHTTP失敗 |
| `BonsaiResponseError` | BonsaiのJSONまたは形状不正 |
| `OutscraperRequestError` | Outscraper通信・HTTP失敗 |
| `OutscraperResponseError` | OutscraperのJSON・形状・状態不正 |
| `OutscraperSecurityError` | endpoint、結果URL、リダイレクトの安全条件違反 |
| `OutscraperTaskFailedError` | プロバイダー側タスク失敗 |
| `OutscraperTaskTimeoutError` | 最大ポーリング回数内に完了しない |
| `RuntimeError` | `OUTSCRAPER_API_KEY` が未設定 |
| `ValueError` | 空入力、不正なscope、URL形式の検索語、不正なキャッシュ形状 |

標準出力には処理段階、request ID、ポーリング回数・状態、キャッシュのヒットまたは保存先を出す。検索語、要求URL、結果URL、APIキーは出力しない。生成ファイルのローカルパスは出力される。

## 11. テスト境界

現行テストは外部通信をモックし、次を直接検証する。

- Bonsaiのパス解決、通信例外、JSON・応答形状
- Outscraperの状態分類、正常0件、失敗、待機超過、同一origin、リダイレクト拒否、再試行
- JPY・USD価格、Prime、商品正規化
- 属性JSONの価格補正、価格帯、応答秘匿
- TF-IDF補助、条件語重み、価格スコア、言語同点時の不足条件
- JSONキャッシュの原子的保存、TTL、破損、パス検証
- パイプラインのキー材料と完全キャッシュ再利用
- CLIの正数引数

```sh
uv run ruff check .
uv run ruff format --check .
uv run pytest
git diff --check
```

これらは実Bonsai・Outscraperとの結合試験ではない。実検索はAPIキー、料金、取得件数、タイムアウトを確認してから明示的に実施する。

## 12. 変更時のチェック

- `Settings` を変えたら `.env.example`、この文書、設定テストを更新する
- Bonsaiプロンプトを変えたら属性キャッシュキーのプロンプトハッシュにより再計算されることを確認する
- 外部レスポンスの解釈を変えたら正規化キャッシュ版を上げる
- 採点ロジックを変えたら採点キャッシュ版またはキー材料を更新する
- 外部APIキーを送る新しいURLは送信前に明示的な許可条件を設ける
- API失敗、商品0件、キャッシュミスを異なる結果として扱う
