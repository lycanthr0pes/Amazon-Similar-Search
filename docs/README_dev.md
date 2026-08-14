# amazon-explorer 開発者向け概要

## 1. 目的

amazon-explorer は、利用者が入力した日本語の要望から Amazon.co.jp の商品候補を取得し、条件への近さで順位付けするローカル実行向けアプリケーションである。

現行実装が扱う範囲は次のとおりである。

- Bonsai 8Bによる商品属性JSONの抽出
- Outscraper Amazon Products APIによる候補取得
- Outscraperレスポンスの内部モデルへの正規化
- SudachiPyとscikit-learnによるテキスト処理・TF-IDF類似度
- 条件一致、価格、否定条件を含むスコアリング
- Streamlit UIとCLI
- 各段階のJSONをローカルキャッシュへ保存

画像生成、画像類似度、SSH連携、利用者認証、バックグラウンドジョブは現行実装に含まれない。これらは必要になった時点で評価する設計候補である。

## 2. 実装構成

```text
app.py
src/
  clients/
    bonsai_client.py
    bonsai_prompt.md
    outscraper_client.py
  main/
    run.py
  services/
    user_attribute_extraction.py
    outscraper_search_select.py
    amazon_product_normalization.py
    text_processing.py
    product_scoring.py
  repositories/
    cache_repository.py
  ui/
    streamlit_ui.py
  utilities/
    build_hash.py
    json_editor.py
  config.py
  schemas.py
tests/
examples/
  legacy-phases/
docs/
```

`src/main/run.py` が処理を統合し、UIとCLIは同じ `run_product_search()` を呼ぶ。

## 3. データフロー

```text
user_input: str
  -> call_bonsai()
  -> raw_attributes: str
  -> extract_product_attributes()
  -> ProductAttributes
  -> select_outscraper_query()
  -> query: str
  -> call_outscraper()
  -> raw response JSON file
  -> normalize()
  -> list[NormalizedAmazonProduct]
  -> scoring()
  -> list[ProductScore]
```

処理中に次のファイルを作る。

- `cache/product_attributes/<attributes_key>.json`
- `cache/outscraper/raw/<raw_key>.json`
- `cache/outscraper/normalized/<normalized_key>.json`
- `cache/outscraper/scored/<scored_key>.json`

各キーは結果へ影響する入力を正規化してSHA-256へ渡し、先頭24桁を使う。属性キーにはキャッシュscope、利用者入力、モデル、プロンプトハッシュ、生成設定を含める。Outscraperキーにはscope、検索語、検索設定、正規化キーにはscope、生レスポンス、変換版、換算レート、採点キーには属性、正規化キー、全スコア設定を含める。

Streamlitはセッション開始時にランダムなscopeを作り、同一セッション内だけで再利用する。CLIは既定の `local-cli` scopeを使う。

## 4. 属性抽出

Bonsai には system メッセージとして `src/clients/bonsai_prompt.md`、user メッセージとして利用者入力を渡す。応答は文字列として受け取り、Markdownコードフェンスがあっても最初の `{` から最後の `}` までをJSON候補として切り出す。

`ProductAttributes` への変換前に次を補正する。

- リスト項目の `null` を空リストにする
- リスト項目が文字列なら1要素のリストにする
- 通貨記号・桁区切り付きの正の整数価格を整数にする
- 価格範囲の上下限が逆なら入れ替える
- 重複・空要素を除く
- 推定名、色、特徴、根拠のあるカテゴリから日本語検索語を再構成する

BonsaiクライアントはJSON object、`choices`、`message`、非空の `content` を検証し、通信失敗とレスポンス不正を専用例外へ分ける。属性JSONの構造とPydantic検証に失敗した場合は固定文言の `ValueError` とし、生のBonsai応答を例外へ含めない。`price_preference` の列挙値には、現時点で厳密なモデル制約がない。

## 5. 商品取得と正規化

Outscraper へ `async=true` のGETリクエストを送り、`results_location` が返れば完了までポーリングする。処理中、成功、失敗、不明を分け、失敗と待機超過は専用例外にする。結果URLはHTTPSかつ設定endpointと同一ホスト・ポートに限定し、リダイレクトを拒否してからAPIキーを送る。

接続失敗、タイムアウト、HTTP 429、5xxは既定3回まで指数バックオフで再試行する。その他の4xxは再試行しない。既定値は1要求30秒、30秒間隔、最大50回である。

正規化では、タイトルがない商品とJPY・USD以外と判定された商品を除く。ASIN、短縮URL、商品URL、タイトルの順で重複キーを選ぶ。通貨記号・桁区切り・小数を含む価格を解析し、USDは `USD_TO_JPY_RATE` でJPYへ換算する。Prime値はbool、0/1、代表的な真偽文字列を正規化する。

## 6. スコアリング

総合スコアは次の値を0から1へ丸める。

```text
0.45 * 商品名類似度
+ 0.35 * 属性類似度
+ 0.20 * 価格スコア
- 否定条件ペナルティ
```

条件語の既定繰り返し回数は次のとおりである。

| 条件 | 回数 |
|---|---:|
| 必須語 | 4 |
| 色 | 3 |
| 特徴語 | 2 |
| 優先語 | 2 |
| 関連語 | 1 |

商品名類似度と属性類似度は日本語・英語を別々に計算し、高い方を採用する。属性類似度はTF-IDFコサイン類似度と重み付き条件一致率の高い方である。否定語は1件につき0.2、最大0.5を総合スコアから減点する。

## 7. 実行

```sh
uv sync
cp .env.example .env
uv run streamlit run app.py
```

CLI:

```sh
uv run python -m src.main.run "静かで軽い日本語配列のワイヤレスキーボード"
```

キャッシュを読まずに外部処理から再実行する場合:

```sh
uv run python -m src.main.run "静かで軽い日本語配列のワイヤレスキーボード" --no-cache
```

`--no-cache` は読込だけを無効にし、新しい結果は保存する。

外部APIを使わない確認:

```sh
uv run ruff check .
uv run ruff format --check .
uv run pytest
git diff --check
```

## 8. 現在の制約

- Outscraper待機をStreamlitのリクエスト内で同期実行する
- Bonsai側のHTTP再試行はない
- キャッシュ書込はアトミックでStreamlitセッション間のキーも分離するが、ファイル配置は共通で、プロセス間ロック、容量上限、自動削除、認証ユーザー単位の永続分離がない
- 属性キャッシュとOutscraper生レスポンスにはTTLがあるが、正規化・採点ファイルの自動削除はない
- Streamlitの認証、レート制限、利用者別保存領域はない
- UIは詳細例外をログへ記録するが、構造化メトリクスとトレースはない

## 9. 設計候補（未実装）

本番運用が必要になった場合の候補であり、現行仕様ではない。

- Outscraper処理をバックグラウンドジョブへ移し、進捗をUIから照会する
- Bonsaiにも上限付き再試行を導入する
- 認証ユーザー単位の永続キャッシュ領域を分離する
- キャッシュ容量上限と削除方針を追加する
- 認証、課金上限、レート制限、監査ログを追加する
- 評価データセットを用意し、ランキング重みを計測に基づいて調整する
- 画像特徴を使う場合は、テキスト検索とは独立した追加段階として設計する

## 10. 関連資料

- `ENVIRONMENT_VARIABLES.md`: 現行設定名と既定値
- `EXTERNAL_API_SPEC.md`: Bonsai・Outscraper通信
- `DATA_MODEL_SPEC.md`: Pydanticモデル
- `CACHE_DESIGN.md`: 現行キャッシュと改善候補
- `PRODUCTION_DESIGN_GUIDE.md`: 本番化の優先順位

`tests/` は現行 `src` を直接検証する。過去の段階別コードは `examples/legacy-phases/` に参照用として保存し、現在の仕様とはみなさない。
