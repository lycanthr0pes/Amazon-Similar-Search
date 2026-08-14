# amazon-explorer

amazon-explorer は、日本語の自然文から Amazon.co.jp の商品候補を検索し、条件への近さで並べる Python アプリケーションである。ローカルの Bonsai 8B が入力を商品属性 JSON に変換し、Outscraper が商品候補を取得する。商品名・属性の TF-IDF 類似度、価格、除外条件を組み合わせて順位を決め、Streamlit または CLI で結果を確認できる。

## 実装フロー

```text
自然文
  -> Bonsai OpenAI互換APIで属性抽出
  -> Outscraper向け検索語を選択
  -> Amazon商品を非同期取得・ポーリング
  -> 商品データを正規化
  -> SudachiPy + TF-IDF + 条件一致 + 価格で採点
  -> Streamlit / CLIへ返却し、cache/へJSON保存
```

主な実装:

- `src/main/run.py`: 4段階の検索処理を統合
- `src/clients/`: Bonsai、Outscraperとの通信
- `src/services/`: 属性抽出、検索語選択、正規化、テキスト処理、採点
- `src/repositories/`: TTL付きJSONキャッシュの読込・保存
- `src/schemas.py`: Pydanticデータモデル
- `src/ui/streamlit_ui.py`: Streamlit UI
- `tests/`: 現行 `src` を直接検証する回帰テスト
- `examples/legacy-phases/`: 段階別に作成した旧検証コードの参照用スナップショット

## 必要なもの

- Python 3.10以上
- [uv](https://docs.astral.sh/uv/)
- OpenAI互換APIとして起動した Bonsai 8B
- Outscraper APIキー

## セットアップ

```sh
uv sync
cp .env.example .env
```

`.env` には最低限 `OUTSCRAPER_API_KEY` を設定する。Bonsai の接続先や Outscraper の取得条件を変更する場合は、[環境変数一覧](docs/ENVIRONMENT_VARIABLES.md)を参照する。実値を `.env.example` や Git 管理ファイルへ書かないこと。

## Bonsai 8B

llama.cpp をビルドし、GGUFモデルを用意する。

```sh
git clone https://github.com/ggml-org/llama.cpp.git
cd llama.cpp
cmake -B build
cmake --build build --config Release -j 2
```

モデルの配置先に合わせてサーバーを起動する。アプリの既定接続先は `http://127.0.0.1:8080/v1`、既定モデル名は `Bonsai-8B.gguf` である。

```sh
/path/to/llama.cpp/build/bin/llama-server \
  -m /path/to/Bonsai-8B.gguf \
  --host 127.0.0.1 \
  --port 8080
```

## Outscraper

`.env` に APIキーを設定する。

```dotenv
OUTSCRAPER_API_KEY=your_api_key
```

既定では `amazon.co.jp`、言語 `ja`、郵便番号 `100-0001`、最大100件を指定する。APIキーは `X-API-KEY` ヘッダーで送信される。

## 起動

Streamlit:

```sh
uv run streamlit run app.py
```

CLI:

```sh
uv run python -m src.main.run "静かで軽い日本語配列のワイヤレスキーボード"
```

CLI の表示件数は `--display-limit` で変更できる。

```sh
uv run python -m src.main.run "1万円以内の白いワイヤレスキーボード" --display-limit 5
```

既存キャッシュを読まずに外部処理からやり直す場合は `--no-cache` を付ける。この指定でも新しい結果はキャッシュへ保存される。

## テストと静的確認

```sh
uv run ruff check .
uv run ruff format --check .
uv run pytest
git diff --check
```

外部APIを使う検索は単体テストとは別である。実行時は Bonsai の起動、Outscraper の認証、API利用料金を確認する。

## 現在の注意点

- 検索処理は同期実行であり、Outscraper の完了まで画面が待機する。
- 属性抽出キャッシュは既定24時間、Outscraper生レスポンスは既定1時間再利用する。正規化・採点結果は内容と設定を含むキーで再利用する。
- Streamlitはセッションごとにランダムなキャッシュscopeを持ち、セッション間でキーを分離する。CLIは `local-cli` scopeを継続利用する。
- JSON書込はアトミックだが、プロセス間ロック、容量上限、自動削除、利用者別の保存領域は未実装である。
- Outscraper は一時的な通信失敗、HTTP 429、5xxを再試行する。Bonsaiの再試行は未実装である。
- ファイル配置は共通であり、認証ユーザー単位の永続領域、構造化メトリクス、分散トレース、認証、レート制限は未実装である。
- ComfyUI、画像生成、画像類似度は現行実装に含まれない。追加する場合は設計候補として別途検討する。

## 設計資料

- [開発者向け概要](docs/README_dev.md)
- [本番設計ガイド](docs/PRODUCTION_DESIGN_GUIDE.md)
- [外部API仕様](docs/EXTERNAL_API_SPEC.md)
- [環境変数一覧](docs/ENVIRONMENT_VARIABLES.md)
- [データモデル仕様](docs/DATA_MODEL_SPEC.md)
- [キャッシュ設計](docs/CACHE_DESIGN.md)
