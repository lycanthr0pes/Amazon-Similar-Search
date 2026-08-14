# AGENTS.md

## Project Overview

このリポジトリは、自然文から Amazon.co.jp の商品候補を取得し、条件への近さで順位付けする Python アプリケーション `amazon-explorer` である。

現行フロー:

1. `src/clients/bonsai_client.py` がローカル Bonsai OpenAI互換APIへ自然文を送る
2. `src/services/user_attribute_extraction.py` が応答を `ProductAttributes` に変換する
3. `src/clients/outscraper_client.py` が Outscraper の非同期タスクを作り、完了までポーリングする
4. `src/services/amazon_product_normalization.py` が商品候補を正規化する
5. `src/services/product_scoring.py` が TF-IDF、条件一致、価格、否定条件で採点する
6. `src/repositories/cache_repository.py` がTTLとキーを確認してJSONキャッシュを再利用する
7. `src/ui/streamlit_ui.py` または `src/main/run.py` が結果を表示する

依存関係は `pyproject.toml` と `uv.lock` で管理し、パッケージ管理には `uv` を使う。Makefile と Docker 設定は現時点では存在しない。

## Start-of-work checks

作業開始時に次を確認する。

1. `git status --short --branch` で既存差分を確認する
2. `pyproject.toml` と `uv.lock`、対象モジュール、関連テストを読む
3. `.env`、`cache/`、外部APIへ影響する操作かを確認する
4. ドキュメントの記述を実装済み機能と設計候補に分ける

シークレットの値は表示・記録しない。`.env` の存在確認だけで足りる場合は内容を読まない。

## Commands

セットアップ:

```sh
uv sync
cp .env.example .env
```

Streamlit:

```sh
uv run streamlit run app.py
```

CLI:

```sh
uv run python -m src.main.run "検索したい商品の説明"
```

キャッシュを読まずに再実行する場合:

```sh
uv run python -m src.main.run "検索したい商品の説明" --no-cache
```

検証:

```sh
uv run ruff check .
uv run ruff format --check .
uv run pytest
git diff --check
```

自動整形を要求された場合だけ次を使う。

```sh
uv run ruff format .
```

外部APIを伴う手動検索は、単体テストの完了条件へ暗黙に含めない。実行する場合は Bonsai の起動、Outscraper APIキー、課金と待ち時間を事前に確認する。

## Code Style

- Python 3.10以上を対象にする
- 新規・変更コードには可能な限り型ヒントを付ける
- 既存の `src/clients`、`src/services`、`src/utilities` の責務分割を保つ
- 設定値は `src/config.py` の `settings` を通し、ハードコードしない
- 外部レスポンスを UI や採点処理へ直接渡さず、Pydanticモデルへ正規化する
- 例外を握りつぶさず、利用者向けメッセージと診断情報を分ける
- ファイルパスは `src/paths.py` のプロジェクトルートまたは `settings.cache_dir` を基準にする
- 既存の日本語コメントとドキュメントの文体・粒度に合わせる

## Testing

変更箇所に対応する最小テストを追加・更新する。

- 属性抽出: 不正JSON、欠損値、文字列化された配列・価格を確認する
- Outscraperクライアント: HTTP通信をモックし、処理中、成功、失敗、待機超過を確認する
- 正規化: 欠損、通貨、価格文字列、重複、真偽値を確認する
- 採点: 日本語・英語、価格範囲、否定条件、空商品リストを確認する
- CLI: 終了コードと標準出力・標準エラーを確認する
- UI: 純粋関数を優先してテストし、外部APIは呼ばない

`tests/` は現行 `src/` を直接 import する回帰テストだけを置く。段階別に作成した旧コードは `examples/legacy-phases/` に保存しているが、現行仕様やテスト対象として扱わない。

## Documentation

- 現在の既定値は `src/config.py` を正とする
- 現在のモデル項目は `src/schemas.py` を正とする
- 実装されていないクラス、API、非同期ワーカー等は「設計候補（未実装）」と明記する
- 外部サービスの料金・仕様・URLは変わり得るため、断定が必要なら公式情報を確認する
- コマンドはリポジトリ内で実行できる形にする

## Git

- 既存差分を勝手に revert しない
- 要求に直接関係するファイルだけを編集する
- `.env`、`.venv/`、`cache/`、取得済み外部HTML、生成物をコミットしない
- `tests/` と Markdown の `docs/` は Git 管理対象にする
- `examples/legacy-phases/` は参照資料であり、現行実装の変更と混在させない
- コミットは1つの論理変更にまとめ、メッセージは命令形で簡潔にする

## Boundaries

- 無関係なリファクタリング、大規模リネーム、新規依存追加を行わない
- APIキーや認証情報をコード、ログ、ドキュメント、テストデータへ埋め込まない
- 外部API呼び出し、課金、長時間ポーリングを伴う確認は明示的な必要性がある場合だけ行う
- キャッシュやユーザーデータを削除する前に、対象と回復方法を確認する
- 実行できなかった検証と理由を完了報告へ記載する
