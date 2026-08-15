# プロジェクトメモリ

## 1. 目的

この文書は、amazon-explorer を長期的に保守するために維持すべき、変化しにくい知識だけを記録する。日々の進捗は [WORKLOG.md](WORKLOG.md)、未完了作業は [TODO.md](TODO.md) と [TASKS.md](TASKS.md)、問題は [ISSUES.md](ISSUES.md) を使う。

一時的な調査結果、個人環境の絶対パス、シークレット、利用者入力、実キャッシュ、期限付きの担当者情報はここへ保存しない。

## 2. プロダクトの目的と範囲

amazon-explorer は、日本語の自然文から Amazon.co.jp の商品候補を取得し、条件への近さで順位付けするPythonアプリケーションである。

現行の中核機能:

1. ローカルBonsai OpenAI互換APIによる商品属性抽出
2. Outscraper Amazon Products APIによる候補取得
3. 外部レスポンスの内部モデルへの正規化
4. SudachiPyとTF-IDF、条件一致、価格、否定条件による採点
5. Streamlit UIとCLIからの実行
6. 段階ごとのローカルJSONキャッシュ

画像生成、画像類似度、ComfyUI、SSH連携、アプリ独自の認証、バックグラウンドジョブは現行機能ではない。将来候補を実装済みとして説明しない。

## 3. 権威ある情報源

変更時は、説明文より次の実装を優先して確認する。

| 知識 | 正とする場所 |
|---|---|
| 依存関係とPython要件 | `pyproject.toml` と `uv.lock` |
| 設定名、既定値、値制約 | `src/config.py` |
| 内部データモデル | `src/schemas.py` |
| パイプライン順序とキャッシュキー | `src/main/run.py` |
| Bonsai通信 | `src/clients/bonsai_client.py` |
| Outscraper通信とURL検証 | `src/clients/outscraper_client.py` |
| キャッシュのパス検証とTTL | `src/repositories/cache_repository.py` |
| UI表示とセッション状態 | `src/ui/streamlit_ui.py` |
| 現行動作の回帰保証 | `tests/` |

文書と実装が違う場合は、コードとテストで現状を確認し、同じ変更で文書を更新する。

## 4. アーキテクチャ上の境界

- `src/clients/`: 外部HTTPサービスとの通信とレスポンス形状の一次検証
- `src/services/`: 属性補正、検索語選択、商品正規化、テキスト処理、採点
- `src/repositories/`: キャッシュの保存先、TTL、読込失敗の扱い
- `src/main/run.py`: 4段階の検索を統合する唯一の共通入口
- `src/ui/`: Streamlit固有の状態と表示
- `src/schemas.py`: サービス間で渡すPydanticモデル
- `src/config.py`: 環境依存設定と値制約
- `src/paths.py`: リポジトリルートを基準にしたパス

StreamlitとCLIは同じ `run_product_search()` を呼ぶ。外部レスポンスをUIや採点へ直接渡さず、正規化したモデルを境界にする。

## 5. データフローの不変条件

```text
user_input: str
  -> Bonsai content: str
  -> ProductAttributes
  -> Outscraper query: str
  -> Outscraper response: dict
  -> list[NormalizedAmazonProduct]
  -> list[ProductScore]
```

- 空の利用者入力は外部通信前に拒否する
- Bonsaiの生応答を解析できないとき、生の内容を利用者向け例外へ含めない
- Outscraperの `data=[]` は正常な0件である
- 正規化ではタイトルのない商品と、明示通貨がJPY・USD以外の商品を除く
- USD価格は設定された固定 `USD_TO_JPY_RATE` で円換算する
- 採点結果は総合スコアの降順で返す

フィールドの完全な定義は [DB-SCHEMA.md](DB-SCHEMA.md)、計算方針は [BACKEND.md](BACKEND.md) を参照する。

## 6. キャッシュの基本知識

キャッシュは `CACHE_DIR`（既定 `cache/`）の下に段階別JSONとして保存する。

```text
product_attributes/
outscraper/raw/
outscraper/normalized/
outscraper/scored/
```

- 属性抽出には既定24時間、Outscraper生レスポンスには既定1時間のTTLがある
- 正規化と採点は内容および設定を含むキーで再利用し、読込TTLはない
- Streamlitはセッションごとのランダムscope、CLIは `local-cli` scopeをキーへ含める
- scopeは認証や認可ではない
- `--no-cache` と `use_cache=False` は読込だけを止め、新規結果は保存する
- JSON書込は一時ファイル、flush、`fsync`、置換の順で行う
- キャッシュキーは結果に影響する入力を含むが、APIキーは含めない

キャッシュの削除は利用者データの削除になり得る。対象を確認せず一括削除しない。

## 7. セキュリティ上の不変条件

- `.env`、`.streamlit/secrets.toml`、`cache/` はGitへ追加しない
- APIキーをURL、キャッシュキー、payload、画面、文書、テストデータへ入れない
- Outscraper endpointと結果URLはHTTPSを必須とする
- `results_location` はendpointと同じホスト・実効ポートだけを許可する
- APIキー付きリクエストのリダイレクトを許可しない
- UIは詳細例外をサーバーログへ残し、利用者には固定メッセージを表示する
- Streamlitセッションscopeをアクセス制御として扱わない

詳細と公開前の条件は [SECURITY.md](SECURITY.md) を参照する。

## 8. 開発と検証

依存関係は `uv` で管理する。標準コマンド:

```sh
uv sync --locked
uv run ruff check .
uv run ruff format --check .
uv run pytest
git diff --check
```

Pythonコードの変更では関連する単体テストを追加・更新する。外部APIを使う結合確認は、モックによるテストと区別し、Bonsai起動状態、Outscraper APIキー、課金、待ち時間を確認してから行う。

`tests/` は現行 `src/` を直接検証する。`examples/legacy-phases/` は開発段階の旧コードを保存した参照資料であり、現行仕様や回帰テストの対象ではない。

## 9. 変更時に同時更新するもの

| 変更 | 同時に確認するもの |
|---|---|
| 設定の追加・既定値変更 | `src/config.py`、`.env.example`、[CONSTRAINTS.md](CONSTRAINTS.md)、テスト |
| モデル変更 | `src/schemas.py`、[DB-SCHEMA.md](DB-SCHEMA.md)、キャッシュ互換性、テスト |
| 外部API変更 | client、[BACKEND.md](BACKEND.md)、[SECURITY.md](SECURITY.md)、モックテスト |
| UI変更 | `src/ui/streamlit_ui.py`、[FRONTEND.md](FRONTEND.md)、[UI.md](UI.md)、テスト |
| キャッシュキー変更 | `src/main/run.py` のキャッシュ版、保存互換性、テスト |
| 運用上の制約変更 | [CONSTRAINTS.md](CONSTRAINTS.md)、[TROUBLESHOOTING.md](TROUBLESHOOTING.md) |

## 10. この文書の更新基準

長期間維持する設計判断または安全上の不変条件が変わった場合だけ更新する。次はこの文書へ入れない。

- 今日だけ必要なコマンド出力
- 未検証の推測
- 一時的な障害や個別Issueの経過
- 進行中タスクのチェックリスト
- APIキー、検索語、商品結果、個人環境の絶対パス

履歴的事実は [WORKLOG.md](WORKLOG.md)、参照元は [REFERENCES.md](REFERENCES.md) へ分離する。
