# 参考資料

## 目的

amazon-explorer の仕様確認、実装変更、障害調査で参照する一次資料をまとめる。アプリの現行挙動はコードとテスト、外部サービスやライブラリの現行仕様は対応する公式資料を正とする。

## 情報源の優先順位

対象ごとに情報源を使い分ける。

1. アプリが現在どう動くかは、現行コードとテストを確認する
2. 採用バージョン、Python要件、設定可能な名前は、`pyproject.toml`、`uv.lock`、`.env.example` を確認する
3. 外部サービスやライブラリが現在何を保証するかは、対象バージョンに対応する公式資料を確認する
4. 設計意図と運用手順は `docs/` の参照資料を確認し、上記の一次資料と矛盾する場合は文書を修正する
5. `examples/legacy-phases/` は経緯の確認だけに使い、現行仕様の根拠にはしない

公式仕様と現行コードが食い違う場合は、外部仕様に合わせて動くと推測せず、互換性の問題としてコード・テスト・文書を同時に確認する。

## リポジトリ内の一次資料

| 確認対象 | 一次資料 |
|---|---|
| 依存関係・Python要件 | [`pyproject.toml`](../pyproject.toml)、`uv.lock` |
| 設定名・既定値・制約 | [`src/config.py`](../src/config.py)、[`.env.example`](../.env.example) |
| データモデル | [`src/schemas.py`](../src/schemas.py) |
| 処理順序・キャッシュキー | [`src/main/run.py`](../src/main/run.py) |
| Bonsai通信 | [`src/clients/bonsai_client.py`](../src/clients/bonsai_client.py) |
| LLM systemプロンプト | [`src/clients/bonsai_prompt.md`](../src/clients/bonsai_prompt.md) |
| Outscraper通信・再試行・URL検証 | [`src/clients/outscraper_client.py`](../src/clients/outscraper_client.py) |
| 属性抽出 | [`src/services/user_attribute_extraction.py`](../src/services/user_attribute_extraction.py) |
| 商品正規化 | [`src/services/amazon_product_normalization.py`](../src/services/amazon_product_normalization.py) |
| 検索語選択 | [`src/services/outscraper_search_select.py`](../src/services/outscraper_search_select.py) |
| 分かち書き・文字列一致 | [`src/services/text_processing.py`](../src/services/text_processing.py) |
| ランキング | [`src/services/product_scoring.py`](../src/services/product_scoring.py) |
| JSONキャッシュ | [`src/repositories/cache_repository.py`](../src/repositories/cache_repository.py)、[`src/utilities/json_editor.py`](../src/utilities/json_editor.py) |
| Streamlit画面 | [`src/ui/streamlit_ui.py`](../src/ui/streamlit_ui.py)、[`app.py`](../app.py) |
| 回帰仕様 | [`tests/`](../tests/) |

## 外部の公式資料

| 対象 | 公式資料 | このリポジトリでの用途 |
|---|---|---|
| uv | [uv documentation](https://docs.astral.sh/uv/) | 依存同期、コマンド実行、ロックファイル管理 |
| Streamlit | [Streamlit documentation](https://docs.streamlit.io/) | ローカルWeb UI、session state、表示キャッシュ |
| Pydantic | [Pydantic documentation](https://docs.pydantic.dev/latest/) | 入出力モデル検証 |
| Pydantic Settings | [Pydantic Settings](https://docs.pydantic.dev/latest/concepts/pydantic_settings/) | `.env` と環境変数の読込・検証 |
| Requests | [Requests documentation](https://requests.readthedocs.io/) | Bonsai・Outscraper HTTP通信 |
| scikit-learn | [scikit-learn documentation](https://scikit-learn.org/stable/) | TF-IDFとコサイン類似度 |
| SudachiPy | [WorksApplications/SudachiPy](https://github.com/WorksApplications/SudachiPy) | 日本語の正規化と分かち書き |
| llama.cpp server | [llama-server documentation](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md) | Bonsai GGUFモデルのOpenAI互換API提供 |
| Outscraper | [Amazon Products API](https://docs.outscraper.com/endpoints/amazon-products/) | Amazon商品候補の非同期取得 |
| pytest | [pytest documentation](https://docs.pytest.org/) | 回帰テスト |
| Ruff | [Ruff documentation](https://docs.astral.sh/ruff/) | lintとformat確認 |

Outscraperの公式ページにはホスト名が異なる例が併記される場合がある。実行時の接続先は [`src/config.py`](../src/config.py) の `OUTSCRAPER_ENDPOINT` を正とし、変更時は公式仕様、結果URLのホスト制約、テストを同時に確認する。

## ローカル保存資料

`docs/API Docs _ Outscraper.html` は取得時点の外部HTMLであり、`.gitignore` 対象である。内容が古くなる可能性があるため、仕様変更の根拠には公式Web資料を使う。

## 参照時の確認事項

- 外部APIの料金、上限、レスポンス形状は利用前に公式資料で再確認する。
- 設計候補を実装済み機能として扱わない。
- 既定値を変更した場合は、コード、`.env.example`、関連文書、テストを同じ変更で更新する。
- 実API確認は、認証情報、課金、取得件数、待機時間を確認してから明示的に実施する。

関連資料: [索引](INDEX.md)、[バックエンド設計](BACKEND.md)、[制約](CONSTRAINTS.md)、[トラブルシューティング](TROUBLESHOOTING.md)
