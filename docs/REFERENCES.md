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
| AIレビューの基本契約・policy・judge・CLI | [`tools/ai_review/models.py`](../tools/ai_review/models.py)、[`tools/ai_review/policy.py`](../tools/ai_review/policy.py)、[`tools/ai_review/judge.py`](../tools/ai_review/judge.py)、[`tools/ai_review/cli.py`](../tools/ai_review/cli.py) |
| trusted release・workflow初期化・import前preflight・deployment check | [`tools/ai_review/runtime_release.py`](../tools/ai_review/runtime_release.py)、[`tools/ai_review/workflow_init.py`](../tools/ai_review/workflow_init.py)、[`tools/ai_review/external_launcher.py`](../tools/ai_review/external_launcher.py)、[`tools/ai_review/preflight.py`](../tools/ai_review/preflight.py)、[`tools/ai_review/deployment_check.py`](../tools/ai_review/deployment_check.py) |
| sensitive path・snapshot・offline evidence | [`tools/ai_review/sensitive_paths.py`](../tools/ai_review/sensitive_paths.py)、[`tools/ai_review/snapshot.py`](../tools/ai_review/snapshot.py)、[`tools/ai_review/offline_runner.py`](../tools/ai_review/offline_runner.py) |
| offline prepare/outer/finalize | [`tools/ai_review/offline_phase_protocol.py`](../tools/ai_review/offline_phase_protocol.py)、[`tools/ai_review/offline_outer_executor.py`](../tools/ai_review/offline_outer_executor.py)、[`tools/ai_review/phase_execution_adapters.py`](../tools/ai_review/phase_execution_adapters.py) |
| bounded packet・broker・固定egress | [`tools/ai_review/review_packet.py`](../tools/ai_review/review_packet.py)、[`tools/ai_review/codex_adapter.py`](../tools/ai_review/codex_adapter.py)、[`tools/ai_review/broker_executor.py`](../tools/ai_review/broker_executor.py)、[`tools/ai_review/broker_egress_provisioner.py`](../tools/ai_review/broker_egress_provisioner.py) |
| broker prepare/outer/frozen ledger/finalize | [`tools/ai_review/broker_phase_protocol.py`](../tools/ai_review/broker_phase_protocol.py)、[`tools/ai_review/broker_outer_executor.py`](../tools/ai_review/broker_outer_executor.py)、[`tools/ai_review/phase_execution_adapters.py`](../tools/ai_review/phase_execution_adapters.py) |
| Ed25519・frozen input復元・nonce ledger・attested judge | [`tools/ai_review/attestation.py`](../tools/ai_review/attestation.py)、[`tools/ai_review/nonce_ledger.py`](../tools/ai_review/nonce_ledger.py)、[`tools/ai_review/coordinator_attestation_inputs.py`](../tools/ai_review/coordinator_attestation_inputs.py)、[`tools/ai_review/attested_judge.py`](../tools/ai_review/attested_judge.py) |
| 7-phase protocol・outer workflow | [`tools/ai_review/phase_protocol.py`](../tools/ai_review/phase_protocol.py)、[`tools/ai_review/outer_driver.py`](../tools/ai_review/outer_driver.py)、[`tools/ai_review/outer_workflow_state.py`](../tools/ai_review/outer_workflow_state.py)、[`tools/ai_review/outer_workflow_runtime.py`](../tools/ai_review/outer_workflow_runtime.py)、[`tools/ai_review/external_launcher.py`](../tools/ai_review/external_launcher.py)、[`tools/ai_review/production_cli.py`](../tools/ai_review/production_cli.py)、[`tools/ai_review/coordinator_workflow_ops.py`](../tools/ai_review/coordinator_workflow_ops.py)、[`tools/ai_review/coordinator_workflow_inputs.py`](../tools/ai_review/coordinator_workflow_inputs.py) |
| AIレビューのJSON Schema、task、policy | [`specs/`](../specs/) |
| 独立reviewer / adversary prompt | [`specs/prompts/`](../specs/prompts/) |
| テスト時ネットワーク方針 | [`tests/conftest.py`](../tests/conftest.py)、[`tests/test_network_policy.py`](../tests/test_network_policy.py) |
| 決定論的CIゲート | [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) |

## 外部の公式資料

| 対象 | 公式資料 | このリポジトリでの用途 |
|---|---|---|
| uv | [uv documentation](https://docs.astral.sh/uv/) | 依存同期、コマンド実行、ロックファイル管理 |
| uv GitHub Actions | [Using uv in GitHub Actions](https://docs.astral.sh/uv/guides/integration/github/) | setup-uvの固定版、Python matrix、locked sync |
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
| Codex CLI | [Non-interactive mode](https://developers.openai.com/codex/noninteractive/) | dry-run argvの `exec`、`--ephemeral`、`--sandbox`、`--ignore-user-config`、`--output-schema`。OS隔離やattestationの根拠にはしない |
| GPT-5.6移行・推論量 | [GPT-5.6 model guidance](https://developers.openai.com/api/docs/guides/latest-model) | role別reasoning effort、persisted reasoning、prompt cache、verbosityの選択 |
| GPT-5.6 Sol | [GPT-5.6 Sol model](https://developers.openai.com/api/docs/models/gpt-5.6-sol) | 1.05M context、128K max output、対応effort、default-tier単価、272K input超の料金境界の確認 |
| Codex設定 | [Codex configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference) | `model_reasoning_effort`、`model_reasoning_summary`、`model_verbosity` の固定 |
| Podman導入 | [Podman installation](https://podman.io/docs/installation) | Archを含む公式package導入先の確認。package変更は管理者承認後だけ行う |
| Podman rootless mode | [Podman manual](https://docs.podman.io/en/latest/markdown/podman.1.html) | `/etc/subuid` / `/etc/subgid`、user-specific image storage、rootless制約の確認 |
| Podman container実行 | [podman-run](https://docs.podman.io/en/latest/markdown/podman-run.1.html) | rootless `--userns=keep-id`、read-only、capability、security option、resource制限の運用確認。現行コードとhost probeを優先する |
| Git clone | [git-clone](https://git-scm.com/docs/git-clone) | linked worktreeを避け、`--no-local` / `--no-hardlinks` でstandalone candidateを用意する際の前提 |
| Python zipapp | [zipapp](https://docs.python.org/3/library/zipapp.html) | 決定論的archiveの形式。現行のarchive内部hashを外部trust anchorとは扱わない |
| Python hashlib | [hashlib](https://docs.python.org/3/library/hashlib.html) | Python 3.10でも利用できるchunk単位SHA-256実装の根拠 |

Outscraperの公式ページにはホスト名が異なる例が併記される場合がある。実行時の接続先は [`src/config.py`](../src/config.py) の `OUTSCRAPER_ENDPOINT` を正とし、変更時は公式仕様、結果URLのホスト制約、テストを同時に確認する。

## ローカル保存資料

`docs/API Docs _ Outscraper.html` は取得時点の外部HTMLであり、`.gitignore` 対象である。内容が古くなる可能性があるため、仕様変更の根拠には公式Web資料を使う。

## 参照時の確認事項

- 外部APIの料金、上限、レスポンス形状は利用前に公式資料で再確認する。
- `specs/policies/openai-pricing-policy.json` は2026-08-15時点の `service_tier=default` を固定したrelease契約であり、将来料金の保証ではない。変更時は公式model pageを再確認して新しいdigestを承認する。
- `tools/ai_review/outer_descriptor_executor.py` はbounded subprocessのtest primitiveであり、provisioned broker production経路の根拠には使わない。正規経路は上表のoffline/broker専用protocolを確認する。
- broker phase protocolはfrozen final ledgerからhost DBなしでtyped evidenceを再構築し、`reconstruct_attestation_inputs` はimmutable phase chainからsign/judge共通bundleを復元する。`build_frozen_bundle_expectations` / `judge_frozen_attestation_bundle` はcanonical prepared/raw evidenceとpinned policy bytesを再finalizeし、productionでhost broker DB/runtime再probeを権威入力にしない。
- outer `--workflow` entry、inner `prepare|finalize` surface、7/7 actual handler、verified snapshot専用mount、sign-only key mount、judge-only nonce mountは接続済みである。readiness gateは不完全なreleaseをcredential read・broker ledger作成前に拒否する。
- `runtime_release workflow-init` はexternal approved manifest SHA、TaskSpec v2/harness、exact task/public key、protected candidate、人手承認済みpatch SHAからinitial requestを作る。同じinstalled manifestからその場で計算したSHAをexternal approvalの代替にしない。
- launcher `--deployment-check` はrootless backendと4 digest-pinned imageのcredential-free local checkであり、成功status `nonlive_ready` でも `production_e2e_complete=false` である。live APIまたはfull workflow実績として引用しない。
- nonce contractは [`tools/ai_review/nonce_ledger.py`](../tools/ai_review/nonce_ledger.py) のSQL、application ID/user version、PRAGMA、index/table metadata、file identityを正とする。replay setは署名検証後に単一transactionで予約し、部分衝突も全件rollbackする。
- 設計候補を実装済み機能として扱わない。
- 既定値を変更した場合は、コード、`.env.example`、関連文書、テストを同じ変更で更新する。
- 実API確認は、認証情報、課金、取得件数、待機時間を確認してから明示的に実施する。

関連資料: [索引](INDEX.md)、[バックエンド設計](BACKEND.md)、[制約](CONSTRAINTS.md)、[トラブルシューティング](TROUBLESHOOTING.md)
