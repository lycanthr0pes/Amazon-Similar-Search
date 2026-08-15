# 作業履歴

## 1. 目的

この文書は、リポジトリで確認できる主要な変更を時系列で記録する。Git履歴を置き換えるものではなく、変更の目的と現在につながる判断を短く説明する。

進行予定は [TASKS.md](TASKS.md) と [TODO.md](TODO.md)、現在の問題は [ISSUES.md](ISSUES.md) を参照する。未来の作業を「進行中」として先取りして記載しない。

## 2. Git履歴に基づく記録

### 2026-05-28: 初期実装（`91d6b48`, `v1.0.0`）

- Pythonアプリケーション本体、Streamlit入口、設定、スキーマ、Bonsai・Outscraperクライアント、正規化、採点、JSONユーティリティを追加した
- `pyproject.toml` と `uv.lock` により依存関係を管理する構成を追加した
- `.gitignore` を追加した

このコミットのファイル構成から確認できる事実であり、当時の実サービス結合試験結果はGit履歴だけからは確認できない。

### 2026-05-28: README追加（`1c51cd0`）

- ルート `README.md` を追加した

### 2026-05-28: プロジェクト設定修正（`a571d92`, `aa117a8`）

- `pyproject.toml` を各コミットで1行ずつ修正した
- コミットメッセージと差分から確認できる範囲を記録し、修正理由の詳細は推測しない

### 2026-05-28: アプリ入口修正（`29746e3`）

- `app.py` を1行修正した
- 修正内容の背景はコミット履歴に説明がないため、ここでは推測しない

### 2026-08-14: 堅牢化とリポジトリ整理（`fb2115a`）

- プロジェクト名と文書を `amazon-explorer` に整理した
- `.env.example`、開発文書、現行 `src` を直接検証するテストを追加した
- 開発段階の旧コードを `examples/legacy-phases/` に参照用として分離した
- Bonsai応答検証、Outscraper状態分類・同一オリジンURL検証・リダイレクト拒否・再試行を追加した
- キャッシュrepository、プロジェクトルート基準パス、設定を含むキャッシュキー、Streamlitセッションscopeを追加した
- JSONのアトミック書込、商品データと価格・真偽値の正規化、採点境界を強化した
- UIでは詳細例外をサーバーログへ残し、固定の利用者向けエラーを表示する形へ変更した

この記録はコミット差分と現行コードで確認した。現行テストが保証する範囲は [ISSUES.md](ISSUES.md#4-検証範囲) を参照する。

## 3. 2026-08-15: 参照文書への再編

- 既存の開発概要、データモデル、環境変数、外部API、キャッシュ、本番設計の内容を現行コード・テストと照合し、20個の目的別文書へ統合した
- 統合後の重複を避けるため旧6文書を削除し、統合先を `INDEX.md` に記録した
- `AGENTS.md` を見出しとMarkdownリンクだけの全Markdown目次へ変更した
- Execution Plan、設計、フロントエンド、バックエンド、UI、セキュリティ、負債、索引、データ境界、起動手順、メモリ、TODO、作業履歴、要件、制約、トラブル解決、Issue、参考資料、Taskへ情報を分離する再編である
- `AI_GUIDE.md` は利用者から後続指示があるまで内容を記載しない方針で作成対象とした

この空ファイル方針は再編時点の履歴である。後述の明示指示を受けた変更では内容を追加しており、現在の状態を表す説明ではない。

この項目は同日の文書再編差分そのものに含まれるため、作成時点ではコミットIDが付与されていない。コミット前の作業をGitへ反映済みと扱わない。

同日の確認結果:

- `uv run ruff check .`: 成功
- `uv run ruff format --check .`: 成功、33ファイルが整形済み
- `uv run pytest`: 成功、68件
- `uv lock --check`: 成功
- プロジェクト内30個のMarkdownについて、コードブロック内を除くローカルリンク先と見出しアンカーの存在確認: 成功
- `docs/` の要求文書20個と `AI_GUIDE.md` の0バイトを確認: 成功
- `git diff --check`: 成功
- BonsaiとOutscraperの実サービス呼出し: 未実行。テストはモックを使用するため、課金を伴う結合動作はこの確認に含まれない

## 4. 2026-08-15: AI相互レビューとTDDハーネスの導入

この項目は記載時点の未コミット変更を記録する。コミットIDはまだ付与されておらず、Gitへ反映済みまたは外部AIレビューを運用開始済みとは扱わない。詳細は [EXEC-001](plans/EXEC-001-AI-REVIEW-TDD-HARNESS.md) を参照する。

### TDDパイロット

- `tests/test_streamlit_ui.py` を先に追加し、`color_term_weight` と `feature_term_weight` の不足により1 failed, 2 passedとなるREDを確認した
- テストファイルのSHA-256は `042ad1b2cd8307afe40787bd53510d4cb55f66914548adf9ed76b57b8306ac4c` である
- `src/ui/streamlit_ui.py` へ2項目を追加後、同じテストファイルで3 passedとなるGREENを確認した
- 同ファイルで `format_price()` と `format_rating()` の代表ケースも固定し、`TODO-002`、`TODO-003`、`ISS-001` を解決済みにした
- `tests/test_outscraper_search_select.py` を先に追加し、空文字とURLの推定商品名fallbackにより2 failed, 2 passedとなるREDを確認した
- fallbackテストのSHA-256は `c6c60c698d7cb3074721c07f04d853c5c742e6ab157fcf5697995ad5df889189` である
- `estimated_product_name_ja` も `validate_search_query()` を通す1行変更後、同じテストファイルで4 passedとなるGREENを確認した
- APIキー欠落時の既存安全性を直接固定するテストを追加し、1 passedと `fetch_amazon_products` 未呼出を確認して `TODO-004` を完了にした。この項目は修正前失敗を伴うRED→GREENではない

### ハーネスと安全境界

- `tools/ai_review/` にstrictなtask / policy / gate / review / TDD evidence / verdict契約、パス安全性、standalone clone向けcanonical single-commit policy、current repositoryを再検査するjudge、実行無効のCodex CLI dry-runを追加した
- `specs/schemas/` に上記6つのJSON Schema、`specs/prompts/` に独立reviewer / adversary prompt、`specs/tasks/` に例とPydantic検証済みの `TASK-006` 契約を追加した
- raw task SHA-256をpolicy / review / gate / TDD evidence / verdictへ、gateをhead / candidate digestへ結び付けた。test manifestはpolicyのtest content hashから再構築し、RED exit / fingerprintはtaskへ固定した
- policyはcontent/numstat後にHEAD、replace refs、index/worktreeを再検査するようにした。ただし同UIDのwritable candidateでは検査途中だけ差替えを戻す競合とreturn後のTOCTOUが残るため、別UID所有のread-only snapshotをattested実行の未完要件にした
- candidateは `git clone --no-local` または `--no-hardlinks` でlocal hardlink最適化を避けるstandalone cloneへ限定した。外部git-dir/common-dir、`commondir` / `worktrees`、attributes/alternates、Git metadata tree内のsymlink/hardlink/nested mount等を拒否するpolicyと回帰テストを追加した
- canonical candidate digest内のblob IDを内容へ束縛するため、SHA-1 repositoryだけを許可し、base/head commit、到達tree、変更前後blobをGit header込みで再hashするようにした。検査末尾にもcommit/treeを再検証し、loose blob/commit/tree改ざんの回帰テストを追加した
- pytestへtest collection前からPythonのIP socket I/O、主要な名前解決、Requests経路を遮断するguardを追加した
- `live_api` はmarkerだけでは通常収集時にskipし、`--run-live-api` も明示した場合だけguardを解除する二重opt-inにした
- 独立reviewerとadversaryがGit replace/external diff、任意gate、TDD再利用、型coercion、nested secret、output link、candidate AGENTS/Python/Git自己改ざん、linked worktree、network経路を攻撃的に再現した。各経路を回帰テスト化し、standalone isolated cloneとcandidate外artifact境界へ修正した
- GitHub ActionsへPython 3.10 / 3.13のlock、Ruff、offline pytest、diff checkを追加した。GitHub上でのworkflow実行結果はまだ確認していない
- Python 3.10にない `hashlib.file_digest()` を使わないchunk hashへ修正した。ただしローカルではPython 3.10 interpreterによる実行を確認していない
- `AI_GUIDE.md` を明示指示に基づいて初めて記載し、役割分離、RED→GREEN証拠、standalone clone、6 JSON契約、停止条件、人間承認を規約化した
- `HARNESS-RUNBOOK.md` に現在可能な非attested開発検証、残る信頼境界、将来の正規フロー、GPT-5.6 Solのrole別推論量、token最適化を集約した

この時点ではzipapp内部SHA-256をtrust anchorとせず、外部AI実行、自動 `pass`、provenance attestationを禁止した。その後に実装した外部preflight、snapshot、OS隔離、broker、attestationは次項へ分ける。

pytest monkeypatch guardはOSレベルの通信遮断ではないため、TASK-007でも開発checkoutの補助防御としてだけ扱う。

最終確認では固定件数を文書へ埋め込まず、共有ツリーに対するoffline pytest、ハーネス自己テスト、network policy自己テスト、Ruff、lock、diff check、Markdownリンク検証の終了状態をhandoffで報告する。GitHub ActionsのPython 3.10 / 3.13 job、外部Codex、Bonsai、Outscraper、実ネットワークはローカル確認に含めない。

## 5. 2026-08-16: attested AI review境界の実装

この項目も記載時点の未コミット変更である。境界コードと敵対的fixtureの実装記録であり、trusted releaseの配備、外部OpenAI APIのlive成功、課金、push/merge済みを意味しない。詳細は [EXEC-002](plans/EXEC-002-ATTESTED-AI-REVIEW-BOUNDARIES.md) を参照する。

### trust、snapshot、offline

- stdlib-only external launcher/preflightを追加し、root-owned path、`-I -S`、manifest raw SHA、open inode、現在のPython executable、harness/task/lock/schema/public key/policyをimport前に固定した
- standalone Git commitをcontent-addressed read-only base/candidate snapshotへ変換し、exact test overlayだけのRED snapshotを別digestへ結び付けた
- rootのtracked `.env.example` は全assignmentが空の安全なtemplateかを検証後、snapshot実行treeから除外するようにした
- `.env*`、`.cache` / `cache`、generic credentials/secrets、SSH/cloud/container/package-manager/provider credential pathを共通policyで拒否した
- pinned runner image、read-only rootfs/snapshot、networkなし、capabilityなし、`no_new_privileges`、resource上限からraw RED/GREEN/gate evidenceを採取・再検証する経路を追加した

### packet、broker、費用

- trusted diffと限定contextからcredential検査済みbounded packetを作り、candidate filesystemをbrokerへ渡さないtool-free Responses requestへ固定した
- canonical request JSON全体を保守的なinput予約に使い、1 call 260K input / 12K output / 250K warning、reviewer=`high`、adversary=`xhigh`、`service_tier=default` を固定した
- broker専用internal networkとcredential-free gateway専用external networkをrole/attemptごとに作り、raw inspect、固定 `api.openai.com:443`、post-inspect、cleanup、absenceをprovisioned lifecycleへ結び付けた
- SQLite ledgerへattemptを外部起動前に予約し、失敗attemptも標準544K / 4.54 USD、絶対1,088K / 7.94 USDへ累積するようにした
- broker outer rawへ全recordsと累積値を持つcanonical frozen final ledgerを加え、host SQLite削除後も同じallowlist/pricing policyからreviewer/adversaryのtyped provisioned evidenceを再構築できるようにした
- 料金値をcanonical `openai-pricing-policy.json` とruntime manifest digestへ固定した

### 署名、judge、phase protocol

- task、policy、raw offline由来gate/TDD、reviewをEd25519署名、runtime/snapshot/request/runner/log、nonce/replay ledgerへ結び付けた
- attested judgeがraw offline evidence、reviewer/adversary各1件のdistinct provisioned broker lifecycle、frozen final ledger、全署名を再構築するようにした
- 完全なclean provenanceでは `pass` を返し得るが、全verdictで `human_approval_required=true` を維持した
- `snapshot -> red-snapshot -> offline -> review-packet -> broker -> sign -> attested-judge` のclosed order、digest chain、SQLite consume-before-execute ledger、phase別mount、exclusive outputを実装した
- phaseごとにprepare/finalize input/output/committed directoryを分け、request、prepared/finalized transition、payload、`coordinator-output.json`、`artifact-manifest.json`、`phase-result.json`、external phaseの `external-evidence.json` を保存し、initial/直前committed treeを `prior-artifacts/` へcopyするcontractを追加した
- request/action/output/result/next requestをcanonical再検証し、descriptor以外をouterへdispatchしないstdlib `run_fixed_workflow` state machineを追加した
- external launcherの `--workflow` をroot-owned outer 7-phase runtimeへ接続し、phaseごとのprepare/finalize input/output/committed treeをexclusive作成してread-only化する経路を追加した
- inner `prepare|finalize` CLIを追加し、先行してsnapshotからbrokerまでをactual typed protocolへ接続した。caller supplied descriptor/argv/invocation/unknown fieldを拒否し、未完成phaseへはその時点でfail closedした
- physical snapshotをhost `snapshot-artifacts/` とcoordinator専用read-only `/snapshots` mountへ分離し、一般artifactのAGENTS拒否を維持したままsemantic/physical SHA集合をexact照合するようにした
- private key mountをsign workflow prepareだけに絞り、attested-judge prepareだけがprivate 0700 nonce ledger rootを専用RW `/nonce-ledger` mountとして受け取るようにした
- immutable phase chain、dedicated snapshot、raw offline runs、broker prepared/raw/frozen ledgerから、live broker DBなしでsign/judge共通 `CoordinatorAttestationInputs` を復元する `reconstruct_attestation_inputs` を追加した
- external launcherに7/7 handlerの完全一致を要求するreadiness gateを追加し、不完全な開発途中releaseはcredential FD読取り・broker ledger作成前にfull workflowをfail closedするようにした
- frozen bundleからrole別expectationを作ってEd25519署名する `sign` handlerと、同じimmutable evidenceからexpectationを独立再構築する `attested-judge` handlerを接続し、actual handlerを7/7とした
- production judgeをcanonical broker prepared/raw bytesとpinned policyから再finalizeするfrozen APIへ移行し、host broker SQLite削除後のpassとtamper/replay拒否を回帰テストした
- nonce ledgerをexact SQLite schema/PRAGMA/index/file identity、WAL/sidecar不在へ固定し、全nonceを単一 `BEGIN IMMEDIATE` transactionで予約するようにした。重複・既使用・部分衝突は全件rollbackする

### 残る運用作業と検証境界（配備前時点）

- 配備前時点のcode/testは7/7境界を接続済みであった。coordinatorはrootless Podman `keep-id` を必須とし、同時点のhostはArch WSL2 / UID 0 / Podmanなし / subuid・subgidなし / rootful Docker・usernsなしのためcredential FD読取り前のbackend検査でfail closedになった
- 最終AI suiteは568 passed / 1 skipped、secret-free temp copyのoffline suiteは644 passed / 1 deselectedで終了0を確認した。この件数は2026-08-16の証拠であり、運用文書の固定成功条件にしない
- 独立security reviewは7-phase重点回帰215 passedとnonce再監査を完了し、未修正CRITICAL/HIGHは0である
- lock、Ruff check/format、schema/hash、tracked+untracked whitespace、PDF不在を確認した。最新の文書同期後は25 Markdownのlocal link/anchor、全57 sh/bash block（Runbook 12 block）の構文、docs対象のdiff checkが終了0である。Python 3.10 local interpreterはなく、実行確認はCI境界として残る
- external OpenAI API、Bonsai、Outscraper、Amazonは実行していない。credential、送信内容、費用の人間opt-inも与えられていない

### 本番配備preflight境界の補完（配備前時点）

- `runtime_release workflow-init` を追加し、external approved manifest SHA、TaskSpec v2と現行harness digest、manifestに固定したexact task/public key、protected standalone clean candidate、人手承認済みpatch SHAを再検証してsequence 1 requestをexclusive作成・凍結する契約にした。credentialとnetworkは使わない
- external launcherの `--deployment-check` を追加し、workflow sensitive inputとcredentialを受け取らず、rootless backendとmanifest-pinned 4 imageのlocal inspect/networkなしsmokeだけを行い、`production_e2e_complete=false` の `nonlive_ready` evidenceへ限定した
- `tests/test_ai_review_workflow_init.py` と `tests/test_ai_review_deployment_check.py` の対象回帰は50 passedで終了0を確認した。この時点ではfake runtimeを使うcode contract検証だけであり、後続の実host `nonlive_ready` は次項へ記録する
- 配備前のread-only host probeではArch Linux on WSL2、UID 0、Podmanなし、subuid/subgidと専用userなし、user namespaceなしのrootful Docker、`/home/products` 0777、trusted `/opt`・private `/var/lib` 未作成、古く不完全なDocker imageを確認した。production検出はfail closedであり、この時点では配備可能と判定しなかった
- package/user/system変更、rootless Podman設定、承認済みclean commitと具体的TaskSpec v2 canaryからのrelease build/install、4 image build/pull、credential/API、full 7-phase live E2Eは実行していない。これらは人間承認後の別作業として残した

## 6. 2026-08-16: credential-free本番配備検証

前項のhost不足は配備前診断の履歴である。利用者の明示承認後、外部OpenAI APIを使わない範囲で本番配備前提を実hostへ構築し、`nonlive_ready` まで確認した。

### hostとtrust root

- Podman 6.1、crun、netavark、passt、fuse-overlayfs等のrootless実行stackを導入した
- coordinator専用 `ai-review`（UID/GID 1100）とcandidate identity `amazon-candidate`（UID/GID 1101）を分離し、ai-reviewだけへsubuid/subgid範囲を割り当てた
- passwd由来の `/var/lib/amazon-explorer-ai-review/home`、専用XDG config/data/runtime、active `containers/storage.conf`、rootless user storeを設定し、user namespaceとseccompを確認した
- root-owned trusted releaseを `/opt/amazon-explorer-ai-review/releases/dd4b6bde2bd2d7f3ebc67c5190949c1cc97652ee`、private artifact/key/ledger rootを `/var/lib/amazon-explorer-ai-review` に分離した

### clean releaseとcanary

- clean base commitを `dd4b6bde2bd2d7f3ebc67c5190949c1cc97652ee`、canary candidate commitを `c603ec833e13f13bdce5af4e0b36f5917e0d4f98` へ固定した
- harness SHA-256は `0d27b9c541b01b1fb6f02c270286965c1507748abe5f5667ac5a9e7250426278`、TaskSpec v2 raw SHA-256は `8507bc001dcf4d383ce43cb335e65851da740c10d6e3c4dd752c1f762b1b32fd`、canonical candidate patch SHA-256は `a9d49bea2225a903fe693f913c1f8652cdea56d02b03355e17f472363ca3b715` である
- runtime manifest SHA-256は `703d2e183558afe6e52198247888675d7f0b526f5082051a9ae75d5ea3a402ae` であり、`/usr/bin/python3.14`、release asset、4つの異なるimage digestを固定した
- `/var/lib/amazon-explorer-ai-review/candidates/TASK-CANARY-001-r2` のstandalone single-commit、決定論的RED exit 23 / GREEN exit 0、exact 2-path patchを確認し、credential-free `workflow-init` のsequence 1 requestを `/var/lib/amazon-explorer-ai-review/build/workflow-init-r2/initial` へ凍結した
- initializer出力はcanonical bindingを満たす一方、root所有0500/0400のbuild証拠であり `ai-review` UID 1100から直接読めない。deployment checkはworkflow inputを受け取らないため成功へ影響しないが、live前に再承認したanchorから `ai-review` 所有のprivate artifact rootへinitial requestを新規生成する必要がある
- 後続指示によりmanifest `703d2e183558afe6e52198247888675d7f0b526f5082051a9ae75d5ea3a402ae`、TaskSpec `8507bc001dcf4d383ce43cb335e65851da740c10d6e3c4dd752c1f762b1b32fd`、candidate head `c603ec833e13f13bdce5af4e0b36f5917e0d4f98`、canonical patch `a9d49bea2225a903fe693f913c1f8652cdea56d02b03355e17f472363ca3b715` を再照合した
- UID 1100でroot所有candidateを使った初回initializerは `candidate Git metadata must be owned by the coordinator user: refs` で安全側停止した。既存candidateを変更せず、local objectを共有しない `/var/lib/amazon-explorer-ai-review/live-candidates/TASK-CANARY-001-r2` をUID 1100で作り、書込み権を除去して再実行した
- `/var/lib/amazon-explorer-ai-review/artifacts/TASK-CANARY-001-live-init-r2/phase-request.json` をUID 1100所有0500/0400で生成した。file SHA-256は `57266f318584f01dd0fc3cccf08a9e356db67371277e974393d7c8b91f42c706`、request SHA-256は `3fce384684bbd5df6d87ddd52af8b6010f732fc5201ce9421e245fe5db0a1a82` で、UID 1101からの読取りを拒否した。Podman containerは残存せず、networkは既定 `podman` だけで、credential/API/課金は使用していない

### imageとdeployment check

- public registryからdigest固定のPython/uv base imageを取得し、coordinator、offline runner、broker、gatewayをrootless Podman storeへbuildした。coordinator/runner buildではimage内package取得を行った
- 4 image digestは順に `sha256:bd1e77e913eeecce78fe2ace2ac595a061d2c92ed4a335a137e9bf2b31d33d03`、`sha256:9ed1d64387776f3026efbcdf4957bfcd0b296493e784c6a775a17f1691f0b8b4`、`sha256:cec5e091d220e87bf0e1723ee59ea1062cf7bb5d6371cf2b55839754b470a1b1`、`sha256:36509c46496d5c3779e66185de9babf8d8ea34a1adf9fee297684c3e54cb11aa` である
- root-owned launcherの `--deployment-check` は実hostで終了0となり、`status="nonlive_ready"`、`credentials_read=false`、`external_api_called=false`、`external_network_created=false`、`production_e2e_complete=false` を確認した。独立した再実行でも同じbackend bindingとflagsを確認した。smoke用のランダム名を含むためrun全体のevidence SHAは実行ごとに異なる
- secret-free full suiteは726 passed / 1 deselected、Ruff check/formatは117 files、lock、diff、release/candidateのstrict Git fsckは終了0である
- 配備記録の同期後、project Markdown 35件のlocal link/anchorとfence balance、sh/bash block 78件の `bash -n`、repository全体の `git diff --check` は終了0である

package導入、public image pull、image内package取得とbuildには公開package/registry通信を使った。一方、OpenAI credentialは読まず、OpenAI API、review packetの外部送信、broker external network、full 7-phase live workflow、課金、provider request IDは発生していない。`nonlive_ready` をlive成功として扱わない。

## 7. 記録規則

- 日付、コミットID、変更ファイル、実行結果のいずれかで確認できる事実を書く
- コミットメッセージにない動機を推測しない
- 外部APIを実行していない場合、実サービスで確認済みと書かない
- シークレット、利用者入力、商品結果、キャッシュ内容を記録しない
- 予定、優先度、担当は履歴に混ぜず、対応する管理文書へ置く
- 未コミット変更はその旨を明記し、コミット後にIDを追記できる
- 巻き戻しや置換があった場合も、履歴を消さず後続項目で説明する
