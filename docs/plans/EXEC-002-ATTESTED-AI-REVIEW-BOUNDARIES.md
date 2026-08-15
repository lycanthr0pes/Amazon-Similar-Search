# EXEC-002: attested AI review境界の実装

## メタデータ

- タスクID: `TASK-007`
- 状態: 進行中（7/7 actual handler、frozen sign/judge、exact nonce contract、workflow初期化、credential-free deployment check、独立security reviewは完了。rootless Podmanへの実配備、具体的v2 canary、nonce長期運用が残る）
- 作成日: 2026-08-15
- 最終更新日: 2026-08-16
- 前提タスク: [TASK-006](../TASKS.md#task-006-ai相互レビューとtddハーネスの導入)
- 関連負債: [TD-009](../TECH-DEBT-TRACKER.md#td-009-ai変更の役割分離と証拠契約)
- 運用規約: [AI_GUIDE.md](../AI_GUIDE.md)
- 実行手順: [HARNESS-RUNBOOK.md](../HARNESS-RUNBOOK.md)

## 目的

candidateがruntime、snapshot、evidence、credential、network、judgeを改ざんできない境界でAI相互レビューを行えるようにする。利用者が観察できる完了状態は、root-owned trusted releaseとrootless Podman hostでclosed 7-phase workflowがfail closedに動き、raw offline evidence、reviewer/adversaryのdistinct provisioned broker lifecycle、Ed25519署名をattested judgeまで一貫して検証できることである。

`pass` でも人間承認を維持し、自動commit、push、mergeは行わない。

## 対象範囲

- root-owned stdlib external launcher/preflightとruntime manifest
- external approved manifest SHAとhuman-approved patch SHAに結ぶcredential-free workflow初期化
- standalone Git commitからのbase/candidate/RED read-only snapshot
- common sensitive path policyとroot `.env.example` の安全な除外
- rootless Podmanのnetworkなしoffline runnerとraw execution evidence
- bounded sanitized text-only review packet
- tool-free GPT-5.6 Sol requestとfixed model/effort/service tier
- broker/gatewayのnetwork分離、fixed egress、raw inspect、cleanup evidence
- 失敗attemptを含むtoken/cost SQLite ledger
- Ed25519 artifact、nonce/replay防止、attested judge
- 7-phase digest chain、durable phase ledger、phase別mount/output
- adversarial regression、schema、CI、runbook
- credential/API/external networkなしの4-image deployment preflight

## 対象外

- 自動commit、push、merge
- 検索アプリのUI、ブックマーク表示数、検索結果件数の変更
- 削除済みPDFの復元または参照
- Bonsai、Outscraper、Amazonの実通信
- 未コミットbootstrap変更自身を自己attest済みと宣言すること
- credential、送信内容、費用の人間承認なしにOpenAI APIを実行すること
- agentic modelへcandidate filesystem、shell、toolを与えること
- rootful Dockerに合わせてproduction境界を弱めること

## 現在の状態

### 実装済みの境界

| 領域 | 主なpath | 現行結果 |
|---|---|---|
| release/preflight | `runtime_release.py`、`workflow_init.py`、`external_launcher.py`、`preflight.py`、`deployment_check.py` | external approved manifest SHA、manifest/asset/Python inode/digestを固定。TaskSpec v2とhuman-approved patchからinitial requestを凍結し、credential-free 4-image checkは `nonlive_ready` に限定 |
| coordinator | `coordinator_launcher.py`、coordinator image | nonroot rootless Podman `keep-id`、seccomp、networkなし、read-only、phase別mount |
| snapshot | `snapshot.py`、`sensitive_paths.py`、`outer_workflow_runtime.py`、`coordinator_launcher.py` | Git再hash、read-only snapshot、exact RED overlay、credential path拒否、root `.env.example` 空値検査後除外、専用physical store/RO mount |
| offline | `offline_runner.py`、`offline_phase_protocol.py`、`offline_outer_executor.py`、runner image | complete prepared batch、networkなしraw execution、coordinator再finalize |
| packet/request | `review_packet.py`、`codex_adapter.py` | bounded text-only packet、credential scanner、strict Responses schema、toolsなし |
| egress/broker | `broker_phase_protocol.py`、`broker_outer_executor.py`、`broker_egress_provisioner.py`、`broker_executor.py`、broker/gateway image | 2役prepared batch、role/attempt別network、credential-free fixed gateway、raw lifecycle、frozen final ledger、coordinator再finalize |
| token/cost | `pricing_policy.py`、`openai-pricing-policy.json` | `service_tier=default`、失敗attemptの事前予約、標準544K/4.54 USD、絶対1,088K/7.94 USD |
| attestation | `attestation.py`、`nonce_ledger.py`、`attested_judge.py`、`coordinator_attestation_inputs.py` | raw offline、2 provisioned lifecycle、frozen final ledger、Ed25519、exact SQLite nonce/replayを検証。host broker DBなしでsign/judgeへ接続 |
| phase protocol | `phase_protocol.py`、`phase_execution_adapters.py`、`outer_driver.py`、`outer_workflow_state.py`、`outer_workflow_runtime.py`、`external_launcher.py`、`production_cli.py`、`coordinator_workflow_ops.py` | closed order/digest/exclusive tree、outer entry、inner operation、7/7 actual handler、readiness gate |

phase順序は次である。

```text
snapshot -> red-snapshot -> offline -> review-packet -> broker -> sign -> attested-judge
```

`snapshot` workflow prepareだけがcandidateをmountし、`sign` workflow prepareだけがprivate keyをread-only mountする。`attested-judge` prepareだけがlauncher所有のprivate nonce ledger rootを専用read-write mountで受け取る。`offline` と `broker` だけがouter executorを使う。outer workflow runtimeは各phaseを `NN-phase/{prepare-input,prepare-output,finalize-input,finalize-output,committed}` へ分ける。`committed/` はrequest、prepared/finalized transition、payload、`coordinator-output.json`、`artifact-manifest.json`、`phase-result.json` を保存し、external phaseではexact `external-evidence.json` も保存する。初回はinitial inputs、それ以後は直前のimmutable committed treeを `prior-artifacts/` へcopyし、phase完了後はtree全体をread-only化する。

brokerのouter rawは両roleのprovisioned lifecycleに加え、失敗attemptを含むcanonical frozen `final_ledger` を持つ。host SQLiteのraw copyやpath/device/inodeのcopyを証拠にせず、prepared/raw pairを `external_execution_sha256` と `phase_sha256` へ結ぶ。同じallowlist/pricing policy bytesを使うと、host DB削除後でもtyped `ProvisionedBrokerExecutionEvidence` 2件を再構築できる。

さらに `reconstruct_attestation_inputs` がimmutable PhaseChain、dedicated snapshot、raw offline runs、broker prepared/raw/frozen ledgerから、host DBなしでsign/judge共通bundleと2つのtyped evidenceを復元する。`sign` はこのimmutable evidenceからrole別expectationを署名し、`attested-judge` は同じevidenceからexpectationを独立再構築する。canonical prepared/raw pairとpinned policy bytesを再finalizeするため、host broker ledger削除後もverdictへ到達できる。raw DB copy/bind mountとruntime再probeはproduction証拠にしない。

### 現在の運用上の残り

- external launcherの `--workflow`、inner `prepare|finalize` CLI、7/7 actual handlerは接続済みである
- readiness gateはhandler tupleが7 phase全体と完全一致することを、credential FD読取り・broker ledger作成前に検査する
- `workflow-init` はexternal approved manifest SHAとhuman-approved patch SHAを必須にし、sequence 1 requestをcredential/networkなしで生成する
- `--deployment-check` はcredential/API/external networkなしでrootless backendと4 imageを確認し、`production_e2e_complete=false` の `nonlive_ready` だけを返す
- Arch WSL2の実hostへ専用UID/subuid/subgid、rootless Podman `keep-id`、trusted `/opt`、private `/var/lib`、現行4-role image、具体的TaskSpec v2 canaryを配備し、credential-free `nonlive_ready` を確認した
- external manifest/patch anchorを再照合し、UID 1100所有のstandalone candidateとprivate artifact rootからlive launcherが読めるinitial requestを生成した
- nonce ledgerの長期保持、backup、容量、rotation運用が未定義である
- external OpenAI APIはcredential/費用opt-inがなく未実行である

package/user/system変更、rootless Podman設定、image build/pull、release installは人間承認が必要であり、今回実行していない。これらを理由に、個別APIを手作業でつないだlive実行を行わない。

## 実行手順と進捗

### M1: import前trust anchor

- [x] stdlib-only launcherがharness import前にmanifestとraw assetを検証する
- [x] open FD、path component、symlink/hardlink、owner/mode、candidate UIDの書換権限を検査する
- [x] `-I -S`、root-owned Python prefix/sys.pathを要求する
- [x] 実行中 `sys.executable` をmanifest Pythonのpath/inode/SHA-256へ一致させる
- [x] coordinator imageをcandidate外のpinned digestへ固定する
- [x] external approved manifest SHA、TaskSpec v2、exact task/public key、protected clean candidate、human-approved patch SHAからinitial requestを作り0500/0400へ凍結する

### M2: immutable snapshotとraw offline runner

- [x] standalone cloneのcommit/tree/blobとGit metadataを検証する
- [x] base/candidateをcontent-addressed read-only snapshotへ変換する
- [x] REDをbase + exact test overlayへ限定し、production差分混入を拒否する
- [x] common sensitive pathをpathで拒否する
- [x] root `.env.example` は64KiB以下のUTF-8、NUL/credential-like contentなし、全assignment空値を検証後、実行snapshotから除外する
- [x] networkなし、read-only、capabilityなし、resource制限付きrunnerからraw evidenceを得る

### M3: bounded packet、broker、予算

- [x] trusted diffと限定contextだけからcanonical packetを作る
- [x] credential-like content、credential path、binary、byte/token上限を拒否する
- [x] canonical Responses request JSON全体を260K input上限/250K warningの予約対象にする
- [x] reviewer=`high`、adversary=`xhigh`、verbosity=`low`、toolsなし、`store=false`、`service_tier=default` を固定する
- [x] brokerとgatewayを別network権限へ分け、gatewayを `api.openai.com:443` へ固定する
- [x] raw inspect、post-inspect、cleanup、absenceをrole別provisioned evidenceへ結ぶ
- [x] root-owned stdlib outerがbroker ledgerをO_EXCL・0600・STRICT schemaで新規作成し、既存fileを拒否する
- [x] attemptを起動前にledgerへ予約し、失敗attemptもtoken/costへ算入する

### M4: Ed25519とattested judge

- [x] private keyをsign workflow prepareだけへread-only mountする
- [x] private nonce ledger rootをattested-judge workflow prepareだけへ専用read-write mountする
- [x] task/policy/gate/TDD/reviewをruntime/snapshot/request/runner/log/nonceへ署名する
- [x] raw offline runから全acceptanceのgate/TDDを再構築する
- [x] reviewer/adversaryのdistinct provisioned lifecycleを各1件要求する
- [x] canonical prepared/raw evidenceとpinned policyを再finalizeし、final ledgerの失敗attempt、累積token/cost、pricing policy digestを再検証する
- [x] tamper、replay、別task/head/snapshot/runtime、重複session/lifecycleをfail closedにする
- [x] clean provenanceの `pass` でも `human_approval_required=true` を維持する

### M5: closed phase protocol

- [x] 7つのphaseと実行domainをclosed tableへ固定する
- [x] request/action/result/artifactをcanonical digest chainへ結ぶ
- [x] SQLite ledgerをconsume-before-executeにし、同workflow/phase replayを拒否する
- [x] candidate/signing key/output mountをphaseごとに限定する
- [x] coordinator outputをtyped envelopeとして再検証し、durable historyと分けて保存する
- [x] offline/brokerをそれぞれtyped prepare→outer→finalizeへ接続し、generic outer descriptorをproduction brokerから除外する
- [x] external prepared/raw evidenceをexclusive保存し、`prior-artifacts/` へ累積する
- [x] broker frozen final ledgerをphase chainへ結び、host DB削除後の再finalizeとtamper拒否を確認する
- [x] stdlib固定state machineが7phaseのrequest/action/output/result/next requestをcanonical再検証する
- [x] external launcherの `--workflow` をstdlib outer runtimeへ接続し、phase別working treeをexclusive作成・read-only化する
- [x] inner `prepare|finalize` CLIを登録し、offline/brokerをactual typed handlerへ接続する
- [x] verified physical snapshotを一般artifactから分離した専用read-only mountへ渡し、semantic/physical集合をexact照合する
- [x] snapshot、red-snapshot、review-packetのactual typed handlerを接続する
- [x] frozen phase evidenceからlive broker DBなしでsign/judge共通input bundleを再構築する
- [x] readiness gateが7/7 handlerの完全一致をcredential read・broker ledger作成前に検査する

### M6: production統合とhandoff

- [x] frozen common bundleを消費してcanonical署名artifactを作る `sign` actual handlerをouter `--workflow` entryへ接続する
- [x] frozen common bundleからverdictを出し、host ledger削除後のpassとtamperされたfrozen evidence拒否を確認する `attested-judge` actual handlerを接続する
- [x] nonce DBのexact schema・PRAGMA・index・file identity・sidecar不在を固定し、replay setを単一transactionで原子的に予約する
- [x] credential/API/external networkなしでrootless backendと4 imageをlocal inspect/smokeし、`nonlive_ready` evidenceだけを返すdeployment checkを追加する
- [ ] 失敗時に同workflowを再開せず、新しいworkflow IDでやり直す運用をE2Eで確認する
- [ ] 管理者承認後に専用user/subuid/subgid/rootless Podman、trusted `/opt`、private `/var/lib` を用意する
- [ ] 人手監査済みclean commit、具体的TaskSpec v2 canary、external approved manifest SHA、4 image digestからroot-owned releaseをinstallし、`--deployment-check` の `nonlive_ready` とrootful/root/no-usernsのfail closedを実hostで確認する
- [x] schema生成・一致、full offline pytest、Ruff、lock、diff、Markdown link/anchorを最終確認する
- [x] 独立security reviewの未修正CRITICAL/HIGHを0にし、7-phase重点回帰とnonce再監査を完了する
- [x] TASKS、TECH-DEBT、WORKLOG、runbookを最終状態へ同期する

## 検証

| 対象 | コマンドまたは方法 | 期待結果 | 現在の記録 |
|---|---|---|---|
| lock | `uv lock --check` | 終了0 | 2026-08-16に終了0 |
| lint | `uv run ruff check .` | 終了0 | 2026-08-16に終了0 |
| format | `uv run ruff format --check .` | 終了0 | 2026-08-16に終了0 |
| offline全体 | `uv run pytest -m 'not live_api'` | liveを実行せず終了0 | 2026-08-16の現行gateは726 passed / 1 deselected |
| trust/phase | `uv run pytest -q tests/test_ai_review_runtime_release.py tests/test_ai_review_coordinator_launcher.py tests/test_ai_review_phase_protocol.py tests/test_ai_review_outer_driver.py tests/test_ai_review_outer_workflow_state.py` | adversarial caseを含め終了0 | 関連回帰は終了0 |
| outer protocol | `uv run pytest -q tests/test_ai_review_offline_phase_protocol.py tests/test_ai_review_broker_phase_protocol.py tests/test_ai_review_phase_execution_adapters.py` | prepare/raw/finalize、frozen ledger、tamper caseを含め終了0 | 関連回帰は終了0 |
| broker/judge | `uv run pytest -q tests/test_ai_review_broker_executor.py tests/test_ai_review_broker_egress_provisioner.py tests/test_ai_review_attested_judge.py` | lifecycle/ledger/tamper caseを含め終了0 | AI suiteの一部として終了0 |
| frozen sign/judge | `uv run pytest -q tests/test_ai_review_coordinator_attestation_inputs.py tests/test_ai_review_attestation.py tests/test_ai_review_attested_judge.py` | host DB/runtime probeなしでsign/judgeが同じimmutable evidenceからexpectationを再構築し、tamper/replayを拒否 | 対象testは終了0 |
| workflow init / deployment check | `uv run pytest -q tests/test_ai_review_workflow_init.py tests/test_ai_review_deployment_check.py` | external anchors、initial request freeze、credential/APIなし、4-image local smoke、`nonlive_ready` contractを検証 | full gateへ含めて終了0。実hostでも `nonlive_ready` とUID 1100所有initial requestを確認 |
| AI test suite | `uv run pytest -q tests/test_ai_review_*.py tests/test_network_policy.py -m 'not live_api'` | 終了0 | 2026-08-16の現行gateは650 passed / 1 deselected。生成asset同期検査も含む |
| patch | `git diff --check` | whitespace errorなし | docs対象は終了0 |
| docs | local Markdown link/anchor検査とshell構文検査 | missing・構文errorなし | 35 Markdown / 全78 sh/bash blockで終了0 |
| independent security review | 7-phase重点回帰、nonce再監査、finding集計 | 未修正CRITICAL/HIGH 0 | 重点回帰215 passed、nonce再監査完了 |
| production host | `id` / rootless Podman / subuid/subgid / trusted path / deployment check / workflow init / 7-phase E2E | fail-closed境界、`nonlive_ready`、artifact chain成立を段階別に確認 | 専用UID、rootless Podman、trusted release、4 image、`nonlive_ready`、UID 1100所有initial requestまで確認。live 7-phaseは未実行 |
| OpenAI live | 人間opt-in後の限定run | 送信・usage・費用・request IDを記録 | 未実行。credential/費用承認なし |

上の件数は2026-08-16の実行証拠であり、将来の固定期待値ではない。Python 3.10 local interpreterがないため、Python 3.10はCI上の将来検証境界として残る。

## セキュリティ・データ・互換性

- `.env`、Streamlit secrets、生cache、利用者検索入力、API response本文を読出し・copy・artifact化しない
- root `.env.example` はsize/UTF-8/NUL/credential-like content/空assignmentを検証し、snapshotから除外する
- OpenAI credentialはbroker processだけへ注入し、gateway、argv、stdin、artifactへ入れない
- private keyはcandidate外0400 fileとし、sign workflow prepare以外へ渡さない
- nonce ledger rootはlauncher/coordinator所有の0700 directoryとし、attested-judge prepare以外へ渡さない
- external AIを通常pytest、CI、release build、preflight診断から起動しない
- app本体、cache schema、ブックマークUI、削除済みPDFへ変更を広げない

## 判断記録

| 日付 | 判断 | 理由 | 影響・見直し条件 |
|---|---|---|---|
| 2026-08-15 | agentic Codexへcandidateをmountせずtext-only packetを使う | credentialとcandidate実行権を同じnamespaceへ置かないため | shell/tool reviewは別のoffline境界を設計するまで禁止 |
| 2026-08-15 | Ed25519に `cryptography` を使う | stdlibに署名実装がなく、openssl subprocess鍵処理を避けるため | dependency/runtime digestへ固定 |
| 2026-08-15 | bootstrap変更を自己attestしない | trust anchor導入前の変更を新anchor自身で証明できないため | 人手監査済みcommitから別trusted buildが必要 |
| 2026-08-16 | coordinator production backendをrootless Podman `keep-id` に限定する | host ownerとcontainer UIDのRW mount意味を一意に保つため | Docker/rootful hostはfail closed。正式な別mappingを設計した場合だけ見直す |
| 2026-08-16 | brokerとgatewayを分離し、gatewayをcredential-freeにする | credential保有主体へunrestricted egressを与えないため | policy digest、raw inspect、cleanup証拠が必須 |
| 2026-08-16 | 失敗attemptも予算へ算入する | paid request後のtimeout/errorで上限を回避させないため | 新packet/workflowでも旧ledgerを改ざんして戻さない |
| 2026-08-16 | clean attestationは `pass` を許すが人間承認を維持する | provenance検証と統合権限を分けるため | 自動commit/push/mergeは対象外 |
| 2026-08-16 | initial requestはexternal manifest anchorとhuman-approved patchから専用initializerで作る | 手書きworkflow ID、placeholder、検査対象manifestの自己承認を防ぐため | dirty checkoutや同じmanifestから都合よく作った期待SHAを権威入力にしない |
| 2026-08-16 | live前の配備確認をcredential-free `nonlive_ready` に限定する | host/image前提の検査と外部送信・課金を分離するため | full E2E、API、credential、external networkの成功とは別に記録する |

## 発見事項

- モデルcontextは1.05Mだが、272K超のinputには料金倍率がある。projectは1 call総予約272K、input 260K、output 12Kへ保守的に制限した
- packet本文だけを数えるとschema/envelope分を漏らすため、canonical request JSON全体のUTF-8 bytesを予約上界に変更した
- fixed gatewayの設計だけでは実配置を証明できないため、create/inspect/post-inspect/cleanup/absenceのraw lifecycleが必要になった
- successful broker evidenceだけでは失敗したpaid attemptを隠せるため、final SQLite ledger全体の検証が必要になった
- live SQLite identityはabsolute path/device/inodeへ結び付くため、raw DB copyやbind mountを後段証拠にできない。broker終了時のcanonical frozen ledgerをouter rawへ入れ、phase digestへ結ぶ方式へ変更した
- 開発途中はbroker phase finalizeのpath依存を除去してもjudgeが実行時状態を再計測していた。そのためcanonical frozen evidenceから再finalizeする専用APIと、sign/judge共通bundle adapterへ移行した
- 開発途中のsingle-phase限定は7/7 actual handlerの接続とreadiness gateにより解消した。不完全releaseは依然としてcredential読取り前にfail closedする
- hostのrootful Dockerはproduction要件を満たさない。境界を弱めずrootless Podman hostへ移す
- rootful Docker storeの古いimageはrootless Podman user storeから見えることも、現行manifestの4-role digestに一致することも証明しない。承認済みrelease digestで別途用意する
- fixed state machineとouter entryがあっても、全phaseのactual handlerと専用mountが閉じていなければ運用者の手作業でbindingを崩し得る
- outer/inner operationを追加しても、全7 phaseのactual handlerと専用mountが同じclosed contractへ接続されなければ実環境E2Eにはならない

## ロールバック

external brokerはdefault disabledとし、production entryが完成しない、host条件が不足する、検証が失敗する場合は外部AIを起動しない。既存アプリの検索経路はハーネスから独立しているため、検索UI、cache、Bonsai/Outscraper設定を削除・変更しない。

失敗したphase/workflow/attemptを巻き戻して再利用しない。artifactを監査用に保持する必要がなければ、人間が対象を確認してcandidate外一時rootを削除する。private key rotationは既存attestationの検証方針を決めた別releaseで行う。

## 結果

候補コードからruntime、snapshot/専用mount、offline network、broker egress、credential、frozen費用ledger、署名、judgeを分ける境界部品、typed external protocol、stdlib固定7-phase state machine、outer `--workflow` entry、7/7 actual handler、frozen sign/judge、exact nonce contract、readiness gate、external-anchor付きworkflow initializer、credential-free deployment check、敵対的回帰テストを実装した。最終gateと独立security reviewは完了し、未修正CRITICAL/HIGHは0である。rootless Podman host、clean release、具体的TaskSpec v2 canary、4 image、実host `nonlive_ready`、UID 1100所有のlive用initial requestまで確認した。残作業は別途人間承認するlive 7-phase E2Eとnonce ledgerの長期運用定義である。

外部OpenAI APIは実行しておらず、credential・送信内容・費用の人間承認もない。これをlive運用済み、課金確認済み、bootstrap自己attest済みとは表現しない。
