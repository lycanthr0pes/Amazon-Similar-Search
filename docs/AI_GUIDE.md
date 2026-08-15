# AI相互レビューとTDD運用規約

## 1. 目的

この文書は、amazon-explorerでAIを利用して実装・レビューするときの強制規約である。AIの自己評価ではなく、固定したtask、RED→GREEN、immutable snapshot、raw execution evidence、独立したreviewer/adversary、署名、deterministic judge、人間承認を同じchainへ結び付ける。

実行コマンドは [HARNESS-RUNBOOK.md](HARNESS-RUNBOOK.md)、脅威と秘密情報の扱いは [SECURITY.md](SECURITY.md)、長時間タスクは [PLANS.md](PLANS.md) と [EXEC-002](plans/EXEC-002-ATTESTED-AI-REVIEW-BOUNDARIES.md)を参照する。

## 2. 現在の境界

現行コードには次がある。

- strictなTaskSpec、policy、gate、review、TDD、verdict、attestation契約
- standalone canonical single-commit policyとGit object再hash
- `.env.example`を含むsecret/credential pathの共有fail-closed policy
- content-addressed base/candidate/RED snapshot
- pinned OCI imageで動くnetworkなしoffline runnerとraw evidence
- credentialを除外したbounded text-only review packet
- tool-free Responses requestとrole別model/effort/token設定
- attempt予約を実行前に耐久化するSQLite broker ledger
- broker専用internal network、credential-free固定egress gateway、raw inspect、cleanup/absenceを結ぶprovisioned evidence
- canonical artifactへのEd25519署名、exact SQLite nonce ledgerによる原子的replay防止、frozen evidenceを使うattested judge
- `snapshot -> red-snapshot -> offline -> review-packet -> broker -> sign -> attested-judge` のdigest chain
- offline/broker専用のprepare→outer execution→coordinator finalizeと、brokerのcanonical frozen final ledger
- request/action/output/result/next requestを再検証するstdlib固定7フェーズstate machine
- immutable phase chainとfrozen broker evidenceからlive broker DBなしでsign/judge共通inputを復元するAPI
- external approved manifest SHA、TaskSpec v2、protected clean candidate、人手承認済みpatch SHAから最初のrequestをcredential/networkなしで作る `runtime_release workflow-init`
- rootless backendとmanifest-pinned 4 imageをcredential/API/external networkなしで検査し、成功を `nonlive_ready` に限定するlauncher `--deployment-check`

現行のproduction wrapperはcanonical prepared/raw broker evidenceとpinned policy bytesからevidenceを再finalizeし、sign/judgeが同じimmutable evidenceからrole別expectationを独立再構築する。host broker ledgerを削除した後もclean provenanceで `pass` を返し得るが、`human_approval_required` は常にtrueである。

2026-08-16時点では、root-owned external launcherのouter `--workflow` entryとinner `prepare|finalize` CLIがあり、7/7 phaseはactual typed protocolへ接続済みである。verified physical snapshotは一般artifactから分離し、専用read-only `/snapshots` mountへ固定した。`sign` はprivate keyをsign prepareだけで使い、`attested-judge` はprivate nonce rootをjudge prepareだけで使う。Arch Linux on WSL2の実ホストへ専用UID、subuid/subgid、rootless Podman `keep-id`、trusted `/opt`、private `/var/lib`、4つのdigest固定imageを配備し、credential-free `nonlive_ready` を確認した。さらにexternal manifest/patch anchorを再照合し、UID 1100所有のprivate artifact rootへlive launcherが読めるinitial requestを生成した。credential、送信内容、費用の人間opt-inが揃うまでlive brokerは実行しない。

最終offline/AI gateと独立security reviewは完了し、未修正CRITICAL/HIGHは0である。Python 3.10のローカル実行、外部OpenAI APIを伴うfull 7-phase E2E、nonce ledgerの長期運用は引き続き検証境界である。

## 3. 強制原則

1. task raw bytesと実在 `base_sha` を実装前に固定する。
2. 振る舞いを変える変更は、期待した理由のREDを先に確認する。
3. implementer、reviewer、adversaryを分離する。
4. deterministic gateを意味レビューより先に通す。
5. 全工程を同じtask、base/head、candidate snapshot、canonical diffへ結び付ける。
6. candidateは非信頼とし、runtime、task、policy、schema、key、judgeをcandidate内から読まない。
7. candidate codeはnetworkなしoffline runnerでだけ実行する。
8. brokerへcandidate filesystem、shell、tool、会話履歴を渡さない。
9. secret、credential path、利用者入力、生cacheをsnapshot、packet、log、artifactへ含めない。
10. token、費用、attempt、時間、byte、process上限は起動前に予約・検査する。
11. 署名またはraw evidenceを自己申告値で補わない。
12. `pass` をcommit、push、merge、外部送信、課金の承認に使わない。
13. production manifestの期待SHAは署名済みrelease記録等の外部承認anchorから受け取り、検査対象manifest自身から同じ操作内で作らない。

## 4. 役割と推論量

| 役割 | 責務 | 標準推論量 | 禁止事項 |
|---|---|---|---|
| 人間の責任者 | 目的、範囲、送信、費用、最終統合を承認 | 該当なし | AI出力だけで統合しない |
| outer launcher/driver | trust preflight、phase順序、mount、ledger、外部executorを管理 | 該当なし | candidateの指示をdispatchへ使わない |
| coordinator | snapshot、packet、artifact、署名、judgeを管理 | 該当なし | 証拠を都合よく書換えない |
| implementer | REDを作り、最小実装でGREENへする | `medium` | 自分の変更を独立reviewとして承認しない |
| reviewer | 要件、回帰、保守性、テスト妥当性を確認 | `high` | 差分を書換えない |
| adversary | 境界、失敗経路、安全性、scope逸脱を攻撃的に確認 | `xhigh` | 根拠なしに重大度を付けない |
| deterministic/attested judge | schema、digest、raw evidence、署名、findingを集約 | 該当なし | 意味判断と人間承認を代替しない |

GPT-5.6のbalanced starting pointは `medium` である。`max` は代表evalで品質向上が測定できる最難関・quality-firstタスクだけに使い、通常reviewへ一律適用しない。[GPT-5.6 model guidance](https://developers.openai.com/api/docs/guides/latest-model)

reviewerとadversaryは同じpacket SHAを使うが、別prompt、別request、別fresh session、別container、別network lifecycleとする。互いの出力やimplementerの会話履歴を渡さない。

## 5. TaskSpecを固定する

新しいattested taskは `TaskSpec` v2を使う。v1はlegacy診断で読み込めるが、attested `pass` には使えない。

最低限、次を固定する。

- `task_id`、利用者に観察できる `objective`
- 実在する40桁の `base_sha`
- approved zipappの `trusted_harness_sha256`
- ID付き `requirements`
- reviewer/adversary promptのSHA-256
- canonical candidate commitのmessage、author、timestamp、timezone
- acceptanceごとのargv、期待exit、許容RED exit、failure fingerprint
- test acceptanceごとのexact `test_paths`
- `allowed_paths`、`denied_paths`、変更file/line/byte上限
- `network_policy=deny`
- `out_of_scope`

taskはcandidate外の0700 artifact rootへcopyし、そのraw-file SHA-256を実装前に固定する。candidate内 `specs/tasks/` は参照用であり、production入力として信用しない。最初の本番canaryも人手承認済みの具体的TaskSpec v2を使い、`specs/tasks/example.task.json` やTASK-006のlegacy v1を流用しない。未知field、型coercion、重複ID、unsafe path、0埋めや存在しないbaseを拒否する。

このリポジトリで継続する対象外:

- ブックマーク表示数を変更するプルダウンを追加しない
- 検索結果件数スライダーをブックマーク設定へ転用しない
- 削除済みPDFを復元または参照しない
- Bonsai、Outscraper、Amazonの実通信をAIハーネス試験に混ぜない

対象外の解釈が変わったら停止し、人間がtaskとPlanを更新する。

productionの初回 `PhaseRequest` は `runtime_release workflow-init` だけで作る。initializerは外部承認済みmanifest SHA、manifestに固定したexact task/public key、現行harness digest、protected standalone clean candidate、人手承認済みpatch SHAを再検証し、CSPRNG由来のworkflow IDとcanonical empty initial artifact digestを持つsequence 1 `snapshot` requestを新規private directoryへexclusive作成してread-only化する。credentialとnetworkを使わない。initializer自体も人手監査済みclean release sourceから実行し、現在のdirty checkoutをtrust anchorにしない。

live opt-in前の配備確認はlauncher `--deployment-check` を使う。このmodeはworkflow path/key/ledger/credential FDを受け取らず、installed TaskSpec v2とverified harnessのbinding、rootless Podman、4つのmanifest-pinned imageをlocal `--pull=never` / `--network=none` smokeで検査する。成功statusは `nonlive_ready` であり、`credentials_read`、`external_api_called`、`external_network_created`、`production_e2e_complete` はすべてfalseでなければならない。`nonlive_ready` をfull workflowまたはlive成功と読み替えない。

## 6. candidateとsnapshot

implementerの作業終了後、coordinatorは次を満たすstandalone candidateだけを受ける。

- `git clone --no-local` / `--no-hardlinks` でlocal objectを共有しない
- linked worktree、submodule checkout、外部git-dir/common-dirを使わない
- `base_sha` を唯一のparentとするcanonical single commit
- tracked、untracked、ignoredを含めclean
- `commondir`、`worktrees`、attributes、alternates、replace ref、metadata内link/mount/特殊fileがない
- commit/tree/blobをGit header込みで再hashできるSHA-1 repository
- allowed path、通常file、UTF-8 text、変更上限を満たす

snapshot作成時はGit treeを検証してからcontent-addressed read-only treeへmaterializeする。`.env.example` は例外的にrepository rootのtracked treeへ存在できるが、64KiB以下のUTF-8、NULなし、credential-like contentなし、assignment valueがすべて空であることを検証した後、snapshotから除外する。値入り、shell文、nested `.env.example` は拒否する。

それ以外の `.env*`、`.envrc`、`.streamlit/secrets.toml`、`cache/` / `.cache/`、generic `credentials` / `credentials.toml` / `secrets.toml`、`.git`、`.ssh/`、`.aws/`、`.azure/`、`.gnupg/`、`.kube/`、`.docker/config.json`、`.netrc`、`.pypirc`、`.npmrc`、Git/provider credential file等は内容を送信せずpathで拒否する。共有policyの正本は `tools/ai_review/sensitive_paths.py` である。

snapshot以後はcandidate repoをmountしない。review packet、broker、sign、judgeはsnapshot/evidenceだけを使う。

## 7. TDD証拠

### 7.1 RED

production codeを変更する前に要求を表す最小テストを追加し、期待した理由で失敗することを確認する。有効なREDには次が必要である。

- TaskSpec v2のacceptance IDとexact `test_paths`
- base snapshotへexact test overlayだけを適用した別RED snapshot
- test content manifestとtest patch SHA-256
- taskで許可した非0 exit code
- taskで固定したfailure fingerprint SHA-256
- raw stdout/stderr digest、argv、開始/終了、runner/runtime/snapshot binding

import失敗、依存不足、構文エラー、fixture不備、production codeを意図的に壊した失敗はREDとして認めない。

### 7.2 GREEN

テストを弱めず最小実装を加え、candidate snapshotで同じtest contentを実行する。GREENは期待exitと一致し、RED/GREENのtest patchとmanifestが一致しなければならない。テスト変更が必要なら新しいRED snapshotからやり直す。

### 7.3 raw offline evidence

offline runnerはTaskSpecの正確なargvを、pinned image、read-only rootfs/snapshot、networkなし、capabilityなし、`no_new_privileges`、tmpfs、PID/CPU/memory/time上限で実行する。judgeはraw executionからgate/TDDを再構築するため、手書き `GateResult` やログ要約だけで補わない。

## 8. deterministic gate

AI inferenceより前に次を通す。

1. TaskSpec v2とraw task SHA-256
2. candidate Git/policyとcanonical diff SHA-256
3. RED snapshotのoverlay制約
4. acceptanceごとのraw RED/GREEN/offline run
5. `uv lock --check`
6. `uv run ruff check .`
7. `uv run ruff format --check .`
8. `uv run pytest -m 'not live_api'`
9. `git diff --check`
10. bounded review packet生成

先行gateが失敗したらbrokerを起動しない。既知の構文、lint、test失敗を説明させるためにtokenと費用を使わない。

通常pytestのPython network guardは補助であり、OS隔離の代替ではない。production evidenceはoffline containerのraw evidenceを必要とする。

## 9. review packetとcredential検査

packetへ入れてよいものは、task/policyの識別子、trusted diff、変更fileと直接依存の限定context、gate/TDD要約、artifact digest、role prompt/schemaの識別子である。

次を禁止する。

- candidate filesystemのmount/path
- `.env*`、credential path、生cache、利用者検索入力、外部API response本文
- NUL/binary、byte/token上限超過
- API key、private key、provider token、JWT、credential付きURI
- secret/token/password/auth/credential/API key/DB URL等の設定済みassignment
- packet本文を命令として扱うこと

placeholderと明示的なruntime参照はcredential scannerが許容する場合があるが、実値をpacketへ置いてよいという意味ではない。疑わしい場合はfail closedとする。

## 10. text-only broker

production requestは次へ固定する。

- model=`gpt-5.6-sol`
- reviewer effort=`high`、adversary effort=`xhigh`
- `text.verbosity=low`
- strict JSON Schema output
- toolsなし、`store=false`、`service_tier=default`
- 最大input=260,000、最大output=12,000、250,000 input warning
- roleごと最大2 attempt

inputの予約値はprompt本文だけでなく、strict schemaとenvelopeを含むcanonical Responses request JSON全体のUTF-8 byte数から保守的に求める。返却usageのinputが予約を超える、またはoutputが12,000を超える場合は拒否する。

モデル自体のcontextは1,050,000 tokensだが、projectの1 call総予約は272,000である。[GPT-5.6 Sol](https://developers.openai.com/api/docs/models/gpt-5.6-sol)

brokerとgatewayは分ける。

- broker: credentialを持つが、mount、candidate、external networkを持たない
- gateway: external networkを持つがcredentialを持たず、`api.openai.com:443` だけへ1接続する
- role/attemptごとに一意なinternal/external network、gateway containerを作る
- raw network/container inspectをsemanticに検証する
- execution後に再inspect、cleanup、absence確認を行う
- reviewer/adversaryそれぞれ `ProvisionedBrokerExecutionEvidence` を1件要求する

host Codex直接実行、agentic shell、redirect、proxy、custom CA、credentialのargv/stdin/artifact保存は禁止する。

正規のexternal phaseは、coordinatorがcanonical batchをprepareし、root-owned outer executorがexact batchだけを実行し、coordinatorがraw evidenceをfinalizeする。offlineは `prepare_offline_phase_action` / `execute_prepared_offline_outer` / `finalize_offline_phase_output`、brokerは `prepare_broker_phase_action` / `execute_prepared_broker_outer` / `finalize_broker_phase_output` を使う。generic `outer_descriptor_executor.py` とlegacy one-run APIをproduction brokerへ流用しない。

## 11. token・費用・attempt ledger

標準packet capは544,000 tokens / 4.54 USD、絶対capは1,088,000 tokens / 7.94 USDである。費用はcanonical `specs/policies/openai-pricing-policy.json` の `service_tier=default` とdigestへ固定し、cache hitを信用せず保守的に予約する。

attemptはAPI起動前にSQLiteへconsumeする。root-owned stdlib outerは `prepare_broker_outer_ledger` でO_EXCL・0600・STRICT schemaの新規ledgerを作り、既存fileを再利用しない。timeout、provider error、invalid response、cleanup後の失敗でも予約を戻さない。roleごとにattempt番号は1から連続し、最大2である。broker outer evidenceは全records、累積token/cost、元のprotected ledger identityをcanonical frozen final ledgerとして持つ。coordinatorはhost SQLiteを削除した後でもprepared payload、outer raw、同じallowlist/pricing policy bytesからreviewer/adversary両方を再finalizeできる。

`reconstruct_attestation_inputs` はimmutable phase chain、dedicated snapshot、raw offline run、broker prepared/raw/frozen ledgerからhost DBなしでsign/judge共通bundleを復元する。frozen judge経路はそのcanonical bytesから失敗attemptを含むledgerを再finalizeするため、raw SQLiteのcopy/bind mountやlive runtime再probeを必要としない。

料金変更時は公式情報を再確認し、新しいpricing policy、version、digest、manifest、capを人間が承認する。古いpolicyを自動更新しない。

## 12. 署名とattested judge

sign workflow prepareだけがcandidate外のread-only Ed25519 private keyをmountできる。attested-judge workflow prepareだけがlauncher所有の0700 nonce ledger rootを専用read-write `/nonce-ledger` mountとして受け取る。task、policy、gate、TDD RED/GREEN、reviewをcanonical envelopeとして署名し、runtime、snapshot、request、runner、argv、log、nonce、時刻へ結び付ける。

nonce ledgerは `application_id=1095062094`、`user_version=1`、`journal_mode=DELETE`、`WITHOUT ROWID` の `used_nonces` tableとexact index/table metadataを要求する。`nonce` は32〜128文字の小文16進、`reserved_at` は0以上のintegerだけを許す。0600の単一regular fileと不変device/inode/owner、0700 directory内の他file・WAL/journal/shm不在を検査する。全署名のbinding・時刻・nonce検証後、nonce setを単一 `BEGIN IMMEDIATE` transactionで予約し、部分衝突でも全件rollbackする。

現行attested judgeのproduction経路は、PhaseResult-boundのfrozen bundleから少なくとも次を再構築する。

- base/candidate/全RED snapshot
- acceptanceを正確に覆うraw offline executions
- reviewer/adversaryのtool-free request、raw request/envelope、inference usage
- reviewer/adversary各1件のdistinct provisioned egress lifecycle
- 失敗attemptを含むfinal broker ledger
- task/policy/gate/TDD/reviewの署名set
- key ID、nonce、age、future skew、replay ledger

改ざん、欠落、重複、別task/head/snapshot/runtime、同一session/lifecycle、期限切れ、replayは `fail` とする。完全なattestationで通常判定もcleanなら `pass`、medium findingやunverified等があれば `human_review`、critical/high、gate失敗、provenance不成立なら `fail` とする。全statusで `human_approval_required=true` である。

phase artifact chainではbrokerのprepared/raw pairとfrozen ledgerを永続化し、`reconstruct_attestation_inputs` がsign/judge共通bundleへ復元する。`build_frozen_bundle_expectations` が署名対象を作り、`judge_frozen_attestation_bundle` が署名とnonceを検証する。この7-phase接続済みという実装事実を、rootless production hostの配備またはlive API E2Eの完了と解釈しない。

## 13. 人間承認

人間は少なくとも次を確認する。

- objective、requirements、out-of-scopeと最終diffが一致する
- clean release commit、TaskSpec v2、4 image digest、external manifest SHA、candidate patch SHAが承認記録と一致する
- REDが期待理由で生じ、同じtest contentがGREENになった
- raw offline、2つのprovisioned broker lifecycle、ledger、署名が同一chainである
- secret、利用者データ、不要なcontextを送っていない
- 実際のtoken、費用、attemptが承認上限内である
- finding/unverifiedと受容理由が妥当である
- commit、push、merge、artifact廃棄の対象が正確である

review JSON、ledger、attestationを手編集して合格扱いにしない。修正したら新しいcandidate commit、snapshot、packet、両review、署名、verdictを作る。

## 14. 停止条件

次で停止する。

- task、runtime、image、schema、policy、prompt、snapshot、packet、phase digestが不一致
- rootless Podman、user namespace、seccomp、別UID、read-only mountが不成立
- secret/credential pathまたはcredential-like contentを検出
- REDが成功する、期待外の理由で失敗する、GREEN/gateが失敗する
- reviewer/adversaryが欠落・重複し、同一session/lifecycleを使う
- fixed egress、gateway credential不在、cleanup/absenceを証明できない
- brokerのfrozen evidenceからsign/judgeが同じexpectationを再構築できない
- token、費用、attempt、time、byte、process上限へ達する
- 要求、対象外、送信内容、課金、削除範囲の解釈が変わる
- 人間の外部AI/credential/費用opt-inがない

同じ失敗を原因変更なしで再試行しない。consume済みworkflow/attemptを再利用せず、新しいIDで最初から作る。

## 15. artifact保存

artifactはcandidateとsource checkoutの外にある0700 directoryへ置き、各fileをexclusive 0600、phase完了後のtreeをread-onlyにする。outer workflow runtimeは各phaseを `NN-phase/{prepare-input,prepare-output,finalize-input,finalize-output,committed}` へ分ける。`committed/` にはrequest、prepared/finalized transition、prepared payload、`coordinator-output.json`、`artifact-manifest.json`、`phase-result.json` を保存する。offline/brokerはさらに `external-evidence.json` を保存し、初回はinitial inputs、それ以後は直前のimmutable committed treeを `prior-artifacts/` へcopyする。brokerの `external-evidence.json` にはprovisioned lifecycleとfrozen final ledgerが含まれ、raw SQLite copyを証拠として残さない。

initial artifact rootだけは `workflow-init` が存在しないpathへ0700/0600で作成後、directory 0500、`phase-request.json` 0400へ凍結する。手作業で同名requestを置いたり、失敗済みpathを削除して再利用したりしない。

保存対象はtask、phase request/result、snapshot manifest、raw offline evidence、packet、broker request/envelope/lifecycle/frozen ledger、usage、attestation、verdictである。

API credential、private key、生cache、利用者入力、不要な外部response本文はartifactへ保存しない。private keyは別の0400 pathに置き、sign workflow prepare以外へ渡さない。nonce ledger rootはlauncher/coordinator所有の0700 directoryとし、空または0600の `nonces.sqlite3` だけを含める。長期判断だけを [WORKLOG.md](WORKLOG.md) とExecution Planへ転記する。

## 16. 最小チェックリスト

開始前:

- [ ] 人間が目的、対象外、送信内容、費用上限を確認した
- [ ] TaskSpec v2 raw SHA、base、prompt、harness、pricing/egress policyを固定した
- [ ] trusted releaseをclean approved commitから構築した
- [ ] external approved manifest SHAとhuman-approved candidate patch SHAから `workflow-init` を実行した
- [ ] rootless Podman `keep-id`、別UID、seccompを確認した
- [ ] credentialなしの `--deployment-check` が `nonlive_ready` を返し、4 image digestを照合した
- [ ] candidate外のartifact root、nonce/phase/broker ledger、keyを用意した

TDD・gate:

- [ ] exact test overlayのRED snapshotを作った
- [ ] 同じtest contentをcandidate snapshotでGREENにした
- [ ] 全acceptanceをraw offline evidenceが覆う
- [ ] deterministic gateを先に通した

review・署名:

- [ ] sanitized bounded packetを固定した
- [ ] reviewer/adversaryを別fresh lifecycleで実行した
- [ ] 失敗attemptを含むtoken/cost ledgerが上限内である
- [ ] frozen broker evidenceをlive SQLite/runtime probeなしでjudgeへ再入力できる
- [ ] 全artifactをsignし、attested judgeで再構築した
- [ ] 人間が最終diff、evidence、費用を承認した

現行outer `--workflow` entryは7/7 readiness gateを通る。不完全なreleaseへ回帰した場合はcredential read・broker ledger作成より手前でfail closedする。このチェックリストを手作業でつないでlive運用を開始しない。
