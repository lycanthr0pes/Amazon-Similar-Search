# AI相互レビュー・ハーネス実行手順

## 1. この文書の結論

amazon-explorer のAI相互レビュー境界は、import前preflight、immutable snapshot、networkなしoffline runner、bounded review packet、固定egress、Ed25519署名、attested judgeまでの7フェーズをactual typed処理へ接続済みである。brokerのcanonical `prepared-payload.json` と `external-evidence.json` からhost SQLiteなしでevidenceを再finalizeし、`sign` と `attested-judge` が同じimmutable evidenceからrole別expectationを独立再構築する。host broker ledger削除後の `pass`、改ざん拒否、nonce replay拒否も回帰テストで確認済みである。

ただし、「credential-freeの本番配備前提を実hostで検証済み」と「外部OpenAI APIを使う7フェーズをlive実行済み」は別である。2026-08-16にPodman stack、専用user、subuid/subgid、trusted/private path、clean release、TaskSpec v2 canary、4つのOCI imageを配備し、rootless Podman 6.1のuser namespaceとseccompを使う `--deployment-check` が `status="nonlive_ready"` で成功した。出力は `credentials_read=false`、`external_api_called=false`、`external_network_created=false`、`production_e2e_complete=false` である。

検証したreleaseは `/opt/amazon-explorer-ai-review/releases/dd4b6bde2bd2d7f3ebc67c5190949c1cc97652ee`、private stateは `/var/lib/amazon-explorer-ai-review` に分離した。coordinatorは `ai-review`（UID 1100）、candidate identityは `amazon-candidate`（UID 1101）である。package導入、public registryからのdigest固定base image pull、image build中のpackage取得、4 image buildは行ったが、OpenAI credentialを読み込まず、OpenAI API、live workflow、外部review packet送信、課金は実行していない。

本番利用には、次のすべてが必要である。

- 人手監査済みcommitから作ったroot-owned runtime
- rootless Podman、user namespace、`keep-id`、有効なseccomp
- candidateと異なる非root coordinator OS user
- digest固定済みの4つの異なるOCI image
- candidate外のprivate artifact rootとEd25519 private key
- launcher所有のprivate nonce ledger root
- 外部送信内容、credential、費用上限に対する人間の明示承認

上記の非live配備前提は成立したが、full 7-phase live workflowには、外部送信内容、OpenAI credential、費用上限、nonce ledger長期運用に対する別の人間承認が必要である。実装はDocker/rootful Podmanへfallbackせず、要件不足ではfail closedで停止する。外部OpenAI API、Bonsai、Outscraper、Amazonへの実通信、課金、commit、push、mergeをこの手順の診断で暗黙に行わない。

運用規約は [AI_GUIDE.md](AI_GUIDE.md)、脅威と保護対象は [SECURITY.md](SECURITY.md)、実装計画は [EXEC-002](plans/EXEC-002-ATTESTED-AI-REVIEW-BOUNDARIES.md)を正とする。

## 2. 実装状態

| 領域 | 現行実装 | 運用上の扱い |
|---|---|---|
| deterministic gate | lock、Ruff、offline pytest、diff check | source checkoutで診断可能 |
| runtime release | deterministic zipapp、schema bundle、Ed25519 keygen、runtime manifest | 承認済みclean commitからtrusted buildする |
| workflow初期化 | `runtime_release workflow-init` がexternal approved manifest SHA、TaskSpec v2、task/harness/key、protected clean candidate、人手承認済みpatch SHAを再検証し、sequence 1 requestを新規・凍結保存 | credential/API/networkなし。manifest SHAを同じinstall先から都合よく作らない |
| import前preflight | stdlib-only、raw SHA-256、open FD、Python inode/digest、`-I -S`、root-owned path | source-tree起動は診断専用 |
| snapshot | standalone clone、Git object再hash、read-only content-addressed snapshot、RED snapshot、専用physical store/RO mount | candidateを変更できるUIDから分離し、一般artifactへ混在させない |
| offline runner | read-only rootfs/candidate、networkなし、capabilityなし、resource上限、raw evidence | pinned runner imageで実行する |
| review packet | trusted diffと限定context、credential検査、canonical request全体のbyte/token上限 | candidate filesystemをbrokerへ渡さない |
| broker egress | role・attemptごとのinternal network、credential-free固定gateway、raw inspect、後検査、cleanup/absence証拠 | reviewerとadversaryの2つのprovisioned lifecycleが必須 |
| 費用ledger | SQLiteでattemptを実行前予約し、失敗attemptも累積上限へ算入 | roleごと最大2 attempt。消費済み番号を再利用しない |
| attestation | canonical artifact envelope、Ed25519、nonce ledger、replay/tamper検査 | private keyはsign workflow prepareだけへread-only mountする |
| attestation input | immutable phase chain、snapshot、raw offline、broker prepared/raw/frozen ledgerからsign/judge共通bundleを再構築 | host broker DB/runtime再probeは不要。sign/judgeが同じimmutable evidenceからexpectationを独立再構築する |
| attested judge | frozen bundleからraw offline、2つのprovisioned broker evidence、final ledger、全署名とbindingを再構築 | host ledger削除後も `pass` 可。全verdictで人間承認必須 |
| nonce ledger | exact SQLite schema/PRAGMA/index/file identityを検査し、`BEGIN IMMEDIATE`内でset全体を予約 | replayまたは部分重複はrollbackし、一部だけconsumeしない |
| phase別outer protocol | offline/broker専用のprepare→outer execution→coordinator finalize、frozen final ledger | host DB削除後のbroker再finalizeからsign/judgeまで接続済み |
| 7フェーズprotocol | digest chain、SQLite replay ledger、closed phase order、phase別mount権限、stdlib固定state machine、outer workflow runtime | 7/7 actual handlerを接続済み |
| 一括production entry | launcherの `--workflow`、inner `--workflow-operation prepare|finalize`、7/7 readiness gate | 実装上はready。本番実行はapproved host/release/credential/費用の人間opt-in後だけ |
| credential-free deployment check | launcherの `--deployment-check` がrootless backend、manifest固定の4 image、local metadata、networkなしsmokeを検査 | 成功は `nonlive_ready` だけ。credential/API/external networkを使わず、production E2E完了を表さない |

`CodexAdapter.run_text_review()` のhost直接実行は禁止されたままである。production brokerはtool-free Responses requestだけを受け、candidate path、shell、tool、会話履歴を持たない。

## 3. 正規の7フェーズ

順序は固定であり、飛越し、並替え、同じphaseの再利用を許可しない。

```text
snapshot
  -> red-snapshot
  -> offline
  -> review-packet
  -> broker
  -> sign
  -> attested-judge
  -> human approval
```

各 `PhaseRequest` はworkflow、task、runtime manifest、coordinator public key、candidate、前phase、入力artifactをSHA-256で結ぶ。`snapshot` prepareだけがcandidateをmountでき、`sign` prepareだけがprivate keyをread-only mountできる。`attested-judge` prepareだけがlauncher所有のprivate nonce ledger rootを `/nonce-ledger` へread-write mountできる。`offline` と `broker` だけがouter executorを使う。

outer workflow runtimeは各phaseを `NN-phase/` へ分け、`prepare-input/`、`prepare-output/`、`finalize-input/`、`finalize-output/`、`committed/` を新規exclusive作成する。commit後はtreeをread-only化する。`committed/` には次を残し、初回はinitial artifact tree、それ以後は直前のimmutable committed treeを `prior-artifacts/` へcopyする。直接の `phase-result.json` とdigest chainを再検証してから次へ進む。

physical snapshotだけは一般artifact treeへcopyしない。hostの `snapshot-artifacts/{snapshots,red-snapshots}/<sha>/tree` に保持し、snapshot phase後のcoordinatorへ専用read-only `/snapshots` mountとして渡す。PhaseResultのsemantic SHA集合とphysical directory集合をexact照合し、candidate pathはsnapshot phase以外へ渡さない。これによりsnapshot内の `AGENTS.md` を許容しつつ、一般 `/artifacts` のAGENTS拒否を弱めない。

repository rootのtracked `.env.example` だけは64KiB以下のUTF-8、NULなし、credential-like contentなし、全assignment空値を検証した後にsnapshot実行treeから除外する。nested `.env.example`、それ以外の `.env*`、`.envrc`、`.streamlit/secrets.toml`、`cache` / `.cache`、generic `credentials` / `credentials.toml` / `secrets.toml`、provider credential pathは内容を読まずpathで拒否する。

| artifact | 内容 |
|---|---|
| `phase-request-input.json` | そのphaseが直接検証したcanonical request |
| `prepared-transition.json` | coordinator actionとpayloadを結ぶcanonical prepared envelope |
| `prepared-payload.json` | coordinatorが承認したexact payload。offline/brokerでは専用canonical batch |
| `external-evidence.json` | exact outer raw evidence。offline/brokerだけ。brokerではfrozen final ledgerを含む |
| `finalized-transition.json` | result、coordinator output、次requestを結ぶcanonical finalized envelope |
| `coordinator-output.json` | coordinatorが再検証したtyped canonical artifact envelope |
| `artifact-manifest.json` | 次phaseの `input_artifacts_sha256` に使うartifact集合 |
| `phase-result.json` | request、anchor、出力digestを含むdurable phase履歴 |
| `prior-artifacts/` | 初回はinitial inputs、それ以後は直前までのread-only committed tree |
| `prepare-output/` / `coordinator-files/` | pinned coordinatorが各operationで書いた補助artifactのimmutable copy |
| `broker-runtime-binding.json` | outerが事前計測したpath-free runtime/security/environment binding。broker phaseだけ |

このartifact契約から `reconstruct_attestation_inputs` がsign/judge共通bundleと2つのtyped provisioned evidenceをhost DBなしで再構築する。`build_frozen_bundle_expectations` はcanonical prepared/raw pairとpinned policy bytesからbroker evidenceを再finalizeし、`judge_frozen_attestation_bundle` は同じbundleと署名setをlive ledger/runtime probeなしで判定する。raw SQLiteのcopy/bind mountは証拠にしない。

途中で失敗または中断したworkflowは同じphaseをやり直さない。新しい `workflow_id` と新しいartifact rootで最初から開始する。

## 4. シナリオ: 外部通信なしで開発状態を確認する

症状・目的: 変更が決定論的ゲートを壊していないかを確認したい。

最初の操作:

```sh
cd /home/products/Git_Products/amazon-explorer
uv sync --locked
uv lock --check
uv run ruff check .
uv run ruff format --check .
uv run pytest -m 'not live_api'
git diff --check
```

ハーネス境界だけを絞る場合:

```sh
uv run pytest -q \
  tests/test_ai_review_runtime_release.py \
  tests/test_ai_review_workflow_init.py \
  tests/test_ai_review_deployment_check.py \
  tests/test_ai_review_coordinator_launcher.py \
  tests/test_ai_review_phase_protocol.py \
  tests/test_ai_review_outer_driver.py \
  tests/test_ai_review_outer_workflow_state.py \
  tests/test_ai_review_outer_workflow_runtime.py \
  tests/test_ai_review_coordinator_workflow_ops.py \
  tests/test_ai_review_coordinator_attestation_inputs.py \
  tests/test_ai_review_offline_phase_protocol.py \
  tests/test_ai_review_broker_phase_protocol.py \
  tests/test_ai_review_phase_execution_adapters.py \
  tests/test_ai_review_trust_boundary.py \
  tests/test_ai_review_broker_executor.py \
  tests/test_ai_review_broker_egress_provisioner.py \
  tests/test_ai_review_attested_judge.py \
  tests/test_network_policy.py \
  -m 'not live_api'
```

次の確認: 終了コードだけでなく、skip理由、失敗した境界、`git diff --check` を確認する。固定のテスト件数は文書へ埋め込まない。

安全上の注意: 通常pytestのnetwork guardは補助防御である。subprocess/native codeまでOSレベルで遮断した証明にはならない。実シークレットを含むcheckoutで、ハーネス全体をattested candidateとして直接実行しない。

## 5. シナリオ: production hostの前提を診断する

症状・目的: launcherがrootless Podmanを要求して停止する理由を、package、user、権限を変更せずに確認したい。

最初の操作:

```sh
id
uname -a
command -v podman
grep -E '^ai-review:|^amazon-candidate:' /etc/subuid /etc/subgid 2>/dev/null || true
getent passwd ai-review amazon-candidate || true
stat -c '%U:%G %a %n' /home/products
test -e /opt/amazon-explorer-ai-review && \
  stat -c '%U:%G %a %n' /opt/amazon-explorer-ai-review
test -e /var/lib/amazon-explorer-ai-review && \
  stat -c '%U:%G %a %n' /var/lib/amazon-explorer-ai-review
docker info --format '{{json .SecurityOptions}}'
```

2026-08-16の配備前診断では、Arch Linux on WSL2、UID 0、Podmanなし、subuid/subgid割当なし、専用userなし、user namespaceなしのrootful Dockerであった。`/home/products` は0777で、`/opt/amazon-explorer-ai-review` と `/var/lib/amazon-explorer-ai-review` は存在しなかった。rootful Docker storeにあったrunner/broker imageも現行4-role releaseと一致せず、coordinator/gatewayが揃わなかった。この記録は不足を検出した時点の履歴であり、後続の承認済み配備で次の状態へ更新した。

| 項目 | 2026-08-16の後続配備で確認した値 |
|---|---|
| container backend | rootless Podman 6.1、user namespace有効、seccomp有効 |
| coordinator / candidate identity | `ai-review` UID 1100 / `amazon-candidate` UID 1101 |
| subordinate ID | `ai-review` 専用の `/etc/subuid` / `/etc/subgid` 範囲 |
| trusted release | `/opt/amazon-explorer-ai-review/releases/dd4b6bde2bd2d7f3ebc67c5190949c1cc97652ee` |
| private state | `/var/lib/amazon-explorer-ai-review/{home,artifacts,broker-ledger,nonce-ledger}` と0400 private key |
| clean base / canary head | `dd4b6bde2bd2d7f3ebc67c5190949c1cc97652ee` / `c603ec833e13f13bdce5af4e0b36f5917e0d4f98` |
| deployment result | `nonlive_ready`。credential、OpenAI API、external network、production E2Eはいずれもfalse |

次の確認:

- launcher/coordinatorをrootで実行していない
- Podmanがrootlessで動き、user namespaceとseccompが有効である
- coordinator OS userとcandidate UIDが異なる
- `podman run --userns=keep-id:uid=65532,gid=65532` を実行できる
- runtime executableと全trusted assetがcandidateから書換不能である
- 4 imageが同一releaseの異なるapproved digestであり、rootless Podman userのimage storeから `name@sha256:...` で参照できる

Dockerしかない、Podmanがrootful、user namespaceが無効、seccompが `unconfined`、現在の実行者がrootのいずれかなら停止が正しい。Docker/rootful用に設定を弱めない。専用の非root OS userとrootless Podmanを用意してから再診断する。

rootless Podmanを準備する場合の最初の操作は、[Podman installation](https://podman.io/docs/installation) と [Podman rootless mode](https://docs.podman.io/en/latest/markdown/podman.1.html) を読み、管理者が専用user名、subuid/subgid範囲、trusted prefix、private state、backup/rollbackを承認することである。Archのpackage更新・導入、`useradd` / `usermod`、`/etc/subuid` / `/etc/subgid`、`/opt` / `/var/lib` の作成はsystem全体を変えるため、この診断の一部として自動実行しない。

承認後は管理者が公式手順に従ってPodmanと専用非rootuserを用意し、そのuserのsessionで次を確認する。

```sh
test "$(id -u)" -ne 0
podman info --format json
grep -E "^$(id -un):" /etc/subuid /etc/subgid
podman unshare cat /proc/self/uid_map
```

次の確認: rootless、user namespace、seccomp、subuid/subgidがすべて確認できてから、candidateを書き換えられないroot-owned releaseとprivate stateを別々に配置する。rootful Dockerの既存imageはrootless Podmanのuser-specific storeに自動移行されないため、承認済みdigestをrootless側で別途取得またはbuildし直す。

安全上の注意: 数値UID/GIDやsubuid/subgid範囲を別hostへ例からコピーせず、既存割当との重複を先に調べる。`/home/products` の権限を一括変更したり、古いDocker imageを本番releaseとして再利用したりしない。今回のpackage/user/system変更とimage取得は承認範囲内で行ったが、別hostでの再実施には対象とrollbackの新しい承認が必要である。

### 5.1 専用userのPodman state境界を準備する

症状・目的: 専用userでは `podman info` が動くのにdeployment checkがHOME、XDG、storage設定のtrust検査で停止する、またはcandidateがPodmanのconfig/image storeへ影響できない状態を先に作りたい。

最初の操作: systemを変更する前に、passwdに登録された専用userのHOMEと、launcherが固定して使う4つのenvironment pathを読み取り専用で確定する。`$REVIEW_USER` は管理者が承認した専用非rootuserであり、candidate userと同じにしない。

```sh
REVIEW_USER=ai-review
REVIEW_UID=$(id -u "$REVIEW_USER")
REVIEW_HOME=$(getent passwd "$REVIEW_USER" | awk -F: '{print $6}')
XDG_CONFIG_HOME="$REVIEW_HOME/.config"
XDG_DATA_HOME="$REVIEW_HOME/.local/share"
XDG_RUNTIME_DIR="/run/user/$REVIEW_UID"

test "$REVIEW_UID" -ne 0
test -n "$REVIEW_HOME"
getent passwd "$REVIEW_USER"
stat -c '%U:%G %a %F %n' \
  "$REVIEW_HOME" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" "$XDG_RUNTIME_DIR"
```

pathがない、symlinkである、POSIX ACLがある、group/world writableである、candidate所有である、またはprivate leafが専用user所有でない場合は、Podmanを起動せず停止する。各pathの全祖先はrootまたはlauncher user所有かつgroup/world非writableでなければならない。launcherはcallerの任意な `HOME` / `XDG_*` を継承せず、passwd HOMEから次を固定し、backend probe、image inspect、4 role smoke、cleanupの全Podman commandで同じcanonical environmentを使う。

- `HOME=$REVIEW_HOME`
- `XDG_CONFIG_HOME=$REVIEW_HOME/.config`
- `XDG_DATA_HOME=$REVIEW_HOME/.local/share`
- `XDG_RUNTIME_DIR=/run/user/$REVIEW_UID`

管理者承認後の準備では、passwd HOME、`$REVIEW_HOME/.config`、`$REVIEW_HOME/.local/share`、login sessionが管理する `/run/user/$REVIEW_UID` を専用user所有のprivate directoryとして用意する。さらに `$XDG_CONFIG_HOME/containers/storage.conf` は専用user所有0600、その親、expected graph root、expected run rootは0700とする。`storage.conf` は承認した `graphroot` / `runroot` だけを使い、別image storeへ迂回するactive `imagestore` / `additionalimagestores` を設定しない。`graphOptions` によるimagestore指定も認めない。directory作成、owner変更、ACL削除、session/linger設定、storage設定変更はsystem変更であるため、診断commandへ混ぜず、対象pathとrollbackを承認した管理者が別作業で行う。

次の確認: 同じ明示environmentで得た `podman info --format json` のrootless/user namespace、seccomp、`store.graphRoot`、`store.runRoot`、`store.configFile` を承認したpathと照合する。deployment checkはこのstore/security stable subsetをimage検査の前後で再計測し、environment、graph root、run root、active config、seccompのbindingが変わればfail closedにする。

安全上の注意: shellで一度成功した `podman info`、rootful Docker store、任意の `HOME` / `XDG_*`、追加image storeをrelease証拠へ流用しない。現行配備ではpasswd由来の `/var/lib/amazon-explorer-ai-review/home` と専用XDG pathを固定し、active storage configを含むstable subsetをdeployment checkの前後で照合した。

## 6. シナリオ: trusted releaseを構築・配備する

### 6.1 前提

releaseは通常の開発checkoutではなく、人手監査済みのclean commitをcheckoutしたcandidate-inaccessibleなbuild環境で作る。現行のdirty worktreeや、ハーネスを含まない既存HEADからbuildしてはならない。最初の本番canaryには、0埋めplaceholderでない、実在base commitと現行harness digestを固定した人手承認済みTaskSpec v2を使う。`specs/tasks/example.task.json` とlegacy TaskSpec v1をproduction入力にしない。

次の例の大文字変数は、承認者が実値へ固定するplaceholderである。コマンドをそのまま実API環境へ貼り付けない。2026-08-16の配備では、OpenAI credentialを渡さず、public registryからdigest固定のPython/uv base imageを取得し、image内package取得を伴うbuildを行った。これはOpenAI APIやreview packetの外部送信ではない。registryへのpushは行っていない。

現行の検証済みrelease bindingは次である。

| artifact | SHA-256 / commit |
|---|---|
| clean base commit | `dd4b6bde2bd2d7f3ebc67c5190949c1cc97652ee` |
| harness | `0d27b9c541b01b1fb6f02c270286965c1507748abe5f5667ac5a9e7250426278` |
| runtime manifest | `703d2e183558afe6e52198247888675d7f0b526f5082051a9ae75d5ea3a402ae` |
| TaskSpec v2 raw bytes | `8507bc001dcf4d383ce43cb335e65851da740c10d6e3c4dd752c1f762b1b32fd` |
| canary candidate commit | `c603ec833e13f13bdce5af4e0b36f5917e0d4f98` |
| canonical candidate patch | `a9d49bea2225a903fe693f913c1f8652cdea56d02b03355e17f472363ca3b715` |
| coordinator image | `sha256:bd1e77e913eeecce78fe2ace2ac595a061d2c92ed4a335a137e9bf2b31d33d03` |
| offline runner image | `sha256:9ed1d64387776f3026efbcdf4957bfcd0b296493e784c6a775a17f1691f0b8b4` |
| broker image | `sha256:cec5e091d220e87bf0e1723ee59ea1062cf7bb5d6371cf2b55839754b470a1b1` |
| broker gateway image | `sha256:36509c46496d5c3779e66185de9babf8d8ea34a1adf9fee297684c3e54cb11aa` |

root-owned source、launcher、manifest、runtime assetは `/opt/amazon-explorer-ai-review/releases/dd4b6bde2bd2d7f3ebc67c5190949c1cc97652ee/{source,bin,runtime}` に置く。build検証用canaryは `/var/lib/amazon-explorer-ai-review/candidates/TASK-CANARY-001-r2`、live初期化用のUID 1100所有standalone cloneは `/var/lib/amazon-explorer-ai-review/live-candidates/TASK-CANARY-001-r2` にある。credential-free initializerの旧確認用出力 `/var/lib/amazon-explorer-ai-review/build/workflow-init-r2/initial` はroot所有のbuild証拠として保持し、live入力には使わない。live用requestは `/var/lib/amazon-explorer-ai-review/artifacts/TASK-CANARY-001-live-init-r2` にUID 1100所有0500/0400で新規生成した。private keyの内容は表示せず、`/var/lib/amazon-explorer-ai-review/coordinator-private.pem` を `ai-review` 所有0400として保持する。

4 imageは同一digestを使い回さず、承認したrootless image storeまたはtrusted registryで確定したimmutable digestを記録する。

```sh
podman build --pull=never -f containers/ai-review-coordinator/Dockerfile \
  -t "$COORDINATOR_TAG" .
podman build --pull=never -f containers/ai-review-runner/Dockerfile \
  -t "$RUNNER_TAG" .
podman build --pull=never -f containers/ai-review-broker/Dockerfile \
  -t "$BROKER_TAG" .
podman build --pull=never -f containers/ai-review-egress/Dockerfile \
  -t "$GATEWAY_TAG" .
```

これらのDockerfileはbase imageをdigest固定するが、coordinator/runner buildの `apt-get` とdependency installはpackage repositoryへ通信する。承認済みbuild networkでだけ実行し、OpenAI credentialを渡さない。registryへのpush、署名、digest確定はrelease管理者の承認範囲で行う。manifestにはtagでなく `sha256:...` を記録し、実行時imageも `name@sha256:...` にする。

### 6.2 runtime assetを作る

```sh
release_stage=$(mktemp -d)
chmod 700 "$release_stage"

uv run python -m tools.ai_review.build_zipapp \
  --source-root . \
  --output "$release_stage/harness.pyz"

uv run python -m tools.ai_review.runtime_release schema-bundle \
  --schema-dir specs/schemas \
  --output "$release_stage/schemas.json"

uv run python -m tools.ai_review.runtime_release keygen \
  --private-key "$release_stage/coordinator-private.pem" \
  --public-key "$release_stage/coordinator-public.pem"
```

private keyを再生成すると既存attestationを検証できなくなる。初回導入後のrotationは別releaseとして扱う。

`$APPROVED_TASK` の `trusted_harness_sha256` は、ここで作った `harness.pyz` の表示SHA-256と一致させる。task raw bytesとそのSHA-256を人間が承認してからinstallへ進む。

### 6.3 root-owned trust rootへinstallする

例では `/opt/amazon-explorer-ai-review/releases/$RELEASE_ID` をimmutable release root、`ai-review` を非root coordinator userとする。`$RELEASE_ID` は承認済みclean base commitの40桁SHA-1へ固定する。

```sh
RELEASE_ROOT="/opt/amazon-explorer-ai-review/releases/$RELEASE_ID"
sudo install -d -o root -g root -m 0755 "$RELEASE_ROOT/bin"
sudo install -d -o root -g root -m 0755 "$RELEASE_ROOT/runtime"
sudo install -d -o root -g root -m 0711 /var/lib/amazon-explorer-ai-review
sudo install -d -o ai-review -g ai-review -m 0700 \
  /var/lib/amazon-explorer-ai-review/artifacts \
  /var/lib/amazon-explorer-ai-review/broker-ledger \
  /var/lib/amazon-explorer-ai-review/nonce-ledger

sudo install -o root -g root -m 0555 tools/ai_review/external_launcher.py \
  "$RELEASE_ROOT/bin/external_launcher.py"
sudo install -o root -g root -m 0444 tools/ai_review/preflight.py \
  "$RELEASE_ROOT/bin/preflight.py"
sudo install -o root -g root -m 0444 "$release_stage/harness.pyz" \
  "$RELEASE_ROOT/runtime/harness.pyz"
sudo install -o root -g root -m 0444 "$release_stage/schemas.json" \
  "$RELEASE_ROOT/runtime/schemas.json"
sudo install -o root -g root -m 0444 "$release_stage/coordinator-public.pem" \
  "$RELEASE_ROOT/runtime/coordinator-public.pem"
sudo install -o root -g root -m 0444 uv.lock \
  "$RELEASE_ROOT/runtime/uv.lock"
sudo install -o root -g root -m 0444 "$APPROVED_TASK" \
  "$RELEASE_ROOT/runtime/task.json"
sudo install -o root -g root -m 0444 specs/policies/broker-egress-policy.json \
  "$RELEASE_ROOT/runtime/broker-egress-policy.json"
sudo install -o root -g root -m 0444 specs/policies/openai-pricing-policy.json \
  "$RELEASE_ROOT/runtime/openai-pricing-policy.json"
sudo install -o ai-review -g ai-review -m 0400 "$release_stage/coordinator-private.pem" \
  /var/lib/amazon-explorer-ai-review/coordinator-private.pem
```

manifestの `python.path` はlauncherを実際に起動する、symlinkでないroot-owned executableそのものにする。launcherは現在の `sys.executable` のpath、inode、SHA-256をmanifestと再照合する。

### 6.4 manifestを固定する

次は承認済みbuild checkoutで行う例である。`$APPROVED_PYTHON` と4つのdigestは事前に確定させる。manifestはinstalled absolute pathを記録するため、root-owned assetを配置した後、利用者所有の一時stageへ新規生成し、最後にroot-owned pathへinstallする。

```sh
uv run python -m tools.ai_review.runtime_release manifest \
  --output "$release_stage/runtime-manifest.json" \
  --python "$APPROVED_PYTHON" \
  --harness "$RELEASE_ROOT/runtime/harness.pyz" \
  --task "$RELEASE_ROOT/runtime/task.json" \
  --dependency-lock "$RELEASE_ROOT/runtime/uv.lock" \
  --schema-bundle "$RELEASE_ROOT/runtime/schemas.json" \
  --coordinator-public-key "$RELEASE_ROOT/runtime/coordinator-public.pem" \
  --broker-egress-policy "$RELEASE_ROOT/runtime/broker-egress-policy.json" \
  --openai-pricing-policy "$RELEASE_ROOT/runtime/openai-pricing-policy.json" \
  --coordinator-image-digest "$COORDINATOR_DIGEST" \
  --offline-runner-image-digest "$RUNNER_DIGEST" \
  --broker-image-digest "$BROKER_DIGEST" \
  --broker-gateway-image-digest "$GATEWAY_DIGEST" \
  --broker-packet-reservation-limit 544000 \
  --broker-packet-cost-limit-microusd 4540000

sudo install -o root -g root -m 0444 "$release_stage/runtime-manifest.json" \
  "$RELEASE_ROOT/runtime/runtime-manifest.json"
sha256sum "$RELEASE_ROOT/runtime/runtime-manifest.json"
```

最後のSHA-256を署名済みrelease記録または同等の外部承認記録へ固定し、production実行者へ `$APPROVED_MANIFEST_SHA256` として別経路で渡す。同じinstall先のmanifestを実行直前に `sha256sum` した値は整合性診断には使えるが、それ自体を承認anchorにしてはならない。価格ファイルは `service_tier=default`、model、rates、long-context倍率をcanonical bytesとSHA-256で固定する。料金が変わったらコード値を暗黙に信用せず、公式料金を再確認し、新しいpolicy/version、manifest、費用上限を人間承認する。

## 7. シナリオ: workflowを初期化し、配備境界を確認する

### 7.1 人間承認済みcandidateから最初のrequestを作る

症状・目的: 手書きのworkflow IDや0埋めplaceholderを使わず、承認済みreleaseとcandidateに結び付いたsequence 1の `snapshot` requestを作りたい。

最初の操作: 承認者が、署名済みrelease記録のmanifest SHA-256と、protected standalone clean candidateのcanonical patch SHA-256を別々に確認する。initializerは人手監査済みclean commitの保護されたrelease sourceから実行し、現在のdirty worktreeを権威実装として使わない。

```sh
cd "$APPROVED_RELEASE_SOURCE"
RELEASE_ROOT="/opt/amazon-explorer-ai-review/releases/$RELEASE_ID"
test -n "$APPROVED_MANIFEST_SHA256"
test -n "$HUMAN_APPROVED_PATCH_SHA256"
test ! -e "$INITIAL_ARTIFACT_ROOT"

uv run --frozen --offline --no-sync python \
  -m tools.ai_review.runtime_release workflow-init \
  --task "$RELEASE_ROOT/runtime/task.json" \
  --runtime-manifest "$RELEASE_ROOT/runtime/runtime-manifest.json" \
  --expected-runtime-manifest-sha256 "$APPROVED_MANIFEST_SHA256" \
  --coordinator-public-key \
    "$RELEASE_ROOT/runtime/coordinator-public.pem" \
  --candidate-repo "$PROTECTED_CANDIDATE_REPO" \
  --candidate-uid "$CANDIDATE_UID" \
  --expected-patch-sha256 "$HUMAN_APPROVED_PATCH_SHA256" \
  --output-dir "$INITIAL_ARTIFACT_ROOT"
```

initializerはcredentialを読まずnetworkへ接続しない。`runtime_release` builderはPydantic modelでTaskSpec v2全体をstrict検証し、task raw bytesとharness digestをruntime manifestへ固定する。external launcherのimport前stdlib検査は、このfull schemaを複製せず、manifestが保持するtask FDのstrict JSON、`schema_version=2.0`、`trusted_harness_sha256` とverified harnessの一致だけを再確認する。完全なTaskSpec検証はbuilder、raw task/harnessの固定はmanifest、manifest自体の信頼はinstall先とは別経路のexternal approved SHAが担う。さらにcandidateのstandalone/clean/single-commit policyと人手承認済みpatch SHAを再検証する。`$INITIAL_ARTIFACT_ROOT` は存在してはならず、そのsymlink-free parentは実行user所有のprivate directoryでなければならない。

次の確認: stdoutの `candidate_sha256`、`runtime_manifest_sha256`、`task_sha256`、`coordinator_public_key_sha256` を承認記録と照合する。成功時は8つの非secret SHA-256だけがJSONで出力され、new directoryは0500、`phase-request.json` は0400へ凍結される。requestはCSPRNG由来のnew `workflow_id`、`phase=snapshot`、`sequence=1`、公開されたempty initial artifact digestを持つ。

安全上の注意: `sha256sum` で同じinstalled manifestから作った値を `$APPROVED_MANIFEST_SHA256` の代わりにしない。既存outputを消して再利用せず、失敗時は承認内容を再確認して別のnew pathへ初期化する。credential/API/live networkはこの操作へ渡さない。

旧 `/var/lib/amazon-explorer-ai-review/build/workflow-init-r2/initial` はroot所有のbuild証拠として流用せず、external manifest SHA-256 `703d2e183558afe6e52198247888675d7f0b526f5082051a9ae75d5ea3a402ae` とcanonical patch SHA-256 `a9d49bea2225a903fe693f913c1f8652cdea56d02b03355e17f472363ca3b715` を再照合した。最初の再実行はroot所有candidate Git metadataをUID 1100のcoordinatorが拒否して安全側で停止した。local objectを共有しないUID 1100所有standalone cloneを新規作成し、書込み権を除去してから新workflowとして再実行し、`/var/lib/amazon-explorer-ai-review/artifacts/TASK-CANARY-001-live-init-r2/phase-request.json` を生成した。directoryはUID 1100所有0500、fileは0400、file SHA-256は `57266f318584f01dd0fc3cccf08a9e356db67371277e974393d7c8b91f42c706`、request SHA-256は `3fce384684bbd5df6d87ddd52af8b6010f732fc5201ce9421e245fe5db0a1a82` である。UID 1101からは読めず、credential/API/external networkは使っていない。

### 7.2 source診断と単一phase契約を確認する

source-treeからのpreflight確認は `--diagnostic-source` のみであり、attested production実行ではない。

```sh
RELEASE_ROOT="/opt/amazon-explorer-ai-review/releases/$RELEASE_ID"
manifest="$RELEASE_ROOT/runtime/runtime-manifest.json"
diagnostic_manifest_sha=$(sha256sum "$manifest" | awk '{print $1}')

"$APPROVED_PYTHON" -I -S \
  "$RELEASE_ROOT/bin/external_launcher.py" \
  --manifest "$manifest" \
  --expected-manifest-sha256 "$diagnostic_manifest_sha" \
  --candidate-uid "$CANDIDATE_UID" \
  --diagnostic-source \
  -- snapshot --help
```

次の確認: この結果はsource診断に限る。`diagnostic_manifest_sha` は外部承認anchorではなく、productionの `workflow-init`、`--deployment-check`、`--workflow` へ流用しない。

productionの単一phase入口は、outer driverが作った `PhaseRequest` とpayload digestを必要とする。共通のinner引数は次である。

```text
<phase>
--task @task-container
--artifact-root @artifact-root-container
--expected-task-sha256 @task-sha256
--phase-request /artifacts/<request.json>
--expected-phase-request-file-sha256 <raw-file-sha256>
--phase-history /artifacts/<prior-phase-result.json>  # 前phase数だけ反復
--phase-payload /artifacts/<payload.json>
--expected-phase-payload-sha256 <payload-sha256>
--runtime-root /runtime
--runtime-manifest @runtime-manifest-container
--expected-runtime-manifest-sha256 @runtime-manifest-sha256
--expected-coordinator-image-digest @coordinator-image-digest
```

外側は `$APPROVED_PYTHON -I -S external_launcher.py` にmanifest、manifest SHA、candidate UID、coordinator image、artifact root、phase request、request file SHA、空のphase output rootを渡す。workflow内では `snapshot` prepareだけ `--candidate-repo`、`sign` prepareだけ `--signing-key`、`attested-judge` prepareだけprivate nonce ledger rootを専用mountとして渡す。

通常inner phase subcommandは入力を検証してbound `PhaseAction` を出す。outer workflow用の `--workflow-operation prepare|finalize` は `production_cli.py` へ登録済みで、7つすべてのphaseが `coordinator_workflow_ops.prepare_workflow_transition` / `finalize_workflow_transition` を通る。`offline` と `broker` だけがouter executionを使い、他はcoordinator内でcanonical payloadを作って同一bytesをfinalizeする。external launcherのreadiness gateはhandler tupleと7 phase全体の完全一致をcredential読取りより前に検査し、現行release surfaceは7/7である。単一phaseのstdoutを手作業でつなぎ、outerのdigest/mount/ledger契約を迂回しない。

outer entryが要求する引数契約は、manifestと期待SHA、candidate UID、4つのdigest付きimage、initial artifact root内のphase request、新規空0700 output root、protected standalone candidate、signing key、新規broker ledger path、private nonce ledger root、reviewer/adversaryの異なるinherited credential FDである。outerはbroker runtimeのexecutable/security/environmentをpath-free canonical bindingとして事前計測する。credential値をargv、parent environment、artifactへ置かず、private regular fileの継承FDでだけ渡す。

`--timeout-seconds` は任意で既定300秒、coordinator実行で許可する範囲は1〜900秒である。`--expected-phase-request-file-sha256` は単一phase用であり、`--workflow` の必須引数ではない。workflow modeはtrailing harness argumentsと `--diagnostic-source` の併用を拒否する。

### 7.3 credential/APIなしで配備preflightを行う

症状・目的: live brokerを起動する前に、rootless runtime、manifest、4 imageのlocal identityと安全な起動条件だけを確認したい。

最初の操作: 7.1で使ったものと同じ外部承認済みmanifest SHA、現行harness digestを結ぶ具体的TaskSpec v2、manifestに固定した4つの異なるdigest、そのdigestを含む `name@sha256:...` image参照を用意する。credential file、artifact、candidate path、signing key、ledgerは用意しない。

```sh
RELEASE_ROOT="/opt/amazon-explorer-ai-review/releases/$RELEASE_ID"
manifest="$RELEASE_ROOT/runtime/runtime-manifest.json"

"$APPROVED_PYTHON" -I -S \
  "$RELEASE_ROOT/bin/external_launcher.py" \
  --manifest "$manifest" \
  --expected-manifest-sha256 "$APPROVED_MANIFEST_SHA256" \
  --candidate-uid "$CANDIDATE_UID" \
  --deployment-check \
  --coordinator-image "$COORDINATOR_IMAGE" \
  --offline-image "$OFFLINE_IMAGE" \
  --broker-image "$BROKER_IMAGE" \
  --broker-gateway-image "$BROKER_GATEWAY_IMAGE"
```

このmodeはrootless Podman、user namespace、seccomp、passwd HOMEから固定した明示 `HOME` / `XDG_CONFIG_HOME` / `XDG_DATA_HOME` / `XDG_RUNTIME_DIR`、Podman infoのgraph root / run root / active storage config、manifest-pinned digest、local image metadataを検査する。backend probeからimage inspect/smoke/cleanupまで同じcanonical environmentを使い、store/security stable subsetを前後で再計測する。active storage configに `imagestore` / `additionalimagestores` がある場合や、graph optionsが別imagestoreを示す場合は拒否する。

4 role smokeは `--pull=never`、`--network=none`、read-only、全capability drop、`no-new-privileges`、`keep-id` だけを使う。coordinatorはhelp、offline runnerはimage metadataと一致するexact `Python 3.13.7`、brokerはempty stdinの安全なparse失敗、gatewayはDNSより前のargv失敗を確認する。credentialを読まず、external networkを作らず、APIを呼ばない。workflow引数、credential FD、trailing phase引数、`--diagnostic-source` との併用は拒否する。

TaskSpecの責務分担は7.1と同じである。builderがPydanticでfull strict validationを行い、external manifest SHAがtask/harnessを含むmanifestをanchorし、launcher import前はheld task FDに対するv2/harness narrow checkを行う。launcherのnarrow checkだけをTaskSpec全体の承認と解釈しない。

次の確認: canonical stdoutが `status="nonlive_ready"`、`credentials_read=false`、`external_api_called=false`、`external_network_created=false`、`production_e2e_complete=false` で、manifest/backend/image evidence digestを持つことを確認する。これは「credential-freeのlocal非live前提が成立した」という意味だけであり、7-phase E2E、broker egress、API response、課金、request ID、長期nonce運用を証明しない。

2026-08-16の実host検証では、`RELEASE_ID=dd4b6bde2bd2d7f3ebc67c5190949c1cc97652ee`、`APPROVED_PYTHON=/usr/bin/python3.14`、`CANDIDATE_UID=1101`、manifest SHA-256 `703d2e183558afe6e52198247888675d7f0b526f5082051a9ae75d5ea3a402ae` と上記4 image digestを使い、終了0と `nonlive_ready` を確認した。4つのbooleanは期待どおりすべてfalseであり、credential file、workflow artifact、signing key、ledgerを引数へ渡していない。

安全上の注意: 失敗時にimageを暗黙pull/buildしたりDocker/rootfulへfallbackしたりしない。missing/stale image、rootless storeの不一致、root/userns/seccomp不足を修正する操作は、承認者がrelease digestとsystem変更範囲を確認した後に別作業として行う。今回のpublic pull/buildは事前準備として明示的に実行し、deployment check本体は `--pull=never` / `--network=none` で完了した。

### 7.4 人間承認後にfull workflowを実行する

本番の正規command形は次である。**今回のcredential-free配備検証では実行していない。送信内容、credential、費用、nonce運用を人間が別途明示承認した後だけ使う。** 4つのimage変数は `name@sha256:...`、broker ledgerはprivate directory内の存在しないpath、output rootは新規空0700 directory、nonce rootはlauncher所有の0700 directoryで空またはexact contractを満たす0600 `nonces.sqlite3` だけを含み、credential fileは0600のbounded ASCII regular fileでなければならない。

```sh
RELEASE_ROOT="/opt/amazon-explorer-ai-review/releases/$RELEASE_ID"
manifest="$RELEASE_ROOT/runtime/runtime-manifest.json"

test -n "$APPROVED_MANIFEST_SHA256"
test ! -e "$BROKER_LEDGER"
test -d "$INITIAL_ARTIFACT_ROOT"
test -f "$INITIAL_ARTIFACT_ROOT/phase-request.json"
mkdir -m 0700 "$WORKFLOW_OUTPUT_ROOT"
test -z "$(find "$WORKFLOW_OUTPUT_ROOT" -mindepth 1 -maxdepth 1 -print -quit)"
test -d "$ATTESTATION_NONCE_LEDGER_ROOT"
test ! -L "$ATTESTATION_NONCE_LEDGER_ROOT"
test "$(stat -c '%a' "$ATTESTATION_NONCE_LEDGER_ROOT")" = 700
test "$(stat -c '%u:%g' "$ATTESTATION_NONCE_LEDGER_ROOT")" = "$(id -u):$(id -g)"
test -z "$(find "$ATTESTATION_NONCE_LEDGER_ROOT" -mindepth 1 -maxdepth 1 \
  ! -name nonces.sqlite3 -print -quit)"
if test -e "$ATTESTATION_NONCE_LEDGER_ROOT/nonces.sqlite3"; then
  test -f "$ATTESTATION_NONCE_LEDGER_ROOT/nonces.sqlite3"
  test ! -L "$ATTESTATION_NONCE_LEDGER_ROOT/nonces.sqlite3"
  test "$(stat -c '%a' "$ATTESTATION_NONCE_LEDGER_ROOT/nonces.sqlite3")" = 600
  test "$(stat -c '%h' "$ATTESTATION_NONCE_LEDGER_ROOT/nonces.sqlite3")" = 1
  test "$(stat -c '%u:%g' "$ATTESTATION_NONCE_LEDGER_ROOT/nonces.sqlite3")" = \
    "$(id -u):$(id -g)"
fi

exec 7<"$REVIEWER_CREDENTIAL_FILE"
exec 8<"$ADVERSARY_CREDENTIAL_FILE"
workflow_status=0
"$APPROVED_PYTHON" -I -S \
  "$RELEASE_ROOT/bin/external_launcher.py" \
  --manifest "$manifest" \
  --expected-manifest-sha256 "$APPROVED_MANIFEST_SHA256" \
  --candidate-uid "$CANDIDATE_UID" \
  --workflow \
  --coordinator-image "$COORDINATOR_IMAGE" \
  --offline-image "$OFFLINE_IMAGE" \
  --broker-image "$BROKER_IMAGE" \
  --broker-gateway-image "$BROKER_GATEWAY_IMAGE" \
  --artifact-root "$INITIAL_ARTIFACT_ROOT" \
  --phase-request "$INITIAL_ARTIFACT_ROOT/phase-request.json" \
  --phase-output-root "$WORKFLOW_OUTPUT_ROOT" \
  --candidate-repo "$PROTECTED_CANDIDATE_REPO" \
  --signing-key "$SIGNING_KEY" \
  --broker-ledger "$BROKER_LEDGER" \
  --attestation-nonce-ledger-root "$ATTESTATION_NONCE_LEDGER_ROOT" \
  --reviewer-credential-fd 7 \
  --adversary-credential-fd 8 || workflow_status=$?
exec 7<&-
exec 8<&-
test "$workflow_status" -eq 0
```

成功時stdoutは `status="complete"`、`phase_count=7`、`final_phase_sha256`、`human_approval_required=true` のcanonical JSONである。終了2、途中directory、空でない新規ledger、7未満のphase、署名済み `pass` のどれも自動再開・再試行・commit・push・mergeの根拠にしない。新しいworkflow ID、output root、broker ledgerで最初から作り直す。

実装済みのstable library境界は次である。

- offline coordinator: `prepare_offline_phase_action` / `finalize_offline_phase_output`
- offline outer: `execute_prepared_offline_outer`
- broker coordinator: `prepare_broker_phase_action` / `finalize_broker_phase_output`
- broker outer: `measure_broker_outer_runtime` / `prepare_broker_outer_ledger` / `execute_prepared_broker_outer`
- broker raw contract: `prepare_provisioned_broker_execution` / `canonical_prepared_broker_batch_bytes` / `finalize_provisioned_broker_execution`
- workflow coordinator: `prepare_workflow_transition` / `finalize_workflow_transition`（7 phaseすべて）
- sign/judge common input: `reconstruct_attestation_inputs`（live broker DB不要のimmutable common bundle）
- frozen attestation: `build_frozen_bundle_expectations` / `judge_frozen_attestation_bundle`
- fixed state machine: `outer_workflow_state.run_fixed_workflow`

brokerの `external-evidence.json` はreviewer/adversary両方のprovisioned lifecycleと、失敗attemptを含むcanonical frozen final ledgerを持つ。coordinator finalizeはhost SQLiteを削除した後でも `prepared-payload.json` とこのraw evidenceからtyped evidenceを再構築し、ledger改ざんを拒否できる。

broker SQLiteはroot-owned stdlib outerが `prepare_broker_outer_ledger` でO_EXCL・0600・STRICT schemaとして新規作成し、そのidentity SHAをcoordinator prepareへ渡す。既存ledgerを再利用しない。

workflowの `sign` はimmutable evidenceからrole別expectationを再構築してEd25519署名する。`attested-judge` も同じimmutable evidenceからexpectationを独立に再構築し、committed sign artifacts、pinned public key、nonce ledgerからverdictを作る。旧live-ledger引数を受けるlibrary互換経路は残るが、production 7-phaseの権威入力ではない。

nonce DBは `application_id=1095062094`、`user_version=1`、`journal_mode=DELETE`、次のexact schema、index/table metadata、integrity、row domainまで検査する。

```sql
CREATE TABLE used_nonces (
  nonce TEXT NOT NULL PRIMARY KEY
    CHECK(typeof(nonce) = 'text'
      AND length(nonce) BETWEEN 32 AND 128
      AND nonce NOT GLOB '*[^0-9a-f]*'),
  reserved_at INTEGER NOT NULL
    CHECK(typeof(reserved_at) = 'integer' AND reserved_at >= 0)
) WITHOUT ROWID
```

fileは0600 regular・single-link・launcher/coordinator所有・identity不変、directoryは0700で `nonces.sqlite3` 以外とSQLite sidecarを拒否する。署名set全体を検証した後、`BEGIN IMMEDIATE` 内でnonceを一括INSERTするため、既使用nonceが1つでもあれば全体をrollbackしてreplayを原子的に拒否する。

`outer_descriptor_executor.py` はbounded subprocessを検証するtest primitiveであり、2役のprovisioned egress lifecycleを満たさない。production brokerの正規経路へ接続しない。`run_fixed_workflow` 単体はclosed state machine libraryである。root-owned launcherと永続phase driverは `--workflow` へ配線済みで、7/7 readiness gateも通る。ただし、配備実績とlive API実績は別に記録する。

## 8. brokerを有効にする条件

brokerは次がすべて成立しない限り起動しない。

1. 人間が送信packet、model、最大費用、最大attempt、保存方針を承認した。
2. `allow_external_ai` と `allow_isolated_broker` の両方がtrueである。
3. credentialはbroker processへだけ環境変数で注入し、argv、stdin、artifact、gatewayへ入れない。
4. broker/gateway image、egress policy、pricing policyのdigestがmanifestと一致する。
5. role・attempt専用internal networkとgateway専用external networkを新規作成した。
6. raw runtime inspectが、brokerにexternal networkがないこと、gatewayにcredentialがないこと、mountがないこと、固定 `api.openai.com:443` だけであることを示す。
7. reviewerとadversaryを別fresh session、別container、別network lifecycleで実行する。
8. 実行後の再inspect、gateway/network cleanup、absence確認を完了する。
9. 失敗attemptを含むSQLite reservation ledgerがtoken・費用上限内である。
10. frozen common bundleからsign/judgeが同じexpectationを再構築し、nonceを原子的に予約できるtrusted releaseである。

brokerはrequestをResponses APIへ送る実通信点である。通常テスト、release build、preflight診断でcredentialを設定しない。

## 9. GPT-5.6 Solとtoken・費用

GPT-5.6 Sol自体のcontext windowは1,050,000 tokens、最大outputは128,000 tokensである。一方、このリポジトリは272K入力超の料金境界を避けるため、1 callを意図的に小さく制限する。[GPT-5.6 Sol](https://developers.openai.com/api/docs/models/gpt-5.6-sol)

| 項目 | 固定値 |
|---|---:|
| model | `gpt-5.6-sol` |
| service tier | `default` |
| 1 callの総予約 | 272,000 tokens |
| 最大input | 260,000 tokens |
| 最大output | 12,000 tokens |
| input警告 | 250,000 tokens |
| role | reviewer=`high`、adversary=`xhigh` |
| roleごとの最大attempt | 2 |
| 標準packet token cap | 544,000 |
| 絶対packet token cap | 1,088,000 |
| 標準packet cost cap | 4,540,000 microUSD = 4.54 USD |
| 絶対packet cost cap | 7,940,000 microUSD = 7.94 USD |

標準544Kはreviewerとadversaryを各1回、最大input/outputで予約できる値である。絶対1,088Kは両role各2回の上限であり、通常設定ではない。失敗、timeout、無効responseでも、起動前に予約したattemptはledgerから戻さない。

input予約はprompt本文だけでなく、strict output schemaとrequest envelopeを含むcanonical Responses request JSON全体のUTF-8 byte数をtoken数の保守的上界として数える。provider usageのinputがこの予約を超える、またはoutputが12,000を超える応答は拒否する。

推論量はimplementer=`medium`、reviewer=`high`、adversary=`xhigh`を標準とする。`medium` は実装のbalanced starting point、`high` は通常レビューの検証深度、`xhigh` は敵対的な境界探索に使う。`max` は代表evalで品質向上が測定でき、遅延とtoken増を受容する最難関・quality-firstタスクだけに限定する。[GPT-5.6 model guidance](https://developers.openai.com/api/docs/guides/latest-model)

tokenを減らす順序:

1. deterministic gateで失敗したらAIを呼ばない。
2. 全repositoryや会話履歴でなく、同じ署名済みbounded packetを使う。
3. diff、変更file、直接依存、gate/TDD要約だけを含める。
4. reviewer/adversaryへ互いの出力を渡さずfresh requestにする。
5. structured output、`verbosity=low`、toolsなし、`store=false`に固定する。
6. 250K警告でtaskを機能単位へ分割する。
7. effort昇格とretryはevalで利益を確認した場合だけ行う。

モデルの大きなcontext windowは「全量を送ってよい」という意味ではない。送信最小化、credential除外、費用予測を優先する。

## 10. 終了コードと停止条件

| 入口 | 0 | 1 | 2 |
|---|---|---|---|
| `runtime_release` | asset生成成功 | 予期しない内部例外 | 入力、policy、上限、出力安全性、CLI使用法エラー |
| `build_zipapp` | archive生成成功 | build中の未処理例外 | CLI使用法エラー |
| external launcher / production phase | preflight・phase処理成功 | 予期しない内部例外 | trust、runtime、binding、isolation、CLI使用法エラー |
| external launcher `--deployment-check` | `nonlive_ready` evidence生成 | 使用しない | manifest/backend/image/smoke/CLIのfail-closed停止 |
| external launcher `--workflow` | 7phase完了 | 使用しない | readiness、引数、preflight、backend/isolation、protocol、outer executionを含むfail-closed停止 |
| legacy `policy` | policy通過 | policy違反 | 入力、runtime、Git検査エラー |
| legacy `judge` | `pass` | `human_review` またはfail | 入力、runtime、証拠検証エラー |

`run_fixed_workflow` はlibrary APIでありprocess exit codeを返さない。検証失敗では `OuterWorkflowStateError` を送出する。`--workflow` entryは内部失敗も `LauncherTrustError` へ包み終了2にする。入口で予期しない終了1、traceback、signal終了を見た場合も成功扱いせず停止する。

`pass` でも `human_approval_required=true` である。commit、push、merge、外部通信、credential利用、課金を自動承認しない。

次のいずれかで即停止する。

- rootless Podman、user namespace、seccomp、別UIDのどれかが成立しない
- runtime、task、schema、policy、image、Python、phase chainのdigestが一致しない
- candidate、private key、artifact、container runtimeを不正なphaseへmountしようとした
- 検証済みsnapshotを一般artifact treeへ混在させ、AGENTS/credential拒否policyを迂回しようとした
- `.env*`、`.cache` / `cache`、generic credentials/secrets、provider credential path、Git metadataがsnapshot/packetへ入る、またはphysical snapshot内のAGENTSを一般artifact/packetへcopyしてtrusted instructionとして扱う
- reviewer/adversaryの片方がない、session/lifecycleが重複する
- gatewayの固定宛先、credential不在、cleanup/absenceを証明できない
- raw offline、provisioned broker、ledger、署名、nonceの再構築に失敗する
- frozen broker evidenceから再構築したexpectationがsign/judgeで一致しない
- token、費用、attempt、時間、byte、process上限へ達する
- 対象外、削除範囲、送信内容、費用の解釈が変わる
- 人間の外部送信・credential・費用承認がない

停止時は同じworkflowを再開せず、最後に成功したphase、失敗理由、未送信・未課金かどうかを記録し、新しいworkflowでやり直す。

## 11. 現在の検証境界

2026-08-16の最終確認では、secret-free full suiteが726 passed / 1 deselected、Ruff check/formatが117 files、lock、diff、strict Git fsckが終了0である。credential-free `workflow-init` と実host `--deployment-check` も成功した。この件数とSHAはその時点の実績であり、将来の固定成功条件ではない。

一方、unit/adversarial testと `nonlive_ready` は次を証明しない。

- この未コミットbootstrap変更自身がtrusted releaseからattest済みであること
- rootless Podman `keep-id` host上でroot-owned releaseを使い7-phase E2Eが成功すること
- 生成済みlive用initial requestを使うfull 7-phase E2Eが成功すること
- 実配備時のnonce ledger長期保持・backup・容量運用が適切であること
- GitHub Actions上の配備結果
- Python 3.10でのlocal実行（現ホストにinterpreterがない）
- 外部OpenAI APIのcredential、課金、provider request IDを伴うlive成功
- Bonsai、Outscraper、Amazonの結合動作

実host検証は、承認済みclean commit、TaskSpec v2 canary、root-owned release、専用user、rootless Podman、4 image、external manifest anchorがcredential-free preflightを通ることまでを証明する。package/user/system変更、public base image pull、image内package取得と4 image buildは実施したが、credential利用、OpenAI API、broker external network、full 7-phase workflow、課金は実施していない。

関連資料: [AI運用規約](AI_GUIDE.md)、[セキュリティ](SECURITY.md)、[Execution Plan](plans/EXEC-002-ATTESTED-AI-REVIEW-BOUNDARIES.md)、[参考資料](REFERENCES.md)
