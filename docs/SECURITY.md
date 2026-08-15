# セキュリティ

## 1. 対象範囲

この文書は、現行のローカル実行向け amazon-explorer に実装されている保護と、運用上必要な制約を整理する。アプリの実装根拠は `src/config.py`、`src/clients/`、`src/repositories/cache_repository.py`、`src/ui/streamlit_ui.py`、AIレビュー用の境界は `tools/ai_review/` と `tests/conftest.py` を正とする。

現行アプリケーションには、アプリ独自の認証、認可、利用者別永続領域、レート制限、監査ログはない。インターネットへ公開する前提の多利用者向けサービスではない。

## 2. 信頼境界とデータフロー

```text
利用者入力
  -> ローカルBonsai OpenAI互換API
  -> 抽出した商品属性
  -> Outscraper API
  -> Amazon商品候補
  -> ローカルJSONキャッシュ
  -> Streamlit / CLI
```

守る対象は次である。

- `OUTSCRAPER_API_KEY`
- 利用者が入力した検索条件
- Bonsaiが抽出した属性
- Outscraperの生レスポンスと商品URL・画像URL
- 一致、不足、除外条件を含む採点結果
- 内部パス、スタックトレース、外部サービスの診断情報

商品検索条件と結果はローカルキャッシュへ平文で保存される。キャッシュキーはSHA-256由来だが、暗号化や匿名化ではない。

## 3. シークレット管理

`src/config.py` のPydantic Settingsは、OS環境変数とプロジェクトルートの `.env` から設定を読む。Outscraper APIキーは `X-API-KEY` ヘッダーで送る。

現在確認できる保護:

- `.env` と `.streamlit/secrets.toml` は `.gitignore` 対象である
- `.env.example` は変数名だけを示し、実値を含めない
- APIキーをクエリURL、キャッシュキー、JSON payloadへ含めない
- Streamlitのサイドバーはキーの有無だけを表示し、値を表示しない
- APIキーが空ならOutscraperへのHTTP要求前に停止する

運用規則:

```sh
test -e .env || cp .env.example .env
chmod 600 .env
git check-ignore -v .env
```

- 実値をGit、Issue、Plan、WORKLOG、画面キャプチャ、シェル履歴へ記録しない
- 本番ではリポジトリ内ファイルより、実行環境のシークレット管理機構を使う
- 漏えいが疑われる場合はキーを失効・再発行し、履歴、ログ、キャッシュ、外部サービスの利用記録を確認する
- `.env` の権限はコードで強制されないため、配置時にOS権限を確認する

## 4. OutscraperへのAPIキー送信

### 4.1 endpoint

タスク作成前に `OUTSCRAPER_ENDPOINT` を次の条件で検証する。

- HTTPSである
- ホストが存在する
- URL内にusernameまたはpasswordを含まない

APIキー付き要求は `allow_redirects=False` で送り、HTTP 3xxを `OutscraperSecurityError` として拒否する。リダイレクト先へAPIキーを転送しない。

### 4.2 `results_location`

非同期タスクが返す `results_location` は外部入力として扱う。結果取得前に次を検証する。

- 文字列である
- HTTPSである
- ホストが存在する
- URL内認証情報がない
- 設定endpointとホストおよび実効ポートが一致する

末尾のドットとホスト名の大文字小文字を正規化し、既定HTTPSポートは443として比較する。条件を満たさないURLにはHTTP要求を行わない。結果取得もリダイレクトを拒否する。

この検証は同一オリジンへのキー送信を守るものであり、設定者自身が悪意あるendpointを設定することまでは防がない。`OUTSCRAPER_ENDPOINT` を変更できる権限を制限する。

## 5. 再試行、待機、失敗分類

Outscraperで自動再試行するのは次だけである。

- `requests.Timeout`
- `requests.ConnectionError`
- HTTP 429
- HTTP 5xx

既定は最大3試行、基準1秒の指数バックオフである。その他の4xxは再試行しない。各HTTP要求の既定タイムアウトは30秒である。

非同期タスクは処理中、成功、失敗、不明へ分類する。`data=[]` は情報欠落や失敗ではなく正常な0件として扱う。既定のポーリング間隔は30秒、最大50回であり、上限後は `OutscraperTaskTimeoutError` とする。

再試行には現時点でジッターと `Retry-After` 対応がない。回数や取得件数を増やすと、課金、負荷、最大待ち時間が増えるため、設定変更時に確認する。

Bonsaiの属性抽出POSTには既定60秒のタイムアウトがあるが、自動再試行はない。

## 6. レスポンス検証と例外

- BonsaiはJSON object、`choices`、`message`、非空の `content` を順に検証する
- Bonsaiの生応答を属性へ変換できない場合、固定文言のエラーにして生応答を例外メッセージへ含めない
- OutscraperはJSON objectを要求し、完了応答の `data` がリストであることを検証する
- Outscraperの通信、応答、危険なURL、タスク失敗、待機超過を別の例外型で区別する
- 外部データは正規化後にPydanticモデルへ変換し、後段の採点と表示へ渡す

Outscraperのタスク失敗例外は、外部レスポンスの `description` または `message` を例外文へ含め、レスポンス辞書を例外属性へ保持する。これらは信頼できない外部データであり、ログ転送や利用者表示へ使う場合はマスキングと改行等の正規化が必要である。

## 7. ログと画面への情報開示

現行の標準出力には次が出る。

- パイプラインの段階
- Outscraperのrequest ID
- ポーリング回数とstatus
- 保存または再利用したキャッシュのローカルパス
- CLIで表示する商品名、価格、商品URL

検索語、Outscraperの要求URL、`results_location`、APIキーは現行の標準出力へ直接出していない。

Streamlitは検索中の例外を `LOGGER.exception()` でサーバーログへ記録し、利用者には「検索に失敗しました。設定と外部サービスの状態を確認してください。」という固定メッセージを表示する。スタックトレースや内部例外を画面へ返さない。サイドバーにはBonsai base URL、Amazonドメイン、言語、取得件数が表示される。

サーバーログには外部例外の詳細やローカルパスが残る可能性がある。ログを外部へ転送する前に、保存先、アクセス権、保持期間、マスキング対象を決める。`SHOW_DEBUG_INFO=true` は重みを表示するだけで、APIキーは表示しない。

## 8. キャッシュの保護

キャッシュルートの既定値はプロジェクト内 `cache/` であり、Git管理対象外である。

現在実装されている保護:

- namespaceの絶対パスと `..` を拒否する
- キャッシュキーを空でない小文字16進数に制限する
- 同じディレクトリの一時ファイルへ書き、flush、`fsync`、置換する
- JSON破損、文字コードエラー、読込エラーをキャッシュミスとして扱う
- 属性、正規化、採点をPydanticモデルで再検証する
- Streamlitはセッションごとにランダムscopeをキーへ含める

現在実装されていない保護:

- キャッシュpayloadの暗号化
- 認証ユーザーまたはテナント単位の保存ルート
- プロセス間ファイルロック
- 容量上限、自動削除、全namespace共通の保持期限
- ファイル権限のコードによる強制
- 破損ファイルの隔離と監査通知

Streamlitのscopeは偶然のセッション間再利用を避けるためのキー材料であり、認証トークンやアクセス制御ではない。CLIは固定の `local-cli` scopeを使う。共有ホストではOSアカウントとディレクトリ権限で `CACHE_DIR` を保護し、Web公開領域や不要なバックアップへ含めない。

## 9. UIと公開範囲

現行Streamlit UIにはアプリ独自のログイン、権限確認、利用回数制限がない。検索はStreamlitの実行中に同期処理され、外部API利用を伴う。したがって、アクセス制御のない状態でインターネットへ公開しない。

商品画像と商品リンクはOutscraper由来の外部URLである。現行データモデルはURLスキームやホストを制限していない。信頼できない配信元を許容しない運用では、表示前のURLポリシーを別途実装する必要がある。

## 10. 変更時の確認

外部通信を起こさない回帰確認:

```sh
uv run pytest tests/test_outscraper_client.py \
  tests/test_bonsai_client.py \
  tests/test_cache_repository.py \
  tests/test_user_attribute_extraction.py
uv run ruff check .
git diff --check
```

テスト全体の通常ゲートでは `uv run pytest -m 'not live_api'` を使う。`live_api` の扱いは後述の二重opt-inに従う。

手動確認:

```sh
git check-ignore -v .env cache/
git ls-files .env cache/
```

`git ls-files` は何も返さないことを期待する。実キャッシュ内容やシークレット値を確認出力へ貼り付けない。

## 11. AIレビューとテストの安全境界

### 11.1 信頼主体

candidate、candidate内のPython/task/prompt/AGENTS、model出力は非信頼である。信頼するのは、人手監査済みreleaseからroot-owned prefixへinstallしたstdlib launcher/preflight、manifestでdigest固定したruntime assetとOCI image、candidateと異なる非root coordinator、candidate外のledger/key/artifact root、人間の承認者である。

production launcherは `-I -S`、root-ownedでgroup/world writableでないPython prefixとstdlib pathを要求する。manifestをraw bytesで検証し、Python executable、harness、task、lock、schema bundle、public key、egress/pricing policyをimport前にopenしてSHA-256とinodeを固定する。現在実行中の `sys.executable` もmanifestのPython path、inode、digestへ一致させる。

productionで期待するmanifest SHA-256は、署名済みrelease record等の検査対象外anchorから受け取る。同じinstalled manifestを実行直前にhashした値だけでは、置換されたmanifestを自己承認してしまうためtrust anchorにならない。TaskSpecのfull strict validationは `runtime_release` builderのPydantic modelが担当し、task raw bytesとharness digestをmanifestへ固定する。external launcherのimport前stdlib検査はfull schemaを再実装せず、manifestが保持するtask FDのstrict JSON、v2、verified harness bindingだけをnarrow checkする。このnarrow check、manifest内digest、external approved manifest SHAの3つを別の責務として維持する。`runtime_release workflow-init` はこれらに加え、manifestに固定したpublic key、protected clean candidate、人手承認済みpatch SHAを再検証して最初のrequestを作る。credentialとnetworkは使わず、outputをexclusive作成後に0500/0400へ凍結する。

coordinator production runtimeは非rootのrootless Podman、user namespace、`keep-id`、有効なseccompを必須とする。Docker、rootful Podman、user namespaceなし、`unconfined` seccompへfallbackしない。Podman subprocessはpasswd HOMEから導出した明示 `HOME` / `XDG_CONFIG_HOME` / `XDG_DATA_HOME` / `XDG_RUNTIME_DIR` を共用する。HOME/XDG pathの全祖先はrootまたはlauncher user所有、group/world非writable、symlink/POSIX ACLなし、private leafはlauncher user所有であり、candidateは別UIDで所有・書込みのどちらもできないことを要求する。

launcher `--deployment-check` はcredential、workflow artifact、key、ledgerを受け取らず、installed TaskSpec v2とverified harnessのbinding、local 4 imageを `--pull=never` / `--network=none` で検査する。Podman infoのgraph root、run root、active storage config、seccompを含むstable subsetをimage検査の前後で同じcanonical environmentへ結び、変更時は停止する。active `storage.conf` の `imagestore` / `additionalimagestores` とgraph optionsの別imagestore指定も拒否する。成功status `nonlive_ready` はcredential-free preflightだけを示し、production E2Eやlive APIを示さない。

2026-08-16の承認済み配備では、`ai-review`（UID 1100）と `amazon-candidate`（UID 1101）を分離し、ai-review専用subuid/subgid、rootless Podman 6.1、user namespace、seccomp、passwd由来のprivate HOME/XDGを確認した。root-owned releaseは `/opt/amazon-explorer-ai-review/releases/dd4b6bde2bd2d7f3ebc67c5190949c1cc97652ee`、private stateは `/var/lib/amazon-explorer-ai-review` に分離した。manifest SHA-256 `703d2e183558afe6e52198247888675d7f0b526f5082051a9ae75d5ea3a402ae`、TaskSpec SHA-256 `8507bc001dcf4d383ce43cb335e65851da740c10d6e3c4dd752c1f762b1b32fd`、harness SHA-256 `0d27b9c541b01b1fb6f02c270286965c1507748abe5f5667ac5a9e7250426278` と4つの異なるimage digestを固定し、`--deployment-check` が `nonlive_ready` で成功した。

準備時には承認範囲内でpackage導入、public base image pull、image内package取得、4 image buildを行った。deployment check本体は `--pull=never` / `--network=none` であり、credential、OpenAI API、broker external network、live workflow、課金を使用していない。したがって、この成功を外部送信またはproduction E2Eの証拠として扱わない。

`/var/lib/amazon-explorer-ai-review/build/workflow-init-r2/initial` のroot所有build証拠はlive入力へ流用しない。external manifest/patch anchorを再照合し、local objectを共有しないUID 1100所有standalone candidateから `/var/lib/amazon-explorer-ai-review/artifacts/TASK-CANARY-001-live-init-r2/phase-request.json` を新規生成した。directoryは0500、fileは0400でUID 1100だけが読め、UID 1101は読めない。initializerはcredential、API、external networkを使っていない。

### 11.2 candidate、path、snapshot

candidateはlocal Git objectを共有しないstandalone canonical single-commit cloneに限定する。Git object、tree、commit、metadata、path、mode、owner、mount、hardlink/symlink、allowed/denied path、byte/line/file上限を検査し、content-addressed read-only snapshotへ固定する。

共通 `sensitive_paths` policyは任意階層の `.env*`、`.envrc`、`.streamlit/secrets.toml`、`cache` / `.cache`、`.git`、SSH/cloud/container/package-manager/provider credential directory、generic `credentials` / `credentials.toml` / `secrets.toml` 等をpathで拒否する。protected blobは原則として内容を読まない。

例外はrepository rootのtracked `.env.example` だけである。64KiB以下のUTF-8、NULなし、credential-like contentなし、assignment valueがすべて空であることを検証し、安全なtemplateだけをsnapshot実行treeから除外する。値入り、shell文、nested `.env.example`、変更対象としての `.env.example` は拒否する。

candidate mountは `snapshot` phaseだけに限定する。snapshot後のRED、offline、packet、broker、sign、judgeはcandidate repository pathを受け取らない。

verified physical snapshotは一般 `/artifacts` へcopyせず、host `snapshot-artifacts/{snapshots,red-snapshots}/<sha>/tree` からcoordinator専用read-only `/snapshots` mountへ渡す。PhaseResultのsemantic SHA集合とphysical directory集合をexact照合する。snapshot内の `AGENTS.md` を理由に一般artifact側のAGENTS/credential拒否policyを弱めない。

### 11.3 offline runner

RED/GREEN/gateはpinned runner imageで、read-only rootfsとsnapshot、`--network=none`、capability drop、`no_new_privileges`、非root user、限定tmpfs、PID/CPU/memory/time/output上限を使って実行する。home、Docker/Podman socket、agent、credential、host cacheをmountしない。

judgeはraw stdout/stderr digest、argv、exit、runtime probe、snapshot、時間を含む `OfflineRunEvidence` からGate/TDD evidenceを再構築する。candidateや人が作った要約値だけを信用しない。

通常pytestのcollection-time network guardと `live_api` marker + `--run-live-api` の二重opt-inは開発checkoutの補助防御として残す。これはsubprocess/native codeを止めるOS境界でも、外部送信・credential・課金の人間承認でもない。

### 11.4 review packetとbroker egress

review packetはtrusted diffと限定contextだけを含むtext-only canonical JSONである。credential path、secret-like assignment、provider token/private key/JWT、credential付きURI、NUL/binary、上限超過を拒否する。Responses inputの予約はprompt本文だけでなく、schemaとenvelopeを含むcanonical request JSON全体のUTF-8 byte数をtoken数の保守的上界として使い、260K hard limitと250K warningを適用する。

brokerはcandidate filesystem、mount、tool、shell、会話履歴を持たず、credentialはbroker processだけへ環境変数で注入する。gatewayはcredentialを持たず、固定 `api.openai.com:443` だけへTLS relayする。brokerは専用internal networkだけ、gatewayはそのinternal networkと専用external networkだけへ接続する。

role/attemptごとに一意なnetworkとgatewayを作り、raw runtime inspectからimage、network、mount、environment、credential不在、固定egress policyを検証する。実行後の再inspect、cleanup、container/networkのabsence確認までを1つの `ProvisionedBrokerExecutionEvidence` へ結ぶ。attested judgeはreviewerとadversaryのdistinct lifecycleを各1件要求する。

broker phaseはcanonical prepared batchだけをroot-owned outer executorへ渡し、raw outer evidenceをcoordinatorで再finalizeする。raw evidenceには両roleのprovisioned lifecycleと、失敗attemptを含むcanonical frozen final ledgerを入れる。host SQLiteのpath/device/inodeを単純copyやbind mountで後段証拠にせず、`prepared-payload.json` と `external-evidence.json` を `PhaseResult.external_execution_sha256` / `phase_sha256` へ結び付ける。同じallowlist/pricing policy bytesを使えばhost DB削除後もtyped evidence 2件を再構築でき、ledger改ざんは拒否される。

`reconstruct_attestation_inputs` はこのprepared/raw pair、immutable phase chain、dedicated snapshot、raw offline evidenceから、host SQLiteを削除した後もsign/judge共通のfrozen bundleを再構築する。`build_frozen_bundle_expectations` と `judge_frozen_attestation_bundle` はcanonical prepared/raw pairとpinned policy bytesからbroker evidenceを再finalizeするため、host ledgerやruntime再probeを権威入力にしない。sign/judgeは同じimmutable evidenceからrole別expectationを独立再構築する。raw SQLiteのcopy/bind mountは後段証拠として禁止する。

redirect、proxy、custom CA、credentialのargv/stdin/artifact混入、gatewayへのcredential、brokerのexternal network、host Codex直接実行は禁止する。

### 11.5 token・費用・attempt

requestはmodel=`gpt-5.6-sol`、`service_tier=default`、toolsなし、`store=false`、reviewer=`high`、adversary=`xhigh`、output最大12Kへ固定する。返却usageが予約inputを超える、またはoutputが12Kを超える場合は拒否する。

broker attemptは外部process起動前にcandidate外SQLite ledgerへtokenと費用を予約する。root-owned stdlib outerがO_EXCL・0600・STRICT schemaで新規作成し、既存ledgerを再利用しない。失敗、timeout、invalid responseでも予約を戻さない。roleごと最大2 attempt、標準packet 544K / 4.54 USD、絶対上限1,088K / 7.94 USDである。価格はcanonical pricing policy bytesとmanifest digestへ固定し、変更時は公式料金と新しいreleaseを人間が承認する。

### 11.6 署名、judge、人間承認

Ed25519 private keyはcandidate外の0400 fileとし、`sign` workflow prepareだけへread-only mountする。attested-judge workflow prepareだけがlauncher/coordinator所有の0700 nonce ledger rootをread-write `/nonce-ledger` mountとして受け取り、空またはexact contractに一致する0600 `nonces.sqlite3` だけを許す。task、policy、raw offline由来gate/TDD、reviewをruntime、snapshot、request、runner、argv、log、nonce、時刻へ結び付けて署名する。

nonce DBは `application_id=1095062094`、`user_version=1`、`journal_mode=DELETE`、`WITHOUT ROWID` の `used_nonces` tableとexact schema/index/table metadata、integrity、row domainを検査する。fileは0600 regular・link count 1・正しいowner・device/inode不変、directoryは0700でDB以外とWAL/journal/shmを拒否する。全署名のbinding・時刻・nonceを先に検証し、全nonceを単一 `BEGIN IMMEDIATE` transactionで予約する。重複、既使用、部分衝突は全件rollbackし、process再起動後もreplayを拒否する。

attested judgeは、raw offline evidence、reviewer/adversary各1件のdistinct provisioned broker lifecycle、失敗attemptを含むfrozen final ledger、全署名を再構築する。欠落、改ざん、別task/head/snapshot/runtime、重複session/lifecycle、期限切れ、replayはfail closedにする。host broker ledger削除後の `pass`、frozen evidence改ざん拒否、replay拒否は回帰テスト済みである。

phase順序はstdlib固定state machineでも再検証し、external launcherのouter `--workflow` entryとinner `prepare|finalize` CLIまで接続している。7/7 phaseがactual typed handlerを持ち、readiness gateは完全なhandler tupleをcredential FD読取り・broker ledger作成より前に確認する。generic `outer_descriptor_executor.py` はtest primitiveであり、provisioned broker production経路として認めない。outer entry、単一phase、library callbackを手作業でつないでlive運用を開始しない。

独立security reviewは7-phase重点回帰とnonce再監査を完了し、未修正CRITICAL/HIGHは0である。後続の実host検証でrootless Podman、trusted release、TaskSpec v2 canary、4 imageのcredential-free `nonlive_ready`、UID 1100所有のlive用initial requestまでは確認したが、Python 3.10 CI、live 7-phase workflow、API送信、課金実績を証明しない。

完全なprovenanceとcleanな通常判定では `pass` を返し得るが、全verdictは `human_approval_required=true` である。AIがcommit、push、merge、外部送信、credential利用、課金を自動承認しない。詳細は [AI_GUIDE.md](AI_GUIDE.md) と [HARNESS-RUNBOOK.md](HARNESS-RUNBOOK.md) を参照する。

## 12. 本番公開前の残作業

次は現行機能ではなく、実装と検証が必要な事項である。

- 認証、認可、利用者別・テナント別データ分離
- API利用量の上限、レート制限、課金監視
- 検索ジョブの非同期化、キャンセル、期限切れ
- 構造化ログ、相関ID、監査ログ、メトリクス、アラート
- シークレットとキャッシュの保持・削除方針
- 外部商品URL・画像URLの検証方針
- 複数ワーカーで安全な保存方式
- AIハーネスのnonce ledger保持・backup・容量・rotation、古いattestationの検証方針、live 7-phase workflowに対するcredential・費用・送信内容の運用承認

これらの大規模対応は [TASKS.md](TASKS.md)、現行構造に残る負債は [TECH-DEBT-TRACKER.md](TECH-DEBT-TRACKER.md) で管理する。
