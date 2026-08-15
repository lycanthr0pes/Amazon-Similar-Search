# EXEC-001: AI相互レビューとTDDハーネスの導入

> **履歴資料:** このPlanは2026-08-15のTASK-006 bootstrap時点を記録する。本文の「未実装」「禁止」「保留」は当時の状態であり、現行要件ではない。現在のattested境界と残作業は [EXEC-002](EXEC-002-ATTESTED-AI-REVIEW-BOUNDARIES.md)、実行可否と手順は [HARNESS-RUNBOOK.md](../HARNESS-RUNBOOK.md) を正とする。

## メタデータ

- タスクID: `TASK-006`
- 状態: 完了（TASK-006時点の履歴。attested境界は当時未完・保留）
- 作成日: 2026-08-15
- 最終更新日: 2026-08-16（history-only notice追加）
- 基準commit: `2fd9c5b1c12efbcf14172d62ad23341291292a3a`
- 関連規約: [PLANS.md](../PLANS.md)、[AI_GUIDE.md](../AI_GUIDE.md)
- 関連負債: [TD-009](../TECH-DEBT-TRACKER.md#td-009-ai変更の役割分離と証拠契約)
- 解決対象: [ISS-001](../ISSUES.md#iss-001-デバッグ表示に2つの条件語重みがない)、`TODO-002`、`TODO-003`、`TODO-004`

## 目的

以下の目的と境界はTASK-006実施時点のものである。

AIを利用する変更で実装者の自己評価だけに依存せず、次を再現可能な証拠へ結び付ける安全側MVPを導入する。

1. 変更前にraw task、要求、許可範囲を固定する。
2. REDからGREENまでを同じcandidateとテスト内容へ固定する。
3. 安価で決定論的なゲートをAIの意味レビューより先に通す。
4. reviewerとadversaryを分け、同じcommit差分をstructured JSONで評価する。
5. provenanceがattestされない間は自動 `pass` を禁止し、人間承認へ戻す。

このPlanの「安全側MVP完了」は、fail-closedな契約、policy、judge、dry-run、オフラインテストを整えたことを指す。外部AIを安全に起動できるという意味ではない。2026-08-15の完了時点では、import前の外部trust anchor、別UID所有のread-only snapshot/clone、コンテナによるOS read/network隔離、coordinator attestationは未実装であり、attested自動実行を保留した。

## 対象範囲

- `tools/ai_review/` のPydantic契約、パス安全性、差分policy、決定論的judge、zipapp builder、実行無効のCodexアダプター、CLI
- `specs/schemas/` のtask、policy、gate、review、TDD evidence、verdictの6 JSON Schema
- `specs/prompts/` の独立reviewer / adversary prompt
- `specs/tasks/` のtask例と `TASK-006` 契約
- 通常pytestのPython network monkeypatch guardと `live_api` の二重opt-in
- GitHub Actionsのlock、Ruff、offline pytest、diff check
- Streamlitデバッグ表示、表示整形、検索語fallback、APIキー欠落経路の回帰テスト
- [AI_GUIDE.md](../AI_GUIDE.md) と関連管理文書

## 対象外

- ブックマーク表示数を変更するプルダウンの追加
- 既存の検索結果表示件数スライダーの用途変更
- 削除済みPDFの復元または参照
- Codexその他の外部AIサービスの実行
- Bonsai、Outscraper、Amazonへの実通信
- standalone isolated clone、2つのAIレビュー、RED/GREEN証拠runnerの自動起動
- AI判定によるcommit、push、merge
- 別UID/read-only external preflight、コンテナ、network namespace、firewall、coordinator署名

対象外を変更する場合は、このPlan、task JSON、セキュリティ条件を人間が承認した別のExecution Planで扱う。

## TASK-006完了時点の状態

基準commitにはAIレビュー契約、実行コード、CI、network guardが存在しなかった。TASK-006当時の作業ツリーでは次を実装した。

- 6つのstructured JSON契約は未知fieldと型coercionを拒否する。
- raw task SHA-256をpolicy、review、gate、TDD evidence、verdictへ結び付ける。
- gateをcandidateのheadとcanonical diff SHA-256へ結び付ける。
- test manifestをpolicy内のtest file content SHA-256からjudgeが再構築する。
- test受入ごとにREDの許容終了コードとfailure fingerprint SHA-256をtaskへ固定する。
- candidateをlinked worktreeではなく、`git clone --no-local` または `--no-hardlinks` でlocal hardlink最適化を避けたstandalone isolated cloneに限定する。
- policyはgit-dir/common-dirが独立した `.git` directoryへ一致することを要求し、`commondir`、`worktrees`、attributes、alternates/http-alternates、metadata tree内のsymlink/hardlink/nested mount/特殊file/所有権・書込権限をfail closedで検査する。
- policyはSHA-1 repositoryだけを許可し、base/head commit、到達tree、変更前後blobをGit header込みで再hashしてobject IDとの一致を要求する。
- policyはbase直系の単一canonical commit、Git設定、metadata、scope、保護path、file type、byte/line/file上限をfail closedで検査する。
- policyはcontent/numstat処理後にもHEAD、replace refs、index/worktree、base/head commit、到達treeを再検査する。ただし同UIDのwritable candidateでは、検査中に一時差替えを戻す競合とreturn後のTOCTOUが残る。
- exact blob copyは拒否する。内容を変更したcopyはsimilarity推測を使わずnew addとして扱う。
- `.env.example` を含む `.env*`、Streamlit secrets、`.git`、`cache` の変更を保護する。
- judge CLIは保存済みpolicyを信用せず、現在のcandidate repositoryへpolicyを再実行して完全一致を要求する。
- provenanceが自己申告である間は自動 `pass` を返さない。
- Codexアダプターはdry-run専用で `--execute` を拒否する。
- pytestはcollection前から通常のPython socket、名前解決、Requests経路をmonkeypatchする。

zipapp内部のSHA-256検査は候補内/source-treeからの誤起動を検出する補助である。ハーネスmodule import後に検査するためtrust anchorではなく、attestationとして扱わない。候補内Python、候補内 `.venv`、source-treeの `python -m tools.ai_review`、直接 `PYTHONPATH` を設定する起動は正規運用にしない。

pytest guardもOSレベルの遮断ではない。subprocess、raw file descriptor、native code、plugin早期import、候補差分によるguard改変を完全には止めない。`network_policy=deny` は契約であってnetwork namespaceではない。

## 実行内容

### 1. taskと証拠binding

- raw task bytesのSHA-256を実装前に候補外で固定する。
- `base_sha`、要求ID、review prompt digest、candidate commit metadata、受入、allowed / denied path、変更上限、RED終了コード/fingerprint、対象外をtaskへ固定する。
- review、gate、TDD evidence、verdictへ同じraw task SHA-256を必須にする。
- reviewerとadversaryへ同じbase/head/canonical diffを要求する。
- gateへhead/candidate digest、TDDへcontent由来test manifestと同一test patchを要求する。

### 2. candidate policyとjudge

- `--no-local` または `--no-hardlinks` で作ったstandalone isolated cloneのcleanなHEADだけを評価する。
- 外部git-dir/common-dir、共有metadata、attributes/alternatesとmetadata tree内link/mountを拒否する。
- commit/tree/blobをGit header込みで再hashし、canonical candidate digest内のobject IDと実内容を束縛する。
- base直系1件のcanonical squash commitとtask固定metadataを要求する。
- 保護対象を検出したらblob本文を読まず、canonical diffを生成せず停止する。
- exact blobのrename/copy、delete、mode/type変更、binary、symlink、gitlinkを拒否する。
- judge時にcandidateのcurrent HEADをpolicyで再検査し、保存済みpolicyとの完全一致を要求する。
- policy末尾でHEAD、replace refs、index/worktree、commit/treeを再検査するが、attested運用では別UIDのread-only snapshot/cloneを追加条件にする。
- critical/high、accept以外、契約不一致、役割不備はfailとし、それ以外もattestation実装まではhuman reviewとする。

### 3. TDDパイロット

- UIデバッグ表示の不足をテストでREDにし、同じテストでGREENにした。
- 検索語fallbackの検証迂回をテストでREDにし、共通validatorへ集約してGREENにした。
- APIキー欠落がHTTP要求前に停止する既存安全性をcharacterization testで固定した。

### 4. networkとCI

- 通常pytestでは `live_api` を除外し、Python通常経路の通信をmonkeypatchで失敗させる。
- live testはmarkerと `--run-live-api` の二重opt-inにする。
- CIはPython 3.10 / 3.13 matrix、locked sync、Ruff、offline pytest、diff checkを定義する。
- hash処理はPython 3.10にない `hashlib.file_digest()` を使わずchunk読込にした。ただし今回のローカル環境ではPython 3.10 interpreterによる実行は未確認である。

## 進捗

以下の未チェック項目はTASK-006当時の移管項目であり、現在の未実装一覧ではない。後続の達成状況と残作業は [EXEC-002](EXEC-002-ATTESTED-AI-REVIEW-BOUNDARIES.md) を参照する。

- [x] task、policy、gate、review、TDD evidence、verdictのモデルと6 schemaを追加した。
- [x] raw task、candidate、gate、TDD、reviewのbindingを強化した。
- [x] standalone clone、外部/共有Git metadataとmetadata link/mountの拒否、Git object再hash、current policy再検査、exact copy、保護pathのfail-closed testを追加した。
- [x] Codex実行と自動 `pass` を禁止し、zipapp内部検査の限界を明確化した。
- [x] network monkeypatch guard、live二重opt-in、CI定義を追加した。
- [x] TDDパイロットと関連文書を追加した。
- [ ] import前に別UID/read-onlyでarchiveとPythonを検証する外部preflightを実装する。
- [ ] policy return後もcandidateを書換不能にする、別UID所有のread-only snapshot/cloneを実装する。
- [ ] 候補から解除できないcontainer read/network isolationを実装する。
- [ ] reviewer / adversaryの起動、RED/GREEN/gate採取、署名付きprovenanceをcoordinatorでattestする。
- [ ] attestedな自動実行の設計を独立監査し、人間が再承認する。

## TDD証拠

| 対象 | テストSHA-256 | RED | GREEN / 固定結果 |
|---|---|---|---|
| Streamlitの全採点重みと表示整形 | `042ad1b2cd8307afe40787bd53510d4cb55f66914548adf9ed76b57b8306ac4c` | `tests/test_streamlit_ui.py` で色・特徴語重みの不足を再現 | 2項目追加後に同じtest contentで成功 |
| Outscraper検索語fallback | `c6c60c698d7cb3074721c07f04d853c5c742e6ab157fcf5697995ad5df889189` | 空文字・URL fallbackの検証迂回を再現 | fallbackも `validate_search_query()` を通して成功 |
| APIキー欠落時の通信抑止 | 現行test content | 新規不具合修正ではないためREDなし | `RuntimeError` と取得関数未呼出を確認 |

RED/GREENの全文ログはGit管理対象へ含めない。上表は実施時の要約であり、test content hashやcandidate digestが変わった将来変更へ証拠を流用しない。

## 検証方針

最終テスト件数は固定値として文書へ埋め込まない。共有ツリーの最終状態に対して次を再実行し、0終了と未実行境界をhandoffで報告する。

```sh
uv run pytest tests/test_ai_review_harness.py tests/test_network_policy.py -m 'not live_api'
uv run pytest -m 'not live_api'
uv run ruff check .
uv run ruff format --check .
uv lock --check
git diff --check
```

GitHub ActionsのPython 3.10 / 3.13 job、外部Codex、Bonsai、Outscraper、実networkはローカル確認に含めない。Python 3.10互換のhash APIへ修正済みだが、3.10実行結果はGitHub Actionsまたは別の3.10環境で確認する。

## セキュリティ判断

次表はTASK-006当時の判断と見直し条件である。見直し後の現行判断は [EXEC-002](EXEC-002-ATTESTED-AI-REVIEW-BOUNDARIES.md#判断記録) を正とする。

| 判断 | 理由 | 見直し条件 |
|---|---|---|
| candidateは `--no-local` または `--no-hardlinks` のstandalone isolated cloneに限定する | linked worktree、external common-dir、local clone hardlinkはGit metadata/objectを共有する | 独立性を同等以上に証明する別方式を敵対的テストで確認した場合 |
| zipapp内部hashをtrust anchorにしない | 検査より前にarchive codeがimportされる | import前の候補外preflightが実装・監査された場合 |
| Codex実行、自動 `pass`、attestationを禁止する | 別UID/read-only preflight、return後も不変なsnapshot、container隔離、署名付きprovenanceがない | 4条件を実装し独立監査と人間承認を終えた場合 |
| exact blob copyだけをcopyとして拒否する | Git similarity heuristicを証拠契約に使わない | copy定義と検出方法をtask/schema/testへ固定できた場合 |
| network monkeypatchを補助とする | Python通常経路の外をOSで遮断しない | container/network namespace等を候補から解除不能にした場合 |
| 全verdictで人間承認を必須にする | 機械規則とAIレビューは目的・有用性・残余リスクの責任を代替しない | 現行では見直さない |

## 発見事項

以下はTASK-006 bootstrap時点の発見事項である。

- TASK-006のbaseにはtrusted harnessがなく、このbootstrap変更自身にattestedなcandidate policy / verdictを生成できない。
- zipappの自己検査は誤起動には有効だが、外部trust anchorという以前の想定を満たさない。
- 保存済みpolicyだけをjudgeへ渡すとcandidate差替えを検出できないため、current repositoryの再検査が必要だった。
- policy末尾のHEAD / replace refs / index / worktree再検査でも、同UIDで検査中だけcandidateを差し替えて戻すraceとreturn後のraceは残る。attestationには別UIDのread-only snapshotが必要である。
- standalone cloneでもlocal cloneのhardlink最適化やGit metadata内の外部参照を許すと、候補外の変更が検査対象へ影響するため、`--no-local` / `--no-hardlinks` とmetadata tree検査が必要だった。
- canonical digestがblob IDだけを含む場合、object file名と内容が一致することが前提になる。SHA-1 object header込み再hashとloose blob/commit/tree改ざんの回帰テストでこの前提を検査する必要があった。
- test path名だけのmanifestでは内容差替えを検出できないため、policyのcontent SHA-256から再構築する必要があった。
- REDの任意失敗を証拠にできないよう、許容終了コードとfailure fingerprintをtaskへ固定する必要があった。
- `.env.example` はアプリ利用者向けの空templateであっても、AI coordinatorでは環境file名として保護する必要がある。

## ロールバック

このPlanの変更はアプリの永続データ移行を伴わない。取り消す場合は対象commitを通常のGit手順でrevertし、次を確認する。

1. 利用者の未コミット差分を巻き込まない。
2. `.env`、`.env.example`、`cache/` の内容を表示・削除しない。
3. 追加テストを単に消して安全性を見かけ上回復させない。
4. CI、network guard、ハーネス、6 schema、task、文書を同じ変更で整合させる。
5. offline gateと文書リンクを再検証する。

## 結果

2026-08-15時点で安全側MVPを完了した。strictな6 JSON契約、raw task / candidate / gate / TDD binding、standalone clone policy、current repository再検査を行うjudge、実行無効のCodex dry-run、補助的network guard、CI定義、TDDパイロット、運用文書をそろえた。

同日の完了時点ではattested自動実行を未完・保留とし、外部Codex、Bonsai、Outscraper、実networkを実行しなかった。そこで移管したpreflight、snapshot、OS隔離、broker、署名、attested judgeの現行実装と、supported production一括運用・配備の残りは [EXEC-002](EXEC-002-ATTESTED-AI-REVIEW-BOUNDARIES.md) に記録する。
