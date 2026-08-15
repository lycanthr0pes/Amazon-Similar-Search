# 技術的負債トラッカー

## 1. 役割

この文書は、現行構造に意図的または歴史的に残っている横断的な改善課題を追跡する。記載内容は2026-08-16時点のコードとテストで確認した。

他の管理文書との区別:

- [ISSUES.md](ISSUES.md): 再現可能な不具合、障害、仕様との不一致
- [TODO.md](TODO.md): 1回の小さな変更で完了できる作業
- [TASKS.md](TASKS.md): 複数段階に分かれる大規模な成果単位
- 本文書: 放置すると保守性、信頼性、運用性、安全性を下げる構造上の負債

負債の解消には複数の変更が必要な場合がある。その場合は `TASKS.md` に成果単位を作り、実行開始時に [PLANS.md](PLANS.md) に従ってPlanを作る。

## 2. 状態と優先度

状態は `未着手`、`対応中`、`ブロック`、`解消`、`受容` を使う。実装、検証、文書更新まで確認できる前に `解消` としない。`受容` には、受容理由と再検討条件が必要である。

| 優先度 | 意味 |
|---|---|
| P0 | シークレット漏えい、データ破壊等につながり、通常利用を止めて対処すべきもの |
| P1 | 多利用者運用または本番公開前に解消・受容判断が必要なもの |
| P2 | ローカル利用は継続できるが、信頼性や保守性を上げるために扱うもの |

現時点でP0として確認済みの項目はない。これは脆弱性が存在しないことを保証するものではない。

## 3. 一覧

| ID | 優先度 | 状態 | 概要 |
|---|---|---|---|
| TD-001 | P1 | 未着手 | 長時間の外部API処理をUIリクエスト内で同期実行する |
| TD-002 | P1 | 未着手 | ファイルキャッシュに競合・容量・全体保持期限の管理がない |
| TD-003 | P1 | 未着手 | 認証、認可、利用量制限、利用者別永続分離がない |
| TD-004 | P1 | 未着手 | 構造化ログ、相関ID、メトリクス、監査経路がない |
| TD-005 | P2 | 未着手 | Bonsai要求に上限付き再試行がない |
| TD-006 | P2 | 対応中 | 決定論的CIは追加中だが配布方式が定義されていない |
| TD-007 | P2 | 未着手 | 内部モデルの一部制約が正規化サービスに依存する |
| TD-008 | P2 | 未着手 | 固定為替レートと手動重みに対する評価基盤がない |
| TD-009 | P2 | 対応中 | credential-free配備前提は実host確認済みだが、live E2Eとnonce長期運用が未完である |

## 4. 詳細

### TD-001: 同期的な検索実行

- 状態: 未着手
- 根拠: `src/ui/streamlit_ui.py` が `run_product_search()` を直接呼び、`src/clients/outscraper_client.py` がポーリング間隔ごとに `time.sleep()` する
- 現在の影響: 検索完了または待機上限まで、同じStreamlit実行が結果を待つ。ジョブIDの返却、キャンセル、後からの状態照会はない
- ローカル利用上の扱い: スピナーを表示して同期完了を待つ
- 解消条件: ジョブ状態、期限、キャンセル、同時実行上限を持つ実行方式を実装し、UIから状態遷移を検証できる
- 関連大規模タスク: [TASK-001](TASKS.md#task-001-検索処理のジョブ化)

### TD-002: ファイルキャッシュのライフサイクルと競合

- 状態: 未着手
- 根拠: `JsonCacheRepository` はアトミック置換を行うが、プロセス間ロック、容量上限、削除処理を持たない。正規化・採点キャッシュは読込TTLを持たない
- 現在の影響: 長期利用でファイルが増え続け得る。同じキーへの複数プロセス書込を調停せず、認証利用者単位の保存領域もない
- 実装済みの緩和: namespaceとキー検証、アトミック書込、属性と生レスポンスのTTL、破損時の再計算、Streamlitセッションscope
- 解消条件: 保存方式を決定し、容量・保持期限・削除・競合・利用者分離の方針を実装して負荷・競合テストを通す
- 関連大規模タスク: [TASK-002](TASKS.md#task-002-キャッシュ基盤の運用対応)

### TD-003: アクセス制御と利用量制御

- 状態: 未着手
- 根拠: 現行依存関係と `src/ui/streamlit_ui.py` にアプリ独自の認証、認可、レート制限、API利用量上限がない。キャッシュscopeはランダム値であり認証主体ではない
- 現在の影響: アクセス制御なしで公開すると、第三者がOutscraper利用とローカル計算を発生させ得る。利用者別の保存・削除要求にも対応できない
- 解消条件: 想定利用者と公開範囲を要件化し、認証、認可、利用上限、永続データ分離、監査を一体で検証する
- 関連大規模タスク: [TASK-003](TASKS.md#task-003-多利用者向けセキュリティ境界の構築)

### TD-004: 観測可能性とログ管理

- 状態: 未着手
- 根拠: パイプラインは主に `print()` を使い、UI例外だけが `LOGGER.exception()` を使う。`APP_ENV` と `LOG_LEVEL` は設定に存在するが現行処理で参照されない。構造化メトリクスとトレースはない
- 現在の影響: 1検索の段階を横断する相関ID、レイテンシ、再試行、キャッシュヒット率、外部API失敗率を一貫して集計できない
- セキュリティ上の注意: Outscraper失敗例外は外部レスポンス由来の説明を含み得るため、外部転送前にマスキング方針が必要である
- 解消条件: ログ項目と禁止項目、相関ID、メトリクス、保持期間、アラートを定義し、値がシークレットや利用者入力を漏らさないテストを持つ
- 関連大規模タスク: [TASK-004](TASKS.md#task-004-観測可能性と配布パイプラインの整備)

### TD-005: Bonsai通信の回復性

- 状態: 未着手
- 根拠: `call_bonsai()` は60秒のタイムアウトと専用例外を持つが、通信失敗または一時的HTTP失敗を再試行しない
- 現在の影響: 一時的なローカルサーバー障害でも検索全体が失敗する
- 制約: 生成要求の再送は計算時間を増やし、応答の再現性にも影響し得る
- 解消条件: 再試行対象、最大回数、バックオフ、重複要求の扱いを決め、通信モックによる回帰テストを追加する

### TD-006: CIと配布方式

- 状態: 対応中
- 根拠: 現行作業ツリーの `.github/workflows/ci.yml` はPython 3.10 / 3.13でlock、Ruff、offline pytest、diff checkを行う。一方、配布方式、必須チェック設定、リリース、ロールバックは未定義である
- 実装中の緩和: 最小権限の読取permission、永続credentialなしのcheckout、固定SHAのAction、20分timeout、`live_api` 除外を設定した
- 現在の影響: 決定論的な品質ゲートは追加中だが、ホスティング環境での実行確認、配布再現、シークレット注入、復旧は保証しない
- 解消条件: CIを実際のGitHub実行で確認し、必須チェック、配布先、シークレット注入、書込領域、リリース、ロールバックを決定して自動検証する
- 関連大規模タスク: [TASK-004](TASKS.md#task-004-観測可能性と配布パイプラインの整備)

### TD-007: モデル境界の制約不足

- 状態: 未着手
- 根拠: `ProductAttributes.price_preference` の列挙値とリスト件数、商品URLのスキーム・ホスト、評価範囲、文字列長はPydanticモデル自体で制約していない。価格の正数化や範囲入替は属性抽出サービスで行う
- 現在の影響: 現行サービスを通らずモデルを直接構築した場合、同じ保証を得られない。外部URLはモデル検証だけでは表示可否を判断できない
- 解消条件: 受け入れる値と互換性を要件化し、モデルまたは明示的な境界サービスで一貫して検証する

### TD-008: 為替とランキング品質の評価

- 状態: 未着手
- 根拠: USD価格は `USD_TO_JPY_RATE` の固定整数で換算する。総合係数と条件語重みは設定値であり、代表クエリと期待順位を持つ評価データセットはリポジトリにない
- 現在の影響: 実勢為替との差と重み変更による検索品質の変化を自動検出できない
- 解消条件: 許容する為替鮮度とランキング評価指標を決め、固定データによる再現可能な評価を追加する
- 関連大規模タスク: [TASK-005](TASKS.md#task-005-ランキング品質評価の確立)

### TD-009: AI変更の役割分離と証拠契約

- 状態: 対応中
- 根拠: AI実装者の変更を、独立したreviewer / adversary、固定commit差分、RED→GREEN証拠、機械検証可能な結果へ一貫して結び付ける仕組みがなかった
- 実装済みの緩和: TaskSpec v2とstrict artifact契約、canonical Git policy、root `.env.example` の空値検査後除外、共通credential path/secret scanner、content-addressed candidate/RED snapshot、networkなしraw offline runner、bounded packet、root-owned stdlib preflight、pinned coordinator/runner/broker/gateway image、fixed egressのprovisioned lifecycle、失敗attemptを含むfrozen final ledger、Ed25519、exact SQLite nonce ledger、frozen attested judge、7-phase digest/replay protocol、stdlib固定state machineを追加した。external phaseはprepared payloadとexact raw evidenceをphase digestへ結び、brokerはhost SQLite削除後も再finalizeできる。7/7 actual handlerは、同じimmutable evidenceからexpectationを再構築するsign/judgeまで接続済みである。さらにexternal approved manifest SHAとhuman-approved patch SHAを必須にするcredential-free `workflow-init`、4つのmanifest-pinned imageをnetworkなしで検査して `nonlive_ready` だけを返すdeployment checkを追加した。TaskSpecはruntime release builderのPydantic full validation、manifestのraw task/harness binding、launcher import前のv2/harness narrow checkへ責務分離した。deployment checkはpasswd HOME由来の明示HOME/XDG、candidate-inaccessibleなconfig/storage path、Podman infoのgraph root/run root/active config/seccomp stable subsetを前後で結び、別image store指定を拒否する
- 現在の影響: コードと回帰テスト上の7/7境界、初期request生成、credential-free deployment preflightは閉じ、独立security reviewの未修正CRITICAL/HIGHも0である。2026-08-16に専用user/subuid/subgid、private passwd HOME/XDG、approved storage config、rootless Podman 6.1、root-owned release、具体的TaskSpec v2 canary、4つの異なるimage digestを配備し、実host `nonlive_ready` を確認した。external manifest/patch anchorを再照合し、`ai-review` 所有のstandalone candidateからUID 1100所有0500/0400のlive用initial requestも生成した。残る未検証境界はlive 7-phase E2E、GitHub Actions、Python 3.10 local実行である。nonce ledgerはreplay防止のため単調増加し、保持・backup・容量・rotation方針は未定義である
- セキュリティ制約: source-tree launcher、candidate内Python/task、root実行、Docker/rootful Podman、user namespace/seccompなし、caller任意のHOME/XDG、candidate-writable config/store、alternate image storeへfallbackしない。external AIにはpacketだけを渡し、candidate filesystemとcredentialを同じ主体へ持たせない。完全なattested verdictでも人間承認を維持する
- 解消条件: 別途承認した送信内容、credential、費用上限でlive 7-phase E2Eを確認する。nonce ledgerの保持・backup・容量・rotationと古いattestationの検証方針を定義する。live API未実行の間はその境界を明記し、credential-free `nonlive_ready` やinitial request生成をlive成功へ読み替えない
- 関連大規模タスク: [TASK-007](TASKS.md#task-007-attested-ai-review境界の実装)
- 実行計画: [EXEC-002](plans/EXEC-002-ATTESTED-AI-REVIEW-BOUNDARIES.md)

## 5. 更新規則

- 新規項目にはコード、テスト、実行結果のいずれかの根拠を付ける
- 推測だけのリスクは負債として断定せず、調査タスクまたはPlanの発見事項にする
- 対応中にした場合は、実行中のTaskまたはPlanへリンクする
- 解消時はコミットまたは変更箇所、検証結果、解消日を追記する
- 別の仕組みに置き換えた場合も、移行と旧データの扱いを確認するまで解消にしない
- 優先度は利用形態が変わったときに見直す。特に外部公開や多利用者化はP1項目の前提を変える
