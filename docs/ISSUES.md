# 問題一覧

## 1. 役割

この文書は、現行実装で再現またはコード上確認できる不具合、利用者影響のある仕様不一致、障害を管理する。推測だけの問題は断定せず、「要確認」として再現条件を記載する。

関連文書との区別:

- 修正作業が小さい場合は [TODO.md](TODO.md) に作業項目を作る
- 複数段階の修正は [TASKS.md](TASKS.md) と個別Planで扱う
- 正常に動作しているが将来の保守・運用に不利な構造は [TECH-DEBT-TRACKER.md](TECH-DEBT-TRACKER.md) で扱う
- 実装されていない将来機能は、不具合として要求済みでない限りIssueにしない

状態は `オープン`、`要確認`、`対応中`、`解決済み`、`再現せず` を使う。テストまたは観察可能な結果を確認する前に `解決済み` としない。

## 2. オープン

2026-08-16時点で、現行作業ツリーにオープンとして記録する確認済みIssueはない。これは不具合が存在しないことを保証するものではない。AIハーネスの7/7 code境界、`workflow-init`、専用userとrootless Podman、root-owned release、4 image、承認済みTaskSpec v2 canary、credential-free `nonlive_ready`、launcher userが読めるlive用initial requestは実hostで確認済みである。OpenAI APIを使うlive E2Eとnonce ledger長期運用が未実行・未定義であることは不具合ではなく、[TASK-007](TASKS.md#task-007-attested-ai-review境界の実装) と [TD-009](TECH-DEBT-TRACKER.md#td-009-ai変更の役割分離と証拠契約) の運用境界として追跡する。

## 3. 解決済みの履歴

### ISS-001: デバッグ表示に2つの条件語重みがない

- 状態: 解決済み
- 重要度: 低
- 確認日: 2026-08-15
- 解決日: 2026-08-15
- 対象: `src/ui/streamlit_ui.py` の `render_status_panel()`
- 前提: `SHOW_DEBUG_INFO=true`
- 原因: 採点に使う `color_term_weight` と `feature_term_weight` がデバッグJSONの構築対象に含まれていなかった
- 解決: 2項目を追加し、総合係数3項目と条件語重み5項目を表示対象にした
- 回帰証拠: `tests/test_streamlit_ui.py` は修正前1 failed, 2 passed、修正後3 passed。テストSHA-256は `042ad1b2cd8307afe40787bd53510d4cb55f66914548adf9ed76b57b8306ac4c`
- 対応作業: [TODO-002](TODO.md#todo-002-デバッグ表示へ全条件語重みを表示する)

APIキーの値は表示対象にしていない。検索結果表示件数スライダーにも変更はなく、ブックマーク表示数プルダウンは追加していない。

次はコミット `fb2115a`（2026-08-14）後のコードと回帰テストで解決状態を確認できる。

| ID | 解決内容 | 根拠 |
|---|---|---|
| ISS-HIST-001 | Outscraper結果URLをHTTPSかつendpointと同一ホスト・ポートへ限定し、APIキー付きリダイレクトを拒否した | `validate_results_location()` と `tests/test_outscraper_client.py` |
| ISS-HIST-002 | Outscraperの正常0件、失敗、不明状態、待機超過を区別した | `task_state()`、専用例外、状態テスト |
| ISS-HIST-003 | 装飾されたJPY・USD価格と文字列Prime値を正規化した | `amazon_product_normalization.py` と正規化テスト |
| ISS-HIST-004 | Bonsaiの不正なレスポンス構造を検証し、生応答を属性変換エラーへ露出しないようにした | `bonsai_client.py`、`user_attribute_extraction.py` と関連テスト |
| ISS-HIST-005 | キャッシュキーへ入力・設定・scopeを含め、Streamlitセッション間の再利用を分離した | `src/main/run.py`、`streamlit_ui.py`、パイプラインテスト |

履歴は現在の回帰理由を残すためのものであり、旧コードで同じ問題が再現することを意味しない。

## 4. 検証範囲

現行テストは外部HTTP通信をモックし、属性抽出、Outscraper状態・再試行・URL検証、正規化、採点、キャッシュ、CLI補助処理、検索パイプラインを確認する。

次は自動テストだけでは確認済みにならない。

- 実際のBonsaiモデルによる抽出品質
- 実Outscraper契約・課金環境での結合動作
- Streamlitをブラウザ操作した一連のUI動作
- 複数プロセスから同じキャッシュへ書く競合
- root-owned releaseをrootless Podman `keep-id` hostへ配備したAIハーネスのlive 7-phase E2E
- 外部OpenAI APIのcredential・送信内容・費用承認を伴うlive実行

これらが未確認であること自体を不具合とは断定しない。障害が観測された場合は、入力やシークレットを伏せた再現情報とともに新しいIDを作る。

## 5. Issueテンプレート

```markdown
### ISS-NNN: 題名

- 状態: オープン
- 重要度: 高 / 中 / 低
- 確認日: YYYY-MM-DD
- 対象: リポジトリ相対パスまたは機能
- 関連要件:

#### 再現手順

1. シークレットと利用者データを含めずに記載する。

#### 期待する状態

#### 実際の状態

#### 影響

#### 証拠

テスト、最小ログ、スクリーンショット等。APIキーと生キャッシュは添付しない。

#### 解決条件

修正と回帰テストを記載する。
```
