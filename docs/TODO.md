# 小規模タスク一覧

## 1. 役割

この文書は、対象と完了条件が明確で、原則として1回の小さな変更で完結する作業を管理する。2026-08-16時点の現行コードとテストから確認できた項目だけを掲載する。AIハーネスの専用user/subuid/subgid/rootless Podman設定、clean release、具体的TaskSpec v2 canary、`nonlive_ready` 実host確認、launcher user向けinitial request生成は完了した。残るlive E2Eとnonce ledger長期運用は単発作業ではないため、[TASK-007](TASKS.md#task-007-attested-ai-review境界の実装) と [TD-009](TECH-DEBT-TRACKER.md#td-009-ai変更の役割分離と証拠契約) で追跡する。credential-free配備確認をOpenAI APIのlive成功として扱わない。

- 再現可能な不具合は [ISSUES.md](ISSUES.md) に原因と影響を記録し、ここから対応作業をリンクする
- 複数段階または複数の設計判断を要する作業は [TASKS.md](TASKS.md) へ移す
- 構造上の継続課題は [TECH-DEBT-TRACKER.md](TECH-DEBT-TRACKER.md) で追跡する
- 長時間の実行計画は [PLANS.md](PLANS.md) に従う

チェックを付けるのは、変更、対応する確認、文書同期が完了した場合だけである。

## 2. 未完了

### TODO-001: Markdownリンク検査を定型化する

- 状態: 未着手
- 根拠: 今回は一時コマンドで検査したが、現行リポジトリに専用スクリプト、テスト、CIステップがない
- 作業: `docs/` とルートMarkdownのローカル相対リンクを検査する再現可能なコマンドまたはテストを追加する
- 完了条件: 存在する相対リンクは成功し、存在しない対象をテスト用に与えると失敗する。実行方法を文書へ記載する
- 注意: 外部URLの到達性検査とは分け、ネットワークなしでも実行できるようにする

### TODO-005: 未参照設定の扱いを明記する

- 状態: 未着手
- 関連負債: [TD-004](TECH-DEBT-TRACKER.md#td-004-観測可能性とログ管理)
- 根拠: `APP_ENV` と `LOG_LEVEL` は `Settings` と `.env.example` にあるが、現行処理では参照されない
- 作業: 次の観測可能性タスクまで維持するか、現在不要として削除するかを決め、設定、サンプル、制約文書を一致させる
- 完了条件: 採用した判断がコードと文書に一致し、設定ロードのテストが成功する

## 3. 完了

### TODO-002: デバッグ表示へ全条件語重みを表示する

- 状態: 完了
- 完了日: 2026-08-15
- 関連Issue: [ISS-001](ISSUES.md#iss-001-デバッグ表示に2つの条件語重みがない)
- 変更: `src/ui/streamlit_ui.py` の `SHOW_DEBUG_INFO=true` 時のJSONへ `color_term_weight` と `feature_term_weight` を追加した
- 証拠: `tests/test_streamlit_ui.py` は修正前1 failed, 2 passed、修正後3 passed。テストSHA-256は `042ad1b2cd8307afe40787bd53510d4cb55f66914548adf9ed76b57b8306ac4c`
- 残事項: なし

### TODO-003: UIの表示用純粋関数をテストする

- 状態: 完了
- 完了日: 2026-08-15
- 変更: `tests/test_streamlit_ui.py` で `format_price()` と `format_rating()` の価格不明、桁区切り、評価なし、レビュー件数あり・なしを確認した
- 検証: UIデバッグ表示のGREENと合わせて3 passed。外部APIは呼び出していない
- 残事項: ブラウザ操作による一連のUI確認はこの単体テストの範囲外である

### TODO-004: APIキー欠落時の外部通信抑止を直接テストする

- 状態: 完了
- 完了日: 2026-08-15
- 変更: `tests/test_outscraper_client.py` にAPIキー空の直接回帰テストを追加した
- 検証: 対象テストは1 passed。`RuntimeError` となり、`fetch_amazon_products` が呼び出されないことを確認した
- 残事項: 実サービス結合試験は実施しておらず、完了条件にも含めない

## 4. 完了済み項目の扱い

完了時は項目を削除せず、次を追記して「完了」節へ移す。

- 完了日
- 変更を特定できるコミットまたはファイル
- 実行した検証
- 別タスクへ残した事項

完了済み項目のテストを変更した場合は、旧証拠を現行テストの結果として流用せず、新しい検証結果を追記する。
