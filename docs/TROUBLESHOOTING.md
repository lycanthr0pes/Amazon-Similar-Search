# トラブルシューティング

## 1. 調査の基本順序

問題が起きたら、次の順序で境界を切り分ける。

1. `uv sync --locked` が成功するか
2. `.env` を読み込めるか
3. Bonsaiの `/models` に到達できるか
4. Outscraper APIキーが設定されているか
5. StreamlitではなくCLIでも再現するか
6. ターミナルに表示された段階と例外種別を確認する
7. キャッシュ読込時だけ起きるかを確認する

Streamlitは利用者画面に固定エラーだけを表示する。詳しい原因は、`uv run streamlit run app.py` を実行したターミナルのログで確認する。APIキーやキャッシュ内容を問い合わせ、issue、チャットへ貼らない。

## 2. `uv` が見つからない

### 症状

```text
uv: command not found
```

### 主な原因

`uv` が未導入、または実行ファイルの場所が `PATH` に入っていない。

### 確認

```sh
command -v uv
uv --version
```

### 解決

公式手順で `uv` を導入し、新しいシェルを開くか `PATH` を再読込する。導入後、リポジトリで次を実行する。

```sh
uv sync --locked
```

## 3. 依存関係の同期に失敗する

### 症状

- `uv sync --locked` がPython版やロック不一致を報告する
- `streamlit`、`pydantic`、`sudachipy` などをimportできない

### 主な原因

- Python 3.10未満を使っている
- `pyproject.toml` と `uv.lock` が一致していない
- 仮想環境が古い配置先や異なるPythonを参照している

### 確認

```sh
uv run python --version
uv lock --check
uv run python -c "import streamlit, pydantic, sklearn, sudachipy"
```

### 解決

通常はロックを変更せずに同期する。

```sh
uv sync --locked
```

リポジトリ移動後などで仮想環境の絶対パスが古い場合は、生成物である `.venv` だけを再作成する。

```sh
uv venv --clear
uv sync --locked
```

`uv.lock` の更新は依存関係変更としてレビューする。単なる起動失敗の回避目的で無条件に更新しない。

## 4. 起動直後に設定検証エラーになる

### 症状

Pydanticの `ValidationError`、数値や真偽値を解析できないというエラー、またはスコア重みのエラーが出る。

### 主な原因

- `.env.example` の任意項目を値なしでコメント解除した
- 正数が必要なタイムアウト、件数、TTLへ0以下を設定した
- 総合係数 `TITLE_SCORE_WEIGHT`、`ATTRIBUTE_SCORE_WEIGHT`、`PRICE_SCORE_WEIGHT` の合計が1.0でない
- すべての条件語重みを0にした
- `BONSAI_TEMPERATURE` が0から2の範囲外である

### 確認

値を表示せず、設定名だけを確認する。

```sh
rg -n '^[A-Z][A-Z0-9_]*=$' .env
```

### 解決

使わない任意項目は行頭に `#` を付ける。使用する項目には正しい型の値を設定し、総合係数を合計1.0に戻す。`.env` はアプリ起動時に読み込まれるため、修正後はStreamlitまたはCLIを再起動する。

## 5. `Bonsai Server: not running` と表示される

### 症状

StreamlitのサイドバーにBonsai停止の警告が出る。検索すると固定の失敗メッセージになる場合がある。

### 主な原因

- `llama-server` が起動していない
- ホスト、ポート、`/v1` のbase pathが `BONSAI_BASE_URL` と一致しない
- コンテナや別ホストから `127.0.0.1` を参照している
- `/models` が3秒以内に応答しない

### 確認

既定接続先の場合:

```sh
curl --fail --show-error http://127.0.0.1:8080/v1/models
```

### 解決

Bonsai GGUFモデルを指定して `llama-server` を起動する。別ホスト・ポートなら `.env` の `BONSAI_BASE_URL` を実際のOpenAI互換base URLへ合わせ、アプリを再起動する。

疎通表示は5秒キャッシュされるため、サーバー起動直後は少し待ってから画面を再実行する。

## 6. Bonsaiはrunningだが検索に失敗する

### 症状

- `Step 1/4` の後に失敗する
- CLIで `BonsaiRequestError` または `BonsaiResponseError` が出る
- 属性JSONを解析できない旨の固定 `ValueError` が出る

### 主な原因

- `/models` は応答するが `/chat/completions` が利用できない
- `BONSAI_MODEL` がサーバーのモデル名と一致しない
- 応答がJSON object、`choices[0].message.content` のOpenAI互換形状ではない
- モデル出力を商品属性JSONへ変換できない
- 60秒の既定タイムアウト内に応答しない

### 確認

CLIで再現し、例外種別を確認する。

```sh
uv run python -m src.main.run "ワイヤレスキーボード" --display-limit 1
```

モデルサーバー側のログで、モデル名、chat completion要求、メモリ不足を確認する。生のモデル応答には検索条件が含まれ得るため、公開場所へ貼らない。

### 解決

- `BONSAI_MODEL` を実際の公開モデル名へ合わせる
- Chat Completions互換エンドポイントを有効にする
- 遅い環境では、原因を確認したうえで `BONSAI_TIMEOUT_SECONDS` を増やす
- 一時的な失敗は再実行する。Bonsai側には自動再試行がない

## 7. `Outscraper API key: missing` と表示される

### 症状

サイドバーがAPIキー未設定を警告し、検索時に次のエラーが発生する。

```text
OUTSCRAPER_API_KEY is not set
```

### 主な原因

`.env` の `OUTSCRAPER_API_KEY` が空、コメント化されている、または別ディレクトリの設定を編集している。

### 確認

値を出力せず、非空行があるかだけを確認する。

```sh
grep -Eq '^OUTSCRAPER_API_KEY=.+$' .env \
  && echo "Outscraper API key: configured" \
  || echo "Outscraper API key: missing"
```

### 解決

プロジェクトルートの `.env` に有効なキーを設定し、アプリを再起動する。

```dotenv
OUTSCRAPER_API_KEY=your_api_key
```

引用符や前後空白がAPIキーの一部として解釈されないよう注意する。キーをシェル履歴へ直接書かない。

## 8. Outscraperが401または403を返す

### 症状

CLIログに `OutscraperRequestError` と `non-retryable HTTP 401` または `403` が出る。

### 主な原因

APIキーが無効、失効、権限不足、または契約上そのAPIを利用できない。401/403は自動再試行しない。

### 確認

Outscraper管理画面でキーの状態、契約、利用上限を確認する。ターミナルへキーを表示して確認しない。

### 解決

有効なAPIキーへ差し替え、アプリを再起動する。漏えいが疑われるキーはOutscraper側で失効・再発行する。

## 9. Outscraperが429、5xx、通信エラーになる

### 症状

- `OutscraperRequestError` が出る
- 429または5xxの後に待機して再試行する
- 接続失敗やHTTPタイムアウトになる

### 主な原因

レート制限、一時障害、ネットワーク障害、または要求タイムアウトである。

### 確認

既定では1回の要求を最大3回試し、1秒を基準に指数バックオフする。最終的に失敗した時刻、HTTP状態、Outscraperのサービス状態と利用量を確認する。

### 解決

- 一時障害なら時間を空けて再実行する
- 429では連続して `--no-cache` を使わない
- 必要なら契約とAPI利用上限を確認する
- ネットワーク、DNS、プロキシ、TLSを確認する
- 設定変更時は待ち時間とAPI利用量への影響を評価する

## 10. 検索スピナーが長時間終わらない

### 症状

`商品候補を取得してスコアリングしています。` のまま待機する。ターミナルには `Poll n/50` が続く。

### 主な原因

Outscraperの非同期タスクが処理中である。現行UIは同期実行で、既定では30秒間隔、最大50回ポーリングする。

### 確認

起動ターミナルで現在の `Step`、request ID、ポーリング回数とstatusを確認する。ブラウザだけでは詳細進捗を確認できない。

### 解決

- Outscraper側のタスク・サービス状態を確認する
- 同じ検索を重ねて送信しない
- `OUTSCRAPER_MAX_POLLS` と `OUTSCRAPER_POLL_INTERVAL_SECONDS` を変更する場合は、最大待ち時間とAPI要求回数を先に計算する
- UIのキャンセル、バックグラウンドジョブは未実装であるため、長時間処理が要件なら [TASKS.md](TASKS.md) で設計タスクとして扱う

## 11. Outscraperのtask failedまたはunknown status

### 症状

- `OutscraperTaskFailedError`
- `OutscraperResponseError` とunknown statusのメッセージ
- 成功状態だが `data` がない、またはリストでないというエラー

### 主な原因

Outscraper側のタスク失敗、API仕様変更、想定外のレスポンス形状である。

### 確認

request ID、status、発生時刻を控える。レスポンス本文には検索条件や商品データが含まれ得るため、そのまま公開しない。

### 解決

OutscraperのAPI仕様とサービス状態を確認する。再現テストを追加する場合はレスポンスを匿名化し、`tests/test_outscraper_client.py` へ最小形状のfixtureを追加する。

## 12. `results_location` またはredirectのセキュリティエラー

### 症状

- `OutscraperSecurityError`
- HTTPS、same host and port、redirect禁止に関するメッセージ

### 主な原因

結果URLが設定endpointと異なるオリジン、HTTP、URL内認証情報付き、またはAPIキー付き要求がリダイレクトされた。これはAPIキーを意図しない送信先へ渡さないための停止である。

### 確認

秘密情報を除いて `OUTSCRAPER_ENDPOINT` のscheme、host、portを確認する。リバースプロキシや独自endpointがリダイレクトを返していないか調べる。

### 解決

安全検証を無効化しない。HTTPSの正式endpointを直接指定し、結果URLが同一host・portになる構成へ直す。Outscraperの正式仕様と異なる応答なら、送信前にサービス提供元へ確認する。

## 13. 検索は成功するが0件になる

### 症状

画面に `表示できる検索結果がありません。` と出る。

### 主な原因

- Outscraperが正常に `data=[]` を返した
- 検索語が限定的すぎる
- タイトルのない商品が正規化で除外された
- JPY・USD以外と明示された商品が除外された
- ドメイン、言語、郵便番号が意図と違う

### 確認

ターミナルで4段階が完了しているか確認する。現在の `OUTSCRAPER_DOMAIN`、`OUTSCRAPER_LANGUAGE`、`OUTSCRAPER_POSTAL_CODE` を確認する。

### 解決

商品種別を残して色や特徴を減らすなど、検索条件を少し広げる。対象市場に合わせてドメイン、言語、郵便番号を設定する。0件を例外扱いへ変更しない。

## 14. 古い結果が再利用される

### 症状

CLIで同じ入力を実行すると、外部APIを呼ばず `loaded from cache` と表示される。

### 主な原因

属性抽出は既定24時間、Outscraper生レスポンスは既定1時間再利用する。正規化と採点は内容・設定ベースのキーが一致すると再利用する。

### 確認

ターミナルの次の表示を確認する。

```text
Product attributes loaded from cache.
Outscraper response loaded from cache: ...
Normalized products loaded from cache.
Scored products loaded from cache.
```

### 解決

外部処理から再実行する必要がある場合だけCLIの `--no-cache` を使う。

```sh
uv run python -m src.main.run "検索条件" --no-cache
```

この指定でも新しいキャッシュは保存され、外部API利用が発生する。Streamlitには `--no-cache` 相当の画面操作がない。`ENABLE_CACHE=false` を使う場合は `.env` 変更後にアプリを再起動する。

## 15. キャッシュの読込・書込に失敗する

### 症状

- `PermissionError` やディスク容量不足が出る
- キャッシュ破損後に再計算が繰り返される
- `CACHE_DIR` を変更してから保存できない

### 主な原因

保存先権限、空き容量、複数プロセスの競合、または不正JSONである。JSON書込はアトミックだが、プロセス間ロック、容量上限、自動削除はない。

### 確認

内容を表示せず、パス、権限、容量だけを確認する。

```sh
ls -ld cache cache/product_attributes cache/outscraper 2>/dev/null
df -h .
find cache -type f -name '*.json' -printf '%s %p\n' | sort -n | tail
```

### 解決

- 実行ユーザーが所有する書込可能なディレクトリを `CACHE_DIR` に指定する
- 公開WebルートやGit管理対象の外へ置く
- 破損が疑われる場合はアプリを止め、対象ファイルをバックアップしてから対象キーだけを隔離する
- キャッシュ全体を無条件に削除しない。利用者入力や取得済みデータが必要か先に確認する
- 複数ワーカー運用は現行ファイルキャッシュの対象外である

## 16. 価格表示や順位が期待と違う

### 症状

- USD商品の円換算が実勢レートと違う
- 価格不明になる
- 必須条件を欠く商品が残る
- 否定条件に一致する商品が完全には除外されない

### 主な原因

- USD換算は `USD_TO_JPY_RATE` の固定値であり、為替を自動取得しない
- JPY・USDと判断できない価格は正規化できない場合がある
- 必須語は一致スコアへ強く反映するが、厳密なフィルターではない
- 否定条件は1件につき0.2、最大0.5の減点であり、自動除外ではない

### 確認

商品カードの「商品名」「属性」「価格」と、一致・不足・否定条件を個別に見る。設定済みのスコア係数と条件語重みを確認する。

### 解決

- 必要なら `USD_TO_JPY_RATE` を運用上の固定レートへ更新して再検索する
- 自然文で価格帯、必須条件、避けたい条件を具体化する
- 重み変更は代表クエリの期待順位を用意してから行う
- 厳密除外が必要なら仕様変更として [REQUIREMENTS.md](REQUIREMENTS.md) とテストを更新する

## 17. Streamlitのポートを使用できない

### 症状

起動時にポートが使用中というエラーになる。

### 確認

```sh
ss -ltn | rg ':8501\b'
```

### 解決

既存プロセスを確認するか、別ポートで起動する。

```sh
uv run streamlit run app.py --server.port 8502
```

外部公開用の `0.0.0.0` bindを安易に指定しない。現行アプリには認証とレート制限がない。

## 18. テストまたは静的解析に失敗する

### 症状

- `uv run pytest` が失敗する
- Ruffが違反やformat差分を報告する
- `git diff --check` が末尾空白を報告する

### 確認

```sh
uv run ruff check .
uv run ruff format --check .
uv run pytest -q
git diff --check
```

### 解決

最初に出た失敗を対象ファイルと行番号から直す。自動整形する場合は差分を確認する。

```sh
uv run ruff format .
git diff --check
```

単体テストは外部APIをモックしており、成功しても実サービスの疎通は保証しない。実APIテストは料金、APIキー、件数を確認してから別に行う。

## 19. 秘密情報を誤って表示・記録した

### 症状

APIキーをGit、ログ、issue、チャット、スクリーンショットへ載せた。

### 解決

1. Outscraper側で該当キーを直ちに失効する
2. 新しいキーを発行し、ローカル `.env` または秘密管理機構だけへ保存する
3. 公開場所の内容を削除・非公開化する
4. Gitへ入った場合は、通常の追記コミットだけでは履歴から消えないため、影響範囲を確認して履歴除去を計画する
5. ログ、キャッシュ、バックアップにも複製がないか確認する

詳細は [SECURITY.md](SECURITY.md)を参照する。

## 20. 解決しない場合に残す情報

秘密情報を除き、次を記録する。

- 発生日時とタイムゾーン
- 実行方法（StreamlitまたはCLI）
- Python、uv、OSの版
- 失敗した段階（Step 1から4）
- 例外クラスと、秘密情報を除いた最小メッセージ
- Bonsaiがローカルか別ホストか
- OutscraperのHTTP状態またはtask status
- キャッシュを読む場合と `--no-cache` の差
- 最小の再現手順
- `uv run pytest` とRuffの結果

未解決問題は [ISSUES.md](ISSUES.md)、修正候補は規模に応じて [TODO.md](TODO.md) または [TASKS.md](TASKS.md) へ登録する。
