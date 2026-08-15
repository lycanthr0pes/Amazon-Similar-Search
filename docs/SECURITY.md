# セキュリティ

## 1. 対象範囲

この文書は、現行のローカル実行向け amazon-explorer に実装されている保護と、運用上必要な制約を整理する。セキュリティ上の実装根拠は `src/config.py`、`src/clients/`、`src/repositories/cache_repository.py`、`src/ui/streamlit_ui.py` を正とする。

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

手動確認:

```sh
git check-ignore -v .env cache/
git ls-files .env cache/
```

`git ls-files` は何も返さないことを期待する。実キャッシュ内容やシークレット値を確認出力へ貼り付けない。

## 11. 本番公開前の未実装事項

次は現行機能ではなく、実装と検証が必要な事項である。

- 認証、認可、利用者別・テナント別データ分離
- API利用量の上限、レート制限、課金監視
- 検索ジョブの非同期化、キャンセル、期限切れ
- 構造化ログ、相関ID、監査ログ、メトリクス、アラート
- シークレットとキャッシュの保持・削除方針
- 外部商品URL・画像URLの検証方針
- 複数ワーカーで安全な保存方式

これらの大規模対応は [TASKS.md](TASKS.md)、現行構造に残る負債は [TECH-DEBT-TRACKER.md](TECH-DEBT-TRACKER.md) で管理する。
