# クイックスタート

## 1. 最短構成

amazon-explorer を実検索まで動かすには、次が必要である。

- Python 3.10以上
- `uv`
- OpenAI互換APIとして起動したBonsai 8B
- 有効なOutscraper APIキー
- Bonsai接続先とOutscraperへ到達できるネットワーク

Outscraperの実検索は外部APIを利用し、契約に応じて料金が発生し得る。最初は `OUTSCRAPER_LIMIT` を小さくして確認することを推奨する。

## 2. インストール

リポジトリへ移動し、ロックファイルに従って依存関係を用意する。

```sh
cd /home/products/Git_Products/amazon-explorer
uv sync --locked
```

`uv.lock` を意図的に更新する場合を除き、通常の利用開始では `--locked` を付ける。

## 3. 環境変数

サンプルをコピーし、所有者だけが読めるようにする。

```sh
test -e .env || cp .env.example .env
chmod 600 .env
```

既存の `.env` は上書きしない。すでに存在する場合は必要な設定名だけを `.env.example` と照合する。

`.env` の次の行へ実値を設定する。

```dotenv
OUTSCRAPER_API_KEY=your_api_key
```

設定していない任意項目はコメントのままにする。数値、真偽値、パスの項目を空文字で有効化すると、起動時の型変換に失敗する場合がある。

既定値のまま使う場合、主要な接続設定は次である。

| 項目 | 既定値 |
|---|---|
| Bonsai URL | `http://127.0.0.1:8080/v1` |
| Bonsaiモデル名 | `Bonsai-8B.gguf` |
| Amazonドメイン | `amazon.co.jp` |
| 言語 | `ja` |
| 郵便番号 | `100-0001` |
| Outscraper取得上限 | `100` |

すべての設定名・既定値は [BACKEND.md](BACKEND.md) と `.env.example`、利用上の限界は [CONSTRAINTS.md](CONSTRAINTS.md) を参照する。APIキーをGit管理ファイル、チャット、画面キャプチャへ貼らない。

## 4. Bonsaiを起動する

llama.cpp の `llama-server` とBonsai 8BのGGUFモデルを用意し、モデルの実パスを指定して起動する。

```sh
/path/to/llama.cpp/build/bin/llama-server \
  -m /path/to/Bonsai-8B.gguf \
  --host 127.0.0.1 \
  --port 8080
```

別ターミナルからOpenAI互換APIの疎通を確認する。

```sh
curl --fail --silent http://127.0.0.1:8080/v1/models >/dev/null \
  && echo "Bonsai API: OK"
```

別のホスト、ポート、base pathを使う場合は `.env` の `BONSAI_BASE_URL` を変更する。モデル名がサーバーの公開名と異なる場合は `BONSAI_MODEL` も合わせる。

## 5. Streamlitで起動する

```sh
uv run streamlit run app.py
```

ブラウザで表示されたURLを開く。サイドバーで次を確認する。

- `Outscraper API key: existing`
- `Bonsai Server: running`

入力例:

```text
1万円以内で白く、静かな日本語配列のワイヤレスキーボード。
テンキー付きは避けたい。
```

「検索」を押すと、Bonsai属性抽出、Outscraper取得、正規化、採点を同期実行する。Outscraperが非同期タスクを処理している間は画面が待機する。

## 6. CLIで起動する

UIを使わず上位結果を標準出力する場合:

```sh
uv run python -m src.main.run \
  "1万円以内で白く、静かな日本語配列のワイヤレスキーボード"
```

上位5件だけ表示する場合:

```sh
uv run python -m src.main.run \
  "1万円以内で白く、静かな日本語配列のワイヤレスキーボード" \
  --display-limit 5
```

`--display-limit` は表示件数だけを変える。Outscraperへ要求する取得上限は `OUTSCRAPER_LIMIT` である。

既存キャッシュを読まず、BonsaiとOutscraperから再実行する場合:

```sh
uv run python -m src.main.run \
  "1万円以内で白く、静かな日本語配列のワイヤレスキーボード" \
  --no-cache
```

`--no-cache` はキャッシュ読込だけを無効にする。新しい結果は引き続き `cache/` へ保存され、外部APIの利用も発生する。

## 7. 正常動作の目印

CLIまたはStreamlitを起動したターミナルには、検索時に次の段階が表示される。

```text
Step 1/4: Bonsaiで商品属性を抽出します
Step 2/4: Outscraperへ渡す検索クエリを選択します
Step 3/4: OutscraperでAmazon商品候補を取得します
Step 4/4: 商品候補をスコアリングします
```

Outscraperの非同期タスクではrequest IDとポーリング回数・状態が表示される。標準の進捗出力はAPIキーを表示しない。成功後は各段階のJSONが `cache/` 配下へ保存される。

同じCLI入力と設定では `local-cli` scopeの有効なキャッシュを再利用する。Streamlitはセッションごとにランダムなscopeを作るため、別セッションの検索結果を通常操作で再利用しない。

## 8. 外部APIを使わない確認

コード変更後の基本確認は外部APIを呼ばない。

```sh
uv run ruff check .
uv run ruff format --check .
uv run pytest
uv lock --check
git diff --check
```

テストのモックと、実際のBonsai・Outscraperを使う結合確認は区別する。上記テストが成功しても、APIキー、モデル、ネットワーク、Outscraper契約が正しいことまでは保証しない。

## 9. 終了

StreamlitとBonsaiサーバーは、それぞれ起動したターミナルで `Ctrl+C` を押して終了する。

検索できない場合は [TROUBLESHOOTING.md](TROUBLESHOOTING.md) を参照する。画面操作は [UI.md](UI.md)、保存データと秘密情報の注意点は [SECURITY.md](SECURITY.md) を参照する。
