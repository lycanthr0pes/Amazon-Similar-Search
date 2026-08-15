# フロントエンド設計

## 1. 目的と対象

amazon-explorer のフロントエンドは Streamlit で実装されている。利用者の自然文入力を受け取り、バックエンドの検索パイプラインを同期実行し、採点済みの商品候補を順位順に表示する。

この文書は現行の `app.py` と `src/ui/streamlit_ui.py` を正として、画面構成、状態管理、バックエンドとの境界、拡張時の規約を定義する。画面上の文言と操作仕様は [UI.md](UI.md)、検索処理の内部構成は [BACKEND.md](BACKEND.md)を参照する。

## 2. エントリーポイント

```text
uv run streamlit run app.py
  -> app.py
  -> src.ui.streamlit_ui.main()
```

`app.py` は `main()` の呼出しだけを担う。ページ設定、ウィジェット、状態管理、表示処理は `src/ui/streamlit_ui.py` に置く。検索、外部API通信、正規化、採点をUIへ実装しない。

## 3. 画面構成

ページは `layout="wide"` を使い、次の領域で構成する。

```text
ページ
├── サイドバー
│   ├── Bonsai接続先
│   ├── Amazonドメイン・言語・取得件数
│   ├── Outscraper APIキー設定状態
│   ├── Bonsai稼働状態
│   ├── 表示件数スライダー
│   └── スコア重み（SHOW_DEBUG_INFO=true の場合だけ）
└── メイン領域
    ├── タイトル
    ├── 自然文入力フォーム
    ├── 実行中スピナーまたはメッセージ
    └── 商品結果カード
```

主な表示関数:

| 関数 | 責務 |
|---|---|
| `main()` | ページ全体、状態初期化、フォーム送信、検索呼出し |
| `render_status_panel()` | 接続先と設定状態をサイドバーへ表示 |
| `render_results()` | 件数表示と上位商品の反復表示 |
| `render_product()` | 画像、スコア、価格、評価、条件、商品リンクを1件分表示 |
| `render_terms()` | 条件語の一覧を区切り文字付きで表示 |
| `format_price()` | 円価格または「価格不明」へ整形 |
| `format_rating()` | 評価とレビュー件数を表示用文字列へ整形 |

## 4. 状態管理

永続的なフロントエンド状態には `st.session_state` を使う。

| キー | 型 | 初期値 | 用途 |
|---|---|---|---|
| `scored_products` | `list[ProductScore]` | `[]` | 最後に成功した検索結果を再実行間で保持する |
| `cache_scope` | `str` | `secrets.token_hex(16)` | バックエンドのキャッシュキーをセッションごとに分離する |

`cache_scope` は同一セッション中は維持され、別のStreamlitセッションでは異なる。これはキャッシュキーの衝突を避けるための値であり、ユーザーID、認証情報、秘密情報ではない。キャッシュファイルの保存ルート自体は共通である。

Bonsaiの疎通確認は `@st.cache_data(ttl=5, show_spinner=False)` を付けた `bonsai_is_available()` で5秒間だけ再利用する。商品検索結果そのものにStreamlitの共有キャッシュは使わない。

### 4.1 再実行時の挙動

Streamlitはウィジェット操作ごとにスクリプトを再実行する。表示件数を変更しても `scored_products` は残るため、外部APIを再実行せず表示件数だけを変えられる。検索失敗時は新しい結果を代入しないため、すでに成功結果があればその結果が画面下部に残る。

## 5. イベントとデータフロー

```text
利用者が検索フォームを送信
  -> 前後空白を除いた入力が空か確認
  -> スピナーを表示
  -> run_product_search(user_input, cache_scope=session_scope)
  -> list[ProductScore] を session_state へ保存
  -> 表示上限まで結果カードを描画
```

フォーム未送信時は外部処理を行わない。空白だけの入力では警告を表示し、バックエンドを呼ばない。

現行処理は同期実行である。Bonsai呼出し、Outscraperタスク作成とポーリング、正規化、採点が終わるまで同じStreamlit実行が待機する。ジョブID表示、段階別の進捗率、キャンセル、バックグラウンド継続は実装されていない。

## 6. バックエンド境界

UIが直接呼ぶ公開境界は次である。

```python
run_product_search(
    user_input: str,
    *,
    use_cache: bool = True,
    cache_scope: str = "local-cli",
) -> list[ProductScore]
```

Streamlitは `use_cache` を指定しないため、`ENABLE_CACHE` が真ならキャッシュを読む。返却値は総合スコア降順の `ProductScore` リストであり、UIは外部APIの生レスポンスや正規化前データへ依存しない。

UIは設定状態の表示にグローバルな `settings`、Bonsaiの疎通確認に `is_bonsai_running()` を参照する。それ以外のBonsai・Outscraperクライアント、キャッシュリポジトリ、採点サービスを直接呼ばない。

## 7. エラー境界

検索中に発生した例外はUI層で型を問わず捕捉する。

- サーバーログ: `LOGGER.exception("Product search failed")` でスタックトレースを記録する
- 利用者画面: 「検索に失敗しました。設定と外部サービスの状態を確認してください。」という固定文言を表示する

画面へAPIキー、外部レスポンス本文、内部パス、スタックトレースを直接表示しない。運用者が原因を調べる手順は [TROUBLESHOOTING.md](TROUBLESHOOTING.md)、秘密情報の扱いは [SECURITY.md](SECURITY.md)を参照する。

## 8. 設定境界

UIが参照する設定は次のとおりである。

| 設定 | 現行の用途 |
|---|---|
| `BONSAI_BASE_URL` | 接続先表示と疎通確認 |
| `OUTSCRAPER_API_KEY` | 値そのものではなく、設定済みかどうかだけを表示 |
| `OUTSCRAPER_DOMAIN` | 対象Amazonドメインの表示 |
| `OUTSCRAPER_LANGUAGE` | 言語の表示 |
| `OUTSCRAPER_LIMIT` | 外部APIの取得上限表示 |
| `SEARCH_RESULT_DISPLAY_LIMIT` | 表示件数スライダーの初期値 |
| `SHOW_DEBUG_INFO` | サイドバーへ重みを表示するか |

表示件数は画面上で1件から30件まで選択できる。初期値は `min(SEARCH_RESULT_DISPLAY_LIMIT, 30)` である。Outscraperの取得件数とは別の設定であり、表示件数を減らしても外部APIの取得上限は減らない。

## 9. セキュリティとプライバシー

- APIキーの値は表示しない。「existing」または「missing」だけを表示する
- 検索条件はBonsaiとOutscraperへ送られ、抽出属性と商品結果はローカルの `cache/` に保存され得る
- セッションscopeは画面に表示せず、認証トークンとして使わない
- 商品画像と商品リンクは外部由来のURLである。現行モデルはこれらのURLスキームやホストを厳密に制限していない
- Streamlitの利用者認証、認可、レート制限、利用者別の永続保存領域は未実装である

外部公開する前に必要な対策は [SECURITY.md](SECURITY.md) と [CONSTRAINTS.md](CONSTRAINTS.md) を参照する。

## 10. 現在の制約

- 長時間のOutscraper待機中も画面要求を占有する
- 進捗表示は単一のスピナーだけで、現在段階や残り時間を画面へ出さない
- 検索のキャンセル、履歴、比較、お気に入り、ページネーションはない
- 接続状態はBonsaiだけをHTTP確認し、OutscraperはAPIキーの有無だけを確認する
- スコア重みは表示できるが、画面から変更できない
- レスポンシブ表示はStreamlitの標準挙動に依存する
- UI専用の自動テスト、キーボード操作試験、スクリーンリーダー試験は未整備である

これらは現行機能として扱わず、実装する場合は [TECH-DEBT-TRACKER.md](TECH-DEBT-TRACKER.md) と [TASKS.md](TASKS.md) で優先順位を管理する。

## 11. 変更規約

1. UIは `ProductScore` だけに依存し、外部API固有の辞書構造を持ち込まない
2. 検索ロジックを追加せず、`src/main/run.py` またはサービス層へ置く
3. エラー詳細を利用者へそのまま表示しない
4. 新しいセッション状態には初期値、型、寿命を明記する
5. 表示文言を変更したら [UI.md](UI.md) と関連テストを同じ変更で更新する
6. 新しい設定を参照したら `.env.example` と設定資料を更新する
7. UI変更後は少なくともStreamlit起動確認、Ruff、テスト、Markdownリンク確認を行う

## 12. 確認コマンド

```sh
uv run streamlit run app.py --server.headless true
uv run ruff check .
uv run ruff format --check .
uv run pytest
git diff --check
```

実検索はBonsaiの起動とOutscraper APIキーを必要とし、Outscraperの利用料金が発生し得る。単なる画面起動確認では検索ボタンを押さない。
