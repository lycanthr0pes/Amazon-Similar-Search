# キャッシュ設計

## 1. 目的

現行実装は検索の各段階をローカルJSONへ保存し、同じscope・入力・設定に対するBonsai、Outscraper、正規化、採点を再利用する。

キャッシュルートは `CACHE_DIR` で指定し、既定値はプロジェクト内の `cache/` である。`cache/` は `.gitignore` 対象である。

## 2. 保存先

```text
cache/
  product_attributes/
    <attributes_key>.json
  outscraper/
    raw/
      <raw_key>.json
    normalized/
      <normalized_key>.json
    scored/
      <scored_key>.json
```

| namespace | 内容 | 再利用条件 |
|---|---|---|
| `product_attributes` | `ProductAttributes.model_dump()` | キー一致かつLLM TTL内 |
| `outscraper/raw` | Outscraper成功応答 | キー一致かつOutscraper TTL内 |
| `outscraper/normalized` | `NormalizedAmazonProduct[]` | キー一致、JSON正常、モデル検証成功 |
| `outscraper/scored` | `ProductScore[]` | キー一致、JSON正常、モデル検証成功 |

## 3. scopeによる分離

各段階のキーは `cache_scope` を直接または前段キー経由で含む。

- Streamlitはセッション開始時に `secrets.token_hex(16)` でランダムscopeを作る
- 同一Streamlitセッション内では同じscopeを再利用する
- 別セッションは同じ検索内容でも別キーになる
- CLIとscope未指定のPython呼出は `local-cli` を使う
- scopeは空文字を禁止し、最大128文字である

ファイルのルートディレクトリ自体は共通である。scopeは認証ユーザーIDや永続アカウント領域ではない。

## 4. キー材料

キー材料をキー名順のコンパクトJSONへ直し、SHA-256の16進表現の先頭24桁を使う。

### 4.1 属性抽出

- 種別とキャッシュ版
- cache scope
- 正規化した利用者入力
- Bonsai base URLとモデル
- systemプロンプトのSHA-256
- temperatureとmax tokens

### 4.2 Outscraper生レスポンス

- 種別
- cache scope
- 検索語
- endpoint、domain、language、postal code、limit

APIキーは含めない。

### 4.3 正規化

- 種別とキャッシュ版
- cache scope
- USDからJPYへの換算レート
- Outscraper生レスポンス全体

### 4.4 採点

- 種別とキャッシュ版
- `ProductAttributes` 全体
- 正規化キャッシュキー
- 商品名、属性、価格の総合係数
- 必須語、色、特徴語、優先語、関連語の重み

正規化キーがscopeを含むため、採点キーもscopeごとに分離される。

## 5. TTL

| 対象 | 環境変数 | 既定値 |
|---|---|---:|
| 属性抽出 | `LLM_CACHE_TTL_SECONDS` | 86400秒 |
| Outscraper生レスポンス | `OUTSCRAPER_CACHE_TTL_SECONDS` | 3600秒 |

正規化・採点は入力内容と実装版からキーを作るため、読込時のTTLを指定しない。期限切れファイルも現時点では自動削除しない。

`ENABLE_CACHE=false`、CLIの `--no-cache`、`run_product_search(use_cache=False)` はキャッシュ読込を無効にする。新しい結果は引き続き保存する。

## 6. 読み書き

`JsonCacheRepository` はrootを絶対パスへ解決し、namespaceが絶対パスまたは `..` を含む場合に拒否する。キーは空でない小文字16進数だけを許可する。

保存時は同じディレクトリへ一時ファイルを作り、次の順で処理する。

1. UTF-8、インデント2でJSONを書き込む
2. flushと `fsync` を行う
3. `Path.replace()` で目的ファイルへ置換する
4. 失敗時に残った一時ファイルを削除する

リポジトリ経由の読込では、ファイル不在、TTL超過、OSエラー、Unicodeエラー、JSON不正をキャッシュミスとして扱う。Pydanticモデルの検証に失敗した属性・正規化・採点データも再計算する。

Outscraper生レスポンスは有効期限内パスを取得後に読み込むため、破損時の専用隔離は現時点でない。

## 7. セキュリティとプライバシー

キャッシュには次が保存され得る。

- 利用者入力から抽出した商品属性
- Outscraperの生レスポンス
- 商品URL、画像URL、価格、評価
- 一致・不足・否定条件

APIキーはキーとpayloadへ含めない。Streamlitのランダムscopeにより通常の画面操作で別セッションの結果を再利用しないが、同じファイルシステムへ保存するためOS権限による保護は必要である。

- `cache/` をGit、公開Webルート、不要なバックアップへ含めない
- 共有ホストではディレクトリ権限を制限する
- scopeを秘密情報や認証トークンとして扱わない
- 実キャッシュ内容をログや完了報告へ貼り付けない

## 8. 現在の制約

- プロセス間ファイルロックがない
- 容量上限と自動削除がない
- 正規化・採点ファイルに時間ベースの期限がない
- 認証ユーザー単位の永続名前空間がない
- キャッシュpayloadを包むスキーマ版・作成時刻・期限の共通エンベロープがない
- 破損ファイルの隔離と運用通知がない

## 9. 設計候補（未実装）

本番要件に応じて次を検討する。

1. 認証ユーザーまたはテナント単位の保存ルート
2. 容量上限、最終利用時刻、定期削除
3. 共通エンベロープによるスキーマ版・作成時刻・期限の明示
4. 複数ワーカー向けのロック、DB、オブジェクトストレージ
5. キャッシュヒット率、破損、削除件数のメトリクス
6. 機微な検索条件の暗号化または非保存モード

## 10. 確認

```sh
git check-ignore -v cache/
uv run pytest tests/test_cache_repository.py tests/test_run_pipeline.py
```

実キャッシュの中身には利用者データが含まれ得るため、確認時も値を不用意に出力しない。
