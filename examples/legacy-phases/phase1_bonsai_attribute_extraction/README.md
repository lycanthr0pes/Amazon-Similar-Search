# 第一段階：自然言語入力から商品属性抽出

## 1. 目的

第一段階では、ユーザーの自然言語入力をBonsaiなどのOpenAI互換ローカルLLMへ渡し、Amazon検索や後続ランキングで使う商品属性JSONへ変換する。

この段階では、Outscraper APIへのリクエスト、商品候補正規化、ランキング、UI、ComfyUI連携は実装対象外とする。

対象範囲は以下に限定する。

```text
自然言語入力
  ↓
Bonsai OpenAI互換API
  ↓
商品属性JSON
  ↓
Outscraper検索用パラメータ候補
```

Bonsaiや `llama-server` の導入手順は `PREREQUISITES.md` を参照する。

## 2. 実行方法

依存パッケージを入れる。

```sh
uv sync
```

BonsaiのOpenAI互換サーバを起動した状態で実行する。

```sh
uv run python phase1_bonsai_attribute_extraction/extract_product_attributes.py
```

利用する環境変数は以下とする。

```env
BONSAI_BASE_URL=http://127.0.0.1:8080/v1
BONSAI_MODEL=Bonsai-8B.gguf
```

未設定の場合は、サンプルコード内の標準値を使う。

## 3. 出力モデル

`ProductAttributes` は、LLMから受け取った商品属性を検証するPydanticモデルである。

主な項目は以下とする。

| 項目 | 内容 |
|---|---|
| `estimated_product_name_ja` | 日本語の推定商品名。必須 |
| `estimated_product_name_en` | 英語の推定商品名 |
| `category_ja` / `category_en` | 商品カテゴリ |
| `color_ja` / `color_en` | 主要な色 |
| `features_ja` / `features_en` | 商品特徴 |
| `negative_conditions_ja` / `negative_conditions_en` | 除外したい条件 |
| `search_queries_ja` / `search_queries_en` | Amazon検索クエリ候補 |
| `required_terms_ja` / `required_terms_en` | ランキングで強く重視する語 |
| `preferred_terms_ja` / `preferred_terms_en` | ランキングで中程度に重視する語 |
| `related_terms_ja` / `related_terms_en` | ランキングで補助的に使う語 |
| `image_prompt` | 画像生成用の英語プロンプト |
| `price_preference` | `cheap`、`premium`、`none` の価格嗜好 |
| `max_price_jpy` | 上限価格 |

## 4. 関数詳細

### `string_list()`

Pydanticモデルでリスト型フィールドのデフォルト値を作るための補助関数。`Field(default_factory=list)` を返し、複数インスタンス間で同じリストを共有しないようにする。

### `call_bonsai(user_input)`

`.env` を読み込み、`BONSAI_BASE_URL` の `/chat/completions` にHTTP POSTする。`build_bonsai_payload()` で作ったOpenAI互換リクエストを送り、レスポンスの `choices[0].message.content` を文字列として返す。

HTTPエラーは `raise_for_status()` で例外にする。戻り値はまだ検証前のLLM生レスポンスであり、JSONとして正しいとは限らない。

### `build_bonsai_payload(user_input)`

Bonsaiへ送るリクエスト本文を作る。モデル名、system prompt、ユーザー入力、temperature、max_tokens を含む辞書を返す。

モデル名は `BONSAI_MODEL` があればそれを使い、未設定の場合は `Bonsai-8B.gguf` を使う。

### `normalize_bonsai_json(data)`

LLMのJSON出力をPydantic検証前に補正する。リストであるべき項目が `null` の場合は `[]` にし、文字列の場合は1要素のリストに変換する。

`max_price_jpy` が文字列で返った場合、数字だけなら `int` に変換し、数値化できない場合は `None` にする。

### `has_japanese_category_evidence(category, evidence_parts)`

日本語カテゴリが、推定商品名や特徴などの根拠テキストに含まれているかを確認する。LLMが根拠の薄いカテゴリを推測した場合に除外するために使う。

### `english_words(text)`

英語テキストを小文字化し、ハイフンを空白扱いにして単語集合へ変換する。3文字以下の語は照合ノイズになりやすいため除外する。

### `has_english_category_evidence(category, evidence_parts)`

英語カテゴリの単語が、推定商品名や特徴などの根拠テキストにすべて含まれているかを確認する。日本語カテゴリと同じく、根拠の薄いカテゴリを除外するために使う。

### `clean_categories(attrs)`

`category_ja` と `category_en` を検証し、商品名や特徴から根拠を確認できないカテゴリを `None` にする。`ProductAttributes` をその場で更新する。

### `unique_non_empty(values)`

空文字、`None`、大文字小文字違いの重複を除き、入力順を保った文字列リストを返す。検索クエリを作るときに同じ語が繰り返されないように使う。

### `contains_japanese(text)`

ひらがな、カタカナ、漢字が含まれているかを判定する。日本語検索クエリに英語だけの語を混ぜすぎないための補助関数。

### `japanese_query_part(value)`

値が空でなく、日本語文字を含む場合だけその値を返す。条件に合わない場合は `None` を返す。

### `improve_search_queries(attrs)`

推定商品名、色、特徴、カテゴリを使って検索クエリを再構築する。日本語要素があれば `search_queries_ja` を1件の検索語に置き換え、英語要素があれば `search_queries_en` を小文字の1件に置き換える。

### `select_outscraper_query(attrs)`

Outscraperへ渡す検索語を選ぶ。優先順位は `search_queries_ja` の先頭、`search_queries_en` の先頭、`estimated_product_name_ja` の順とする。

### `build_outscraper_amazon_params(attrs, limit)`

第一段階の属性からOutscraper Amazon Products Scraper向けのクエリパラメータを作る。`query`、`domain`、`language`、`limit`、`async` を含む辞書を返す。

### `build_outscraper_amazon_url(attrs, endpoint, limit)`

`build_outscraper_amazon_params()` の結果をURLエンコードし、Outscraper APIの確認用URLを組み立てる。実際のAPIキーは含めない。

### `parse_attributes(raw_text, fallback_query)`

Bonsaiの生レスポンスをJSONとして読み込み、`normalize_bonsai_json()` で補正し、`ProductAttributes` として検証する。JSONが壊れている場合やスキーマに合わない場合は、元レスポンスを含む `ValueError` を送出する。

検索語が空の場合は `fallback_query` や `estimated_product_name_en` を使って最低限の検索語を補う。その後、カテゴリ検証と検索クエリ改善を実行する。

### `extract_product_attributes(user_input)`

第一段階のメイン処理。自然言語入力を `call_bonsai()` に渡し、返ってきたテキストを `parse_attributes()` で検証済みの `ProductAttributes` に変換する。

## 5. 完了条件

- Bonsai local serverへHTTP接続できる
- 自然言語入力からJSONのみを取得できる
- Pydanticで商品属性スキーマを検証できる
- 後続のOutscraper検索に使う検索語を1件以上作れる
- JSONが壊れた場合に失敗理由を明示できる
