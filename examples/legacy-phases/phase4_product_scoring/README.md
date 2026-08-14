# 第四段階：商品名類似度、属性類似度、価格スコア計算

## 1. 目的

第四段階では、第三段階で正規化したAmazon商品候補に対して、第一段階で抽出した商品属性との一致度を計算し、ランキング用の総合スコアを付与する。

この段階では、Outscraper APIへのリクエスト、Streamlit UI、ComfyUI連携、embeddingによる高精度な類似度計算は実装対象外とする。

対象範囲は以下に限定する。

```text
商品属性JSON
  ↓
正規化済み商品候補JSON
  ↓
SudachiPy単語分割
  ↓
TF-IDFによる商品名類似度 + 属性類似度 + 価格スコア
  ↓
スコア付き商品候補JSON
```

## 2. サンプルデータ

第三段階の正規化済みデータをもとに、サンプル用のダミー商品候補を以下に用意している。

```text
cache/outscraper/amazon_products_normalized_dummy.json
```

第一段階の商品属性抽出結果を想定したダミー属性は以下に用意している。

```text
cache/product_attributes/product_attributes_dummy.json
```

## 3. 実行方法

依存パッケージを入れる。

```sh
uv sync
```

サンプルデータでスコアを計算する。

```sh
uv run python phase4_product_scoring/score_products.py
```

入力ファイルを指定して実行することもできる。

```sh
uv run python phase4_product_scoring/score_products.py \
  --attributes cache/product_attributes/product_attributes_dummy.json \
  --products cache/outscraper/amazon_products_normalized_dummy.json
```

スコア結果をファイルに保存する場合は `--output` を指定する。

```sh
uv run python phase4_product_scoring/score_products.py \
  --output cache/outscraper/amazon_products_scored_sample.json
```

## 4. スコア設計

標準の重みは以下とする。

| 項目 | 重み | 内容 |
|---|---:|---|
| 商品名類似度 | `0.45` | 推定商品名、カテゴリ、ランキング語と商品名のTF-IDF類似度 |
| 属性類似度 | `0.35` | 色、カテゴリ、特徴、ランキング語と商品テキストのTF-IDF類似度 |
| 価格スコア | `0.20` | 上限価格または価格嗜好に合うか |

第一段階の商品属性JSONに以下のランキング語が含まれる場合は、TF-IDFクエリ内で重み付けする。

| 項目 | 繰り返し回数 | 内容 |
|---|---:|---|
| `required_terms_ja` / `required_terms_en` | `3` | 商品種別など必須に近い語 |
| `preferred_terms_ja` / `preferred_terms_en` | `2` | 色、形状、機能など重視したい語 |
| `related_terms_ja` / `related_terms_en` | `1` | 略語や言い換えなど補助的な語 |

除外条件に一致する語がある場合は、総合スコアから減点する。

```text
total_score =
  title_similarity * 0.45
  + attribute_similarity * 0.35
  + price_score * 0.20
  - negative_penalty
```

## 5. 完了条件

- 正規化済み商品候補JSONを読み込める
- 商品属性JSONを読み込める
- 商品名類似度、属性類似度、価格スコアを計算できる
- 除外条件に一致する商品を減点できる
- 総合スコア順に商品候補を並べ替えられる

## 6. 関数詳細

### モデルと入出力

#### `string_list()`

Pydanticモデルでリスト型フィールドのデフォルト値を作る補助関数。`Field(default_factory=list)` を返し、属性やスコア結果ごとに独立したリストを持てるようにする。

#### `SearchAttributes`

第一段階の商品属性JSONを受け取るPydanticモデル。推定商品名、カテゴリ、色、特徴、除外条件、検索クエリ、ランキング用語、価格嗜好、上限価格を保持する。

第四段階では、商品名類似度、属性類似度、価格スコア、除外条件の計算に使う。

#### `ProductScore`

商品1件のスコア結果を表すPydanticモデル。商品識別情報に加えて、商品名類似度、属性類似度、価格スコア、除外ペナルティ、総合スコア、マッチした語、欠落した語、除外条件に一致した語を保持する。

#### `read_json(path)`

指定したJSONファイルをUTF-8で読み込み、Pythonオブジェクトとして返す。属性JSONと正規化済み商品候補JSONの読み込みに使う。

#### `write_json(path, data)`

スコア付き商品候補をJSONファイルへ保存する。親ディレクトリがない場合は作成し、UTF-8、インデント付き、非ASCII文字を読める形式で出力する。

### テキスト正規化と単語分割

#### `normalize_text(text)`

文字列を `casefold()` で小文字化する。英語の大文字小文字差を吸収し、日本語や記号を含む文字列でも比較しやすくする。

#### `normalized_morpheme_text(morpheme)`

SudachiPyの形態素から正規化済みの表記を取り出す。`normalized_form()` が `*` の場合は `surface()` を使い、最後に `normalize_text()` と `strip()` を適用する。

#### `is_content_japanese_token(token, morpheme)`

形態素がランキングに使う日本語トークンかを判定する。空文字を除外し、品詞が名詞、動詞、形容詞、形状詞のいずれかで、ひらがな、カタカナ、漢字を含む場合に `True` を返す。

#### `split_japanese_words(text)`

SudachiPyで日本語を分割し、`is_content_japanese_token()` を通った語だけを返す。助詞や記号など、ランキングに使いにくい語はここで落とす。

#### `split_words(text, dedupe)`

英数字トークンと日本語トークンをまとめて取り出す。英語は正規表現、日本語は `split_japanese_words()` を使う。

`dedupe=True` の場合は `unique_non_empty()` で重複を除き、`dedupe=False` の場合はランキング語の重み付けのために重複を残す。

#### `term_matches_text(term, text)`

検索語や除外語が商品テキストに含まれるかを判定する。まず正規化文字列として部分一致を確認し、部分一致しない場合は単語分割して、語をすべて含むかを確認する。

例として、`wireless earbuds` は `Black wireless compact earbuds` に一致する。

#### `unique_non_empty(values)`

空値と大文字小文字違いの重複を除き、入力順を保った文字列リストを返す。クエリ語、属性語、除外語などの整理に使う。

### クエリ語と商品テキストの構築

#### `build_title_query_terms(attrs)`

商品名類似度に使う基本語を作る。英語推定商品名、日本語推定商品名、英語カテゴリ、日本語カテゴリを重複除去して返す。

#### `build_attribute_terms(attrs)`

属性一致の確認に使う語を作る。色、カテゴリ、英語特徴、日本語特徴を重複除去して返す。

#### `repeat_terms(terms, weight)`

語句を指定回数だけ繰り返す。TF-IDFクエリ内で重要語の影響を強めるために使う。

#### `build_weighted_ranking_terms(attrs)`

第一段階で抽出したランキング用語を重み付きで展開する。`required_terms` は3回、`preferred_terms` は2回、`related_terms` は1回繰り返す。

#### `build_negative_terms(attrs)`

除外条件の英語語句と日本語語句をまとめ、重複を除いて返す。`calculate_negative_penalty()` で使う。

#### `product_text_parts(product)`

商品辞書から、タイトル、ストア名、カテゴリ、説明文を取り出す。カテゴリがリストの場合は空白区切りの文字列にする。

#### `combined_product_text(product)`

`product_text_parts()` の結果から空文字を除き、1つの商品テキストに結合する。属性類似度や除外条件判定に使う。

#### `build_tfidf_text(values, dedupe)`

複数の文字列を結合し、`split_words()` でTF-IDFに渡すための空白区切りトークン列へ変換する。

`dedupe=False` の場合は重み付きランキング語の繰り返しを残す。

#### `build_title_query_text(attrs)`

商品名類似度用のTF-IDFクエリ文字列を作る。基本の商品名・カテゴリ語に、重み付きランキング語を加える。

#### `build_attribute_query_text(attrs)`

属性類似度用のTF-IDFクエリ文字列を作る。色、カテゴリ、特徴に、重み付きランキング語を加える。

#### `build_product_tfidf_text(product)`

商品全体テキストをTF-IDF用のトークン列へ変換する。属性類似度の文書側テキストとして使う。

#### `build_product_title_tfidf_text(product)`

商品タイトルだけをTF-IDF用のトークン列へ変換する。商品名類似度の文書側テキストとして使う。

### スコア計算

#### `calculate_tfidf_similarities(query_text, document_texts)`

クエリ文字列と複数の商品文書文字列のTF-IDFコサイン類似度を計算する。クエリまたは文書が空の場合は0点を返す。

`TfidfVectorizer` は、すでに分割済みの空白区切りトークン列を使うため、`token_pattern` を広めに設定し、`lowercase=False` にしている。

#### `calculate_term_match_score(terms, text)`

指定した語句リストのうち、商品テキストに一致した語と一致しなかった語を求める。戻り値は、マッチ率、マッチした語、欠落した語のタプルとする。

#### `calculate_title_similarity(attrs, product)`

商品名類似度を1商品分だけ計算する。`build_title_query_text()` と `build_product_title_tfidf_text()` を使い、TF-IDF類似度を1つ返す。

#### `calculate_attribute_similarity(attrs, product)`

属性類似度を1商品分だけ計算する。商品全体テキストに対して、属性語のマッチ状況とTF-IDF類似度を求める。

戻り値は、属性類似度、マッチした属性語、欠落した属性語のタプルとする。

#### `calculate_price_score(attrs, product)`

価格スコアを計算する。価格がない場合や0以下の場合は0点とする。

`max_price_jpy` がある場合、上限価格以下なら1点、上限超過なら超過率に応じて減点する。上限価格がない場合は、`price_preference` が `cheap` なら安いほど高く、`premium` なら高価格寄りほど高く、指定なしなら0.5点にする。

#### `calculate_negative_penalty(attrs, product)`

除外条件に一致した語を探し、総合スコアから引くペナルティを計算する。1語一致ごとに0.2点、最大0.5点まで減点する。

戻り値は、ペナルティ値と一致した除外語のタプルとする。

#### `score_product(attrs, product, title_similarity, attribute_similarity, title_weight, attribute_weight, price_weight)`

商品1件に対して最終的な `ProductScore` を作る。商品名類似度、属性類似度、価格スコア、除外ペナルティを組み合わせ、0から1の範囲に丸めた `total_score` を計算する。

`title_similarity` と `attribute_similarity` が渡された場合はそれを再利用し、未指定の場合はこの関数内で計算する。

#### `score_products(attrs, products)`

複数の商品候補をまとめてスコアリングする。商品名類似度と属性類似度は、商品ごとに個別計算せず、`calculate_tfidf_similarities()` でまとめて計算する。

各商品を `score_product()` で `ProductScore` に変換し、`total_score` の降順で返す。

### CLI

#### `parse_args()`

CLI引数を定義する。第一段階の商品属性JSON、第三段階の正規化済み商品候補JSON、出力先JSONを受け取る。

#### `main()`

CLI実行時の入口。属性JSONを `SearchAttributes` として検証し、商品候補JSONがリストであることを確認する。その後 `score_products()` でスコアリングし、`--output` があればファイルへ保存し、なければ標準出力へ表示する。
