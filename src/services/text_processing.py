from typing import Any, Sequence
import re
from sudachipy import dictionary, tokenizer

# 日本語形態素解析器を作成
SUDACHI_TOKENIZER = dictionary.Dictionary().create()
# 解析の粒度を設定
SUDACHI_MODE = tokenizer.Tokenizer.SplitMode.C
CONTENT_PARTS_OF_SPEECH = {"名詞", "動詞", "形容詞", "形状詞"}
# 日本語判定の正規表現を変数に入れる
JAPANESE_CHARACTER_PATTERN = re.compile(r"[\u3040-\u30ff\u4e00-\u9fff]")
# 英語判定の正規表現を変数に入れる
ENGLISH_TOKEN_PATTERN = re.compile(r"[a-z0-9]+")


# あらゆる文字を小文字に正規化
def normalize_text(text: str) -> str:
    return text.casefold()


# SudachiPyで分割された各単語情報オブジェクトを正規化して文字列で返す
# normalized_form() : 正規化
# morpheme.surface() : 元の単語
def normalized_morpheme_text(morpheme: Any) -> str:
    normalized = morpheme.normalized_form()
    # 正規化ができなければ元の単語を返す
    if normalized == "*":
        normalized = morpheme.surface()
    return normalize_text(normalized).strip()


# SudachiPyで分割した各単語をTF-IDFに使う日本語トークンとして残すか判定する
# 単語が存在する かつ 単語情報オブジェクトの品詞情報が品詞リストに含まれる かつ 単語に日本語が含まれる
# part_of_speech() : 品詞情報をタプルで返す
def is_content_japanese_token(token: str, morpheme: Any) -> bool:
    return (
        bool(token)
        and morpheme.part_of_speech()[0] in CONTENT_PARTS_OF_SPEECH
        and bool(JAPANESE_CHARACTER_PATTERN.search(token))
    )


# 日本語テキストをSudachiPyで単語分割してリスト化する
# morpheme = 単語情報オブジェクト
def split_japanese_words(text: str) -> list[str]:
    japanese_tokens = []
    # SudachiPyで単語分割
    for morpheme in SUDACHI_TOKENIZER.tokenize(text, SUDACHI_MODE):
        # 各単語を正規化する
        token = normalized_morpheme_text(morpheme)
        # 各単語をTF-IDFに使う日本語トークンとして残すか判定する
        if is_content_japanese_token(token, morpheme):
            japanese_tokens.append(token)
    return japanese_tokens


# テキストの単語を分割してリストで返す
def split_words(text: str, *, dedupe: bool = True) -> list[str]:
    normalized = normalize_text(text)
    # 英数字の連続部分を取り出して単語分割してリスト化する
    english_tokens = ENGLISH_TOKEN_PATTERN.findall(normalized)
    # 日本語をSudachiPyで単語分割してリスト化する
    japanese_tokens = split_japanese_words(normalized)
    # 各リストの中身を取り出して結合する
    tokens = [*english_tokens, *japanese_tokens]

    # 重複を削除して返す
    if dedupe:
        return clean_dupe_empty(tokens)
    # 空のトークンを削除して返す
    return [token for token in tokens if token]


# その語句が対象テキストに含まれているか判定する
def term_matches_text(term: str, text: str) -> bool:
    normalized_term = normalize_text(term).strip()
    normalized_text = normalize_text(text)
    if not normalized_term:
        return False
    # 語句丸ごと入っているならTrue
    if normalized_term in normalized_text:
        return True

    # 語句を単語分割する
    term_words = split_words(normalized_term)
    if not term_words:
        return False
    # テキストを単語分割して重複を排除する
    text_words = set(split_words(normalized_text))
    # 単語分割した語句が全て含まれていればTrue
    return all(word in text_words for word in term_words)


# 配列の各要素の前後の空白を削除し, 重複する要素を消す
def clean_dupe_empty(values: Sequence[str | None]) -> list[str]:
    unique_values, seen = [], set()
    for value in values:
        if not value:
            continue
        normalized = value.strip()
        # 小文字化して重複判定する
        if not normalized or normalized.casefold() in seen:
            continue
        unique_values.append(normalized)
        seen.add(normalized.casefold())
    return unique_values


# 一度単語リストを空白区切りで結合し, 単語分割したあと, また空白区切りの文字列で返す
def build_tfidf_text(values: Sequence[str | None], *, dedupe: bool = True) -> str:
    # 空白を削除し重複を消す場合
    if dedupe:
        cleaned_values = clean_dupe_empty(values)
    # 空白を削除し重複を消さない場合
    else:
        cleaned_values = [value.strip() for value in values if value and value.strip()]

    joined_text = " ".join(cleaned_values)
    tokens = split_words(joined_text, dedupe=dedupe)
    return " ".join(tokens)
