from src.schemas import ProductAttributes


# 処理済みのbonsaiが返したJSONの検索クエリが空でないことと, URLでないことを確認する.
def validate_search_query(query: str) -> str:
    if not query:
        raise ValueError("Search query must not be empty.")
    if query.startswith(("http://", "https://")):
        raise ValueError("Pass a search query instead of an Amazon URL.")
    return query


# 処理済みJSONからOutscraperに渡す最も優先度の高い検索クエリを返す
def select_outscraper_query(attrs: ProductAttributes) -> str:
    if attrs.search_queries_ja:
        return validate_search_query(attrs.search_queries_ja[0])
    if attrs.search_queries_en:
        return validate_search_query(attrs.search_queries_en[0])
    # 検索クエリが存在しなければ自然言語をそのまま返す
    return validate_search_query(attrs.estimated_product_name_ja)
