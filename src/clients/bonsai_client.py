from dotenv import load_dotenv
from src.config import settings
import requests
from requests import RequestException
from typing import Any


# プロンプトをロード
def load_bonsai_prompt() -> str:
    return settings.bonsai_prompt_path.read_text(encoding="utf-8")


# bonsaiに渡すJSONを組み立てる
def build_bonsai_payload(user_input: str) -> dict[str, Any]:
    return {
        "model": settings.bonsai_model,
        "messages": [
            {"role": "system", "content": load_bonsai_prompt()},
            {"role": "user", "content": user_input},
        ],
        "temperature": settings.bonsai_temperature,
        "max_tokens": settings.bonsai_max_tokens,
    }


# bonsaiを呼び出し, 自然言語入力の返り値として商品属性JSONを取得する
# user_input: ユーザによる自然言語入力
def call_bonsai(user_input: str) -> str:
    load_dotenv()
    response = requests.post(
        f"{settings.bonsai_base_url}/chat/completions",
        json=build_bonsai_payload(user_input),
        timeout=settings.bonsai_timeout_seconds,
    )
    # HTTPリクエストが失敗したら例外を出す
    response.raise_for_status()
    data = response.json()
    # /chat/completionsに沿う
    return data["choices"][0]["message"]["content"]

# Bonsaiサーバの疎通確認(if 200 OK -> True else -> False)
def is_bonsai_running() -> bool:
    try:
        response = requests.get(
            f"{settings.bonsai_base_url}/models",
            timeout=3,
        )
        return response.ok
    except RequestException:
        return False