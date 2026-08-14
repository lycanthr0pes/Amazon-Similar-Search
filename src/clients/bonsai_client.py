import requests
from typing import Any

from requests import RequestException

from src.config import settings
from src.exceptions import BonsaiRequestError
from src.exceptions import BonsaiResponseError


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


def extract_bonsai_content(data: object) -> str:
    if not isinstance(data, dict):
        raise BonsaiResponseError("Bonsai response must be a JSON object")
    choices = data.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        raise BonsaiResponseError("Bonsai response does not include a valid choices list")
    message = choices[0].get("message")
    if not isinstance(message, dict):
        raise BonsaiResponseError("Bonsai response does not include a valid message")
    content = message.get("content")
    if not isinstance(content, str) or not content.strip():
        raise BonsaiResponseError("Bonsai response content must be a non-empty string")
    return content


# bonsaiを呼び出し, 自然言語入力の返り値として商品属性JSONを取得する
# user_input: ユーザによる自然言語入力
def call_bonsai(user_input: str) -> str:
    try:
        response = requests.post(
            f"{settings.bonsai_base_url}/chat/completions",
            json=build_bonsai_payload(user_input),
            timeout=settings.bonsai_timeout_seconds,
        )
        response.raise_for_status()
    except RequestException as exc:
        raise BonsaiRequestError("Bonsai request failed") from exc

    try:
        data = response.json()
    except ValueError as exc:
        raise BonsaiResponseError("Bonsai returned invalid JSON") from exc
    return extract_bonsai_content(data)


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
