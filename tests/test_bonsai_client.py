from unittest.mock import Mock
from unittest.mock import patch

import pytest
import requests

from src.clients.bonsai_client import call_bonsai
from src.clients.bonsai_client import extract_bonsai_content
from src.clients.bonsai_client import load_bonsai_prompt
from src.exceptions import BonsaiRequestError
from src.exceptions import BonsaiResponseError


def test_prompt_path_is_independent_of_current_directory(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)

    assert "商品属性抽出プロンプト" in load_bonsai_prompt()


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {},
        {"choices": []},
        {"choices": [{}]},
        {"choices": [{"message": {}}]},
        {"choices": [{"message": {"content": ""}}]},
    ],
)
def test_extract_bonsai_content_rejects_invalid_response_shape(payload):
    with pytest.raises(BonsaiResponseError):
        extract_bonsai_content(payload)


def test_call_bonsai_returns_valid_content():
    response = Mock()
    response.raise_for_status.return_value = None
    response.json.return_value = {"choices": [{"message": {"content": '{"ok": true}'}}]}

    with patch("src.clients.bonsai_client.requests.post", return_value=response):
        assert call_bonsai("キーボード") == '{"ok": true}'


def test_call_bonsai_wraps_request_error():
    with (
        patch(
            "src.clients.bonsai_client.requests.post",
            side_effect=requests.Timeout("timeout"),
        ),
        pytest.raises(BonsaiRequestError),
    ):
        call_bonsai("キーボード")


def test_call_bonsai_rejects_invalid_json():
    response = Mock()
    response.raise_for_status.return_value = None
    response.json.side_effect = ValueError("invalid")

    with (
        patch("src.clients.bonsai_client.requests.post", return_value=response),
        pytest.raises(BonsaiResponseError, match="invalid JSON"),
    ):
        call_bonsai("キーボード")
