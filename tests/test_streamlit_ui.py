from __future__ import annotations

from typing import Any

from src.ui import streamlit_ui


class SidebarSpy:
    def __init__(self) -> None:
        self.messages: list[str] = []
        self.json_payloads: list[dict[str, Any]] = []

    def header(self, message: str) -> None:
        self.messages.append(message)

    def caption(self, message: str) -> None:
        self.messages.append(message)

    def success(self, message: str) -> None:
        self.messages.append(message)

    def warning(self, message: str) -> None:
        self.messages.append(message)

    def json(self, payload: dict[str, Any]) -> None:
        self.json_payloads.append(payload)


def test_render_status_panel_debug_includes_all_weights_without_api_key(monkeypatch):
    sidebar = SidebarSpy()
    test_api_key = "test-api-key-must-not-be-rendered"
    monkeypatch.setattr(streamlit_ui.st, "sidebar", sidebar)
    monkeypatch.setattr(streamlit_ui.settings, "show_debug_info", True)
    monkeypatch.setattr(streamlit_ui.settings, "outscraper_api_key", test_api_key)
    monkeypatch.setattr(streamlit_ui, "bonsai_is_available", lambda: False)

    streamlit_ui.render_status_panel()

    assert len(sidebar.json_payloads) == 1
    assert set(sidebar.json_payloads[0]) == {
        "title_score_weight",
        "attribute_score_weight",
        "price_score_weight",
        "required_term_weight",
        "preferred_term_weight",
        "related_term_weight",
        "color_term_weight",
        "feature_term_weight",
    }
    rendered_output = repr((sidebar.messages, sidebar.json_payloads))
    assert "api_key" not in repr(sidebar.json_payloads).lower()
    assert test_api_key not in rendered_output


def test_format_price_handles_missing_and_thousands() -> None:
    assert streamlit_ui.format_price(None) == "価格不明"
    assert streamlit_ui.format_price(1_980) == "1,980円"


def test_format_rating_handles_missing_and_review_count() -> None:
    assert streamlit_ui.format_rating(None, 25) == "評価なし"
    assert streamlit_ui.format_rating(4.25, None) == "4.2"
    assert streamlit_ui.format_rating(4.25, 12_345) == "4.2 / 12,345件"
