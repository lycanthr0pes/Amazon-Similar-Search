from typing import Any


class BonsaiError(RuntimeError):
    """Bonsai連携で発生する例外の基底クラス。"""


class BonsaiRequestError(BonsaiError):
    """BonsaiへのHTTPリクエストが完了できなかった場合の例外。"""


class BonsaiResponseError(BonsaiError):
    """Bonsaiから解釈できないレスポンスを受け取った場合の例外。"""


class OutscraperError(RuntimeError):
    """Outscraper連携で発生する例外の基底クラス。"""


class OutscraperRequestError(OutscraperError):
    """OutscraperへのHTTPリクエストが完了できなかった場合の例外。"""


class OutscraperResponseError(OutscraperError):
    """Outscraperから解釈できないレスポンスを受け取った場合の例外。"""


class OutscraperSecurityError(OutscraperError):
    """APIキーを安全に送信できないURLが指定された場合の例外。"""


class OutscraperTaskFailedError(OutscraperError):
    """Outscraper側で検索タスクが失敗した場合の例外。"""

    def __init__(self, status: str, response_data: dict[str, Any]) -> None:
        self.status = status
        self.response_data = response_data
        detail = response_data.get("description") or response_data.get("message") or "No details"
        super().__init__(f"Outscraper task failed with status '{status}': {detail}")


class OutscraperTaskTimeoutError(OutscraperError):
    """Outscraperの検索タスクが規定回数内に完了しなかった場合の例外。"""

    def __init__(
        self,
        max_polls: int,
        results_location: str,
        last_response: dict[str, Any],
    ) -> None:
        self.max_polls = max_polls
        self.results_location = results_location
        self.last_response = last_response
        super().__init__(f"Outscraper task is still pending after {max_polls} polls")
