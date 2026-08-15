from __future__ import annotations

import _socket
import socket
from collections.abc import Generator
from typing import Any

import pytest


_ORIGINAL_SOCKET = socket.socket
_ORIGINAL_LOW_LEVEL_SOCKET = _socket.socket
_ORIGINAL_SOCKET_TYPE = socket.SocketType
_ORIGINAL_RESOLVERS = {
    name: getattr(socket, name)
    for name in (
        "getaddrinfo",
        "gethostbyaddr",
        "gethostbyname",
        "gethostbyname_ex",
        "getnameinfo",
    )
}
_NETWORK_FAMILIES = frozenset({socket.AF_INET, socket.AF_INET6})
_BLOCKED_MESSAGE = (
    "Network access is disabled during tests. "
    "Mark an intentional live-service test with @pytest.mark.live_api "
    "and run it with --run-live-api."
)


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--run-live-api",
        action="store_true",
        default=False,
        help="run tests that may contact explicitly approved live services",
    )


def pytest_collection_modifyitems(
    config: pytest.Config,
    items: list[pytest.Item],
) -> None:
    if config.getoption("--run-live-api"):
        return
    skip_live_api = pytest.mark.skip(reason="requires explicit --run-live-api opt-in")
    for item in items:
        if item.get_closest_marker("live_api") is not None:
            item.add_marker(skip_live_api)


class _NetworkBlockedSocket(_ORIGINAL_SOCKET):
    """Socket that permits local IPC but rejects IPv4 and IPv6 communication."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        _ORIGINAL_LOW_LEVEL_SOCKET.__init__(self, *args, **kwargs)
        self._io_refs = 0
        self._closed = False

    def _fail_if_network(self) -> None:
        if self.family in _NETWORK_FAMILIES:
            raise AssertionError(_BLOCKED_MESSAGE)

    def connect(self, address: Any) -> None:
        self._fail_if_network()
        return super().connect(address)

    def connect_ex(self, address: Any) -> int:
        self._fail_if_network()
        return super().connect_ex(address)

    def bind(self, address: Any) -> None:
        self._fail_if_network()
        return super().bind(address)

    def accept(self) -> Any:
        self._fail_if_network()
        return super().accept()

    def listen(self, backlog: int = 0) -> None:
        self._fail_if_network()
        return super().listen(backlog)

    def recv(self, bufsize: int, flags: int = 0) -> bytes:
        self._fail_if_network()
        return super().recv(bufsize, flags)

    def recv_into(self, buffer: Any, nbytes: int = 0, flags: int = 0) -> int:
        self._fail_if_network()
        return super().recv_into(buffer, nbytes, flags)

    def recvfrom(self, bufsize: int, flags: int = 0) -> Any:
        self._fail_if_network()
        return super().recvfrom(bufsize, flags)

    def recvfrom_into(
        self,
        buffer: Any,
        nbytes: int = 0,
        flags: int = 0,
    ) -> Any:
        self._fail_if_network()
        return super().recvfrom_into(buffer, nbytes, flags)

    def recvmsg(self, *args: Any) -> Any:
        self._fail_if_network()
        return super().recvmsg(*args)

    def recvmsg_into(self, *args: Any) -> Any:
        self._fail_if_network()
        return super().recvmsg_into(*args)

    def send(self, data: Any, flags: int = 0) -> int:
        self._fail_if_network()
        return super().send(data, flags)

    def sendall(self, data: Any, flags: int = 0) -> None:
        self._fail_if_network()
        return super().sendall(data, flags)

    def sendto(self, *args: Any) -> int:
        self._fail_if_network()
        return super().sendto(*args)

    def sendmsg(self, *args: Any) -> int:
        self._fail_if_network()
        return super().sendmsg(*args)

    def sendfile(self, file: Any, offset: int = 0, count: int | None = None) -> int:
        self._fail_if_network()
        return super().sendfile(file, offset, count)

    def shutdown(self, how: int) -> None:
        self._fail_if_network()
        return super().shutdown(how)


def _block_name_resolution(*args: Any, **kwargs: Any) -> None:
    del args, kwargs
    raise AssertionError(_BLOCKED_MESSAGE)


def _install_network_guard() -> None:
    socket.socket = _NetworkBlockedSocket
    socket.SocketType = _NetworkBlockedSocket
    _socket.socket = _NetworkBlockedSocket
    for name in _ORIGINAL_RESOLVERS:
        setattr(socket, name, _block_name_resolution)


def _restore_network_functions() -> None:
    socket.socket = _ORIGINAL_SOCKET
    socket.SocketType = _ORIGINAL_SOCKET_TYPE
    _socket.socket = _ORIGINAL_LOW_LEVEL_SOCKET
    for name, original in _ORIGINAL_RESOLVERS.items():
        setattr(socket, name, original)


def pytest_configure(config: pytest.Config) -> None:
    del config
    _install_network_guard()


def pytest_unconfigure(config: pytest.Config) -> None:
    del config
    _restore_network_functions()


@pytest.fixture
def original_socket_type(request: pytest.FixtureRequest) -> type[socket.socket]:
    """Expose the unpatched type only for the network policy's self-test."""

    if request.node.get_closest_marker("live_api") is None or not request.config.getoption(
        "--run-live-api"
    ):
        raise RuntimeError("the original socket is available only to an opted-in live_api test")
    return _ORIGINAL_SOCKET


@pytest.fixture(autouse=True)
def block_network_access(
    request: pytest.FixtureRequest,
) -> Generator[None, None, None]:
    """Keep collection and normal tests guarded; opt-in live tests restore temporarily."""

    live_opted_in = request.node.get_closest_marker(
        "live_api"
    ) is not None and request.config.getoption("--run-live-api")
    if live_opted_in:
        _restore_network_functions()
    else:
        _install_network_guard()
    try:
        yield
    finally:
        _install_network_guard()
