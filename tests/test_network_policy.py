from __future__ import annotations

import _socket
import socket

import pytest
import requests


BLOCKED_MESSAGE = "Network access is disabled during tests"
NETWORK_GUARD_ACTIVE_DURING_COLLECTION = socket.socket.__name__ == "_NetworkBlockedSocket"


@pytest.mark.parametrize(
    ("family", "address"),
    [
        (socket.AF_INET, ("127.0.0.1", 9)),
        (socket.AF_INET6, ("::1", 9)),
    ],
)
def test_network_policy_blocks_tcp_connect(family: socket.AddressFamily, address: tuple) -> None:
    with socket.socket(family, socket.SOCK_STREAM) as client:
        with pytest.raises(AssertionError, match=BLOCKED_MESSAGE):
            client.connect(address)


def test_network_policy_blocks_connect_ex() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        with pytest.raises(AssertionError, match=BLOCKED_MESSAGE):
            client.connect_ex(("127.0.0.1", 9))


def test_network_policy_blocks_udp_sendto() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
        with pytest.raises(AssertionError, match=BLOCKED_MESSAGE):
            client.sendto(b"probe", ("127.0.0.1", 9))


@pytest.mark.parametrize(
    "method_name",
    [
        "accept",
        "listen",
        "recv",
        "recv_into",
        "recvfrom",
        "recvfrom_into",
        "recvmsg",
        "recvmsg_into",
        "sendfile",
        "sendmsg",
        "shutdown",
    ],
)
def test_network_policy_overrides_ip_io_without_using_the_network(method_name) -> None:
    assert method_name in socket.socket.__dict__


@pytest.mark.parametrize(
    ("resolver", "args"),
    [
        (socket.gethostbyaddr, (object(),)),
        (socket.getnameinfo, (object(), 0)),
    ],
)
def test_network_policy_blocks_reverse_name_resolution(resolver, args) -> None:
    with pytest.raises(AssertionError, match=BLOCKED_MESSAGE):
        resolver(*args)


def test_network_policy_is_active_during_test_module_collection() -> None:
    assert NETWORK_GUARD_ACTIVE_DURING_COLLECTION is True
    assert _socket.socket is socket.socket
    assert socket.SocketType is socket.socket


def test_network_policy_allows_unix_domain_ipc() -> None:
    left, right = socket.socketpair()
    with left, right:
        left.sendall(b"local")
        assert right.recv(5) == b"local"


def test_network_policy_blocks_name_resolution() -> None:
    with pytest.raises(AssertionError, match=BLOCKED_MESSAGE):
        socket.getaddrinfo("localhost", 80)


def test_network_policy_blocks_requests_before_transport() -> None:
    with pytest.raises(AssertionError, match=BLOCKED_MESSAGE):
        requests.get("http://127.0.0.1:9", timeout=0.01)


@pytest.mark.live_api
def test_live_api_marker_explicitly_opts_out_of_network_guard(
    original_socket_type: type[socket.socket],
) -> None:
    assert socket.socket is original_socket_type
