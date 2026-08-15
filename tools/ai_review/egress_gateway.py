#!/usr/local/bin/python -I
"""One-shot, fixed-destination TCP gateway for the isolated review broker.

The gateway has no credential and understands no application payload.  Its pinned container is
the only member of both the broker's internal network and a separately attested outbound network.
It accepts one private-network peer and can connect only to globally routable addresses returned
for ``api.openai.com:443``.  TLS remains end-to-end between the broker and OpenAI.
"""

from __future__ import annotations

import ipaddress
import os
import selectors
import socket
import sys
import time
from collections.abc import Mapping


LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8443
TARGET_HOST = "api.openai.com"
TARGET_PORT = 443
ACCEPT_TIMEOUT_SECONDS = 30
CONNECT_TIMEOUT_SECONDS = 30
RELAY_TIMEOUT_SECONDS = 240
MAX_BYTES_PER_DIRECTION = 16_000_000
MAX_TARGET_ADDRESSES = 16
_FORBIDDEN_ENV_NAMES = {
    "all_proxy",
    "aws_ca_bundle",
    "curl_ca_bundle",
    "http_proxy",
    "https_proxy",
    "ld_audit",
    "ld_library_path",
    "ld_preload",
    "netrc",
    "no_proxy",
    "openai_api_key",
    "openai_base_url",
    "pythonhome",
    "pythonpath",
    "requests_ca_bundle",
    "ssl_cert_dir",
    "ssl_cert_file",
}


class EgressGatewayError(RuntimeError):
    """A generic gateway failure that does not include DNS, peer, or payload content."""


def _validate_environment(environment: Mapping[str, str]) -> None:
    lowered = {name.casefold() for name in environment}
    if lowered & _FORBIDDEN_ENV_NAMES:
        raise EgressGatewayError("egress gateway environment is not approved")
    if environment.get("AI_REVIEW_EGRESS_GATEWAY") != "1":
        raise EgressGatewayError("egress gateway opt-in is missing")


def _validated_target_addresses(
    *,
    resolver=socket.getaddrinfo,
) -> tuple[tuple[int, tuple], ...]:
    try:
        results = resolver(
            TARGET_HOST,
            TARGET_PORT,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except OSError as exc:
        raise EgressGatewayError("egress target resolution failed") from exc
    addresses: list[tuple[int, tuple]] = []
    seen: set[tuple[int, str, int]] = set()
    for family, socket_type, protocol, _canonical_name, address in results:
        if (
            family not in {socket.AF_INET, socket.AF_INET6}
            or socket_type != socket.SOCK_STREAM
            or protocol not in {0, socket.IPPROTO_TCP}
            or not isinstance(address, tuple)
            or len(address) < 2
            or address[1] != TARGET_PORT
        ):
            continue
        try:
            ip = ipaddress.ip_address(address[0])
        except ValueError:
            continue
        if not ip.is_global:
            raise EgressGatewayError("egress target resolution returned a forbidden address")
        key = (family, ip.compressed, address[1])
        if key not in seen:
            seen.add(key)
            addresses.append((family, address))
        if len(addresses) > MAX_TARGET_ADDRESSES:
            raise EgressGatewayError("egress target resolution exceeded its address limit")
    if not addresses:
        raise EgressGatewayError("egress target resolution returned no approved address")
    return tuple(addresses)


def _validate_peer(address: tuple) -> None:
    if not isinstance(address, tuple) or not address:
        raise EgressGatewayError("egress gateway peer is invalid")
    try:
        peer = ipaddress.ip_address(address[0])
    except ValueError as exc:
        raise EgressGatewayError("egress gateway peer is invalid") from exc
    if not peer.is_private or peer.is_loopback or peer.is_link_local or peer.is_multicast:
        raise EgressGatewayError("egress gateway peer is outside the private broker network")


def _connect_target(addresses: tuple[tuple[int, tuple], ...]) -> socket.socket:
    for family, address in addresses:
        connection = socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        try:
            connection.settimeout(CONNECT_TIMEOUT_SECONDS)
            connection.connect(address)
            connection.settimeout(None)
            return connection
        except OSError:
            connection.close()
    raise EgressGatewayError("egress target connection failed")


def _relay(peer: socket.socket, target: socket.socket) -> None:
    selector = selectors.DefaultSelector()
    endpoints = {peer: target, target: peer}
    byte_counts = {peer: 0, target: 0}
    deadline = time.monotonic() + RELAY_TIMEOUT_SECONDS
    try:
        for endpoint in endpoints:
            endpoint.setblocking(False)
            selector.register(endpoint, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise EgressGatewayError("egress relay timed out")
            events = selector.select(min(remaining, 1.0))
            for key, _mask in events:
                source = key.fileobj
                destination = endpoints[source]
                try:
                    chunk = source.recv(65_536)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(source)
                    try:
                        destination.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    continue
                byte_counts[source] += len(chunk)
                if byte_counts[source] > MAX_BYTES_PER_DIRECTION:
                    raise EgressGatewayError("egress relay exceeded its byte limit")
                view = memoryview(chunk)
                while view:
                    try:
                        written = destination.send(view)
                    except BlockingIOError:
                        if time.monotonic() >= deadline:
                            raise EgressGatewayError("egress relay timed out") from None
                        continue
                    if written <= 0:
                        raise EgressGatewayError("egress relay failed")
                    view = view[written:]
    finally:
        selector.close()


def serve_once(*, environment: Mapping[str, str] = os.environ) -> None:
    _validate_environment(environment)
    addresses = _validated_target_addresses()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
    peer: socket.socket | None = None
    target: socket.socket | None = None
    try:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((LISTEN_HOST, LISTEN_PORT))
        listener.listen(1)
        listener.settimeout(ACCEPT_TIMEOUT_SECONDS)
        try:
            peer, peer_address = listener.accept()
        except OSError as exc:
            raise EgressGatewayError(
                "egress gateway did not receive one broker connection"
            ) from exc
        _validate_peer(peer_address)
        target = _connect_target(addresses)
        _relay(peer, target)
    finally:
        listener.close()
        if peer is not None:
            peer.close()
        if target is not None:
            target.close()


def main() -> int:
    try:
        if sys.argv[1:]:
            raise EgressGatewayError("egress gateway accepts no arguments")
        serve_once()
        return 0
    except EgressGatewayError as exc:
        print(f"egress gateway error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
