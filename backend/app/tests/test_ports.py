import socket

import pytest

from app.deep_scanners.ports import (
    CONTROLLED_PORTS,
    resolve_public_addresses,
    scan_open_ports,
    test_tcp_connection as check_tcp_connection,
)
from app.utils.domain import DomainValidationError


class FakeConnection:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True


def public_resolver(
    domain,
    port,
    type,
):
    return [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("93.184.216.34", 0),
        ),
    ]


def private_resolver(
    domain,
    port,
    type,
):
    return [
        (
            socket.AF_INET,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
            "",
            ("127.0.0.1", 0),
        ),
    ]


def test_resolves_public_address():
    addresses = resolve_public_addresses(
        "example.com",
        resolver=public_resolver,
    )

    assert addresses == [
        "93.184.216.34"
    ]


def test_rejects_private_address():
    with pytest.raises(
        DomainValidationError,
        match="private or unsafe",
    ):
        resolve_public_addresses(
            "example.com",
            resolver=private_resolver,
        )


def test_open_connection_returns_true():
    connection = FakeConnection()

    def connector(target, timeout):
        return connection

    result = check_tcp_connection(
        "93.184.216.34",
        443,
        0.5,
        connector=connector,
    )

    assert result is True
    assert connection.closed is True


def test_closed_connection_returns_false():
    def connector(target, timeout):
        raise ConnectionRefusedError()

    result = check_tcp_connection(
        "93.184.216.34",
        443,
        0.5,
        connector=connector,
    )

    assert result is False


def test_scan_reports_only_open_ports():
    def connector(target, timeout):
        _, port = target

        if port == 443:
            return FakeConnection()

        raise ConnectionRefusedError()

    result = scan_open_ports(
        "example.com",
        resolver=public_resolver,
        connector=connector,
        ports={
            80: CONTROLLED_PORTS[80],
            443: CONTROLLED_PORTS[443],
        },
    )

    assert result["open_port_count"] == 1
    assert result["checks"][0]["port"] == 443


def test_database_port_needs_attention():
    def connector(target, timeout):
        return FakeConnection()

    result = scan_open_ports(
        "example.com",
        resolver=public_resolver,
        connector=connector,
        ports={
            3306: CONTROLLED_PORTS[3306],
        },
    )

    assert result["status"] == "Needs Attention"
    assert result["checks"][0]["service"] == "MySQL"
    assert result["checks"][0][
        "vulnerability_confirmed"
    ] is False


def test_web_ports_are_expected():
    def connector(target, timeout):
        return FakeConnection()

    result = scan_open_ports(
        "example.com",
        resolver=public_resolver,
        connector=connector,
        ports={
            80: CONTROLLED_PORTS[80],
            443: CONTROLLED_PORTS[443],
        },
    )

    assert result["status"] == "Observed"
    assert result["open_port_count"] == 2


def test_invalid_worker_limit_is_rejected():
    with pytest.raises(
        ValueError,
        match="worker",
    ):
        scan_open_ports(
            "example.com",
            max_workers=100,
            resolver=public_resolver,
        )