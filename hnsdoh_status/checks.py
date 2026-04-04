from __future__ import annotations

import socket
import ssl
import time
from datetime import datetime, timezone

import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver

from hnsdoh_status.models import CheckResult, NodeSnapshot, ProtocolName, Snapshot


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def discover_nodes(domain: str) -> tuple[list[str], str]:
    resolver = dns.resolver.Resolver()
    try:
        answer = resolver.resolve(domain, "A")
        return sorted({record.address for record in answer}), ""
    except Exception as exc:  # noqa: BLE001
        return [], str(exc)


def _check_dns_udp(ip: str, timeout: float) -> CheckResult:
    started = time.perf_counter()
    checked_at = utcnow()
    query = dns.message.make_query("hnsdoh.com", dns.rdatatype.A)
    try:
        response = dns.query.udp(query, ip, timeout=timeout, port=53)
        latency = (time.perf_counter() - started) * 1000
        return CheckResult(
            protocol="dns_udp",
            ok=bool(response.answer),
            latency_ms=latency,
            checked_at=checked_at,
            reason="ok" if response.answer else "empty answer",
        )
    except Exception as exc:  # noqa: BLE001
        return CheckResult("dns_udp", False, None, checked_at, str(exc))


def _check_dns_tcp(ip: str, timeout: float) -> CheckResult:
    started = time.perf_counter()
    checked_at = utcnow()
    query = dns.message.make_query("hnsdoh.com", dns.rdatatype.A)
    try:
        response = dns.query.tcp(query, ip, timeout=timeout, port=53)
        latency = (time.perf_counter() - started) * 1000
        return CheckResult(
            protocol="dns_tcp",
            ok=bool(response.answer),
            latency_ms=latency,
            checked_at=checked_at,
            reason="ok" if response.answer else "empty answer",
        )
    except Exception as exc:  # noqa: BLE001
        return CheckResult("dns_tcp", False, None, checked_at, str(exc))


def _tls_connection(ip: str, port: int, hostname: str, timeout: float) -> ssl.SSLSocket:
    context = ssl.create_default_context()
    raw = socket.create_connection((ip, port), timeout=timeout)
    try:
        tls_socket = context.wrap_socket(raw, server_hostname=hostname)
        return tls_socket
    except Exception:
        raw.close()
        raise


def _decode_chunked_body(data: bytes) -> bytes:
    output = bytearray()
    cursor = 0

    while True:
        line_end = data.find(b"\r\n", cursor)
        if line_end < 0:
            raise ValueError("invalid chunk framing")

        size_token = data[cursor:line_end].split(b";", maxsplit=1)[0].strip()
        size = int(size_token or b"0", 16)
        cursor = line_end + 2

        if size == 0:
            break

        next_cursor = cursor + size
        if next_cursor + 2 > len(data):
            raise ValueError("truncated chunk payload")
        output.extend(data[cursor:next_cursor])

        if data[next_cursor : next_cursor + 2] != b"\r\n":
            raise ValueError("invalid chunk terminator")
        cursor = next_cursor + 2

    return bytes(output)


def _parse_http_response(response: bytes) -> tuple[str, dict[str, str], bytes]:
    head, separator, body = response.partition(b"\r\n\r\n")
    if not separator:
        raise ValueError("invalid HTTP response")

    lines = head.split(b"\r\n")
    status_line = lines[0].decode("latin-1", errors="replace")
    headers: dict[str, str] = {}

    for line in lines[1:]:
        if b":" not in line:
            continue
        key, value = line.split(b":", maxsplit=1)
        headers[key.decode("latin-1", errors="replace").lower()] = value.decode(
            "latin-1", errors="replace"
        ).strip()

    transfer_encoding = headers.get("transfer-encoding", "").lower()
    if "chunked" in transfer_encoding:
        body = _decode_chunked_body(body)

    return status_line, headers, body


def _check_doh(ip: str, hostname: str, path: str, timeout: float) -> CheckResult:
    started = time.perf_counter()
    checked_at = utcnow()
    query = dns.message.make_query(hostname, dns.rdatatype.A)
    query_wire = query.to_wire()
    request = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {hostname}\r\n"
        "Accept: application/dns-message\r\n"
        "Content-Type: application/dns-message\r\n"
        f"Content-Length: {len(query_wire)}\r\n"
        "Connection: close\r\n\r\n"
    ).encode("ascii") + query_wire

    try:
        with _tls_connection(ip, 443, hostname, timeout) as conn:
            conn.settimeout(timeout)
            conn.sendall(request)
            response = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                response += chunk

        latency = (time.perf_counter() - started) * 1000
        status_line, _, body = _parse_http_response(response)
        status_ok = " 200 " in status_line

        payload_ok = False
        reason = ""
        if status_ok and body:
            try:
                parsed_dns = dns.message.from_wire(body)
                payload_ok = parsed_dns.rcode() == dns.rcode.NOERROR and bool(
                    parsed_dns.answer
                )
                if payload_ok:
                    reason = "ok"
                elif parsed_dns.rcode() != dns.rcode.NOERROR:
                    reason = f"dns rcode {dns.rcode.to_text(parsed_dns.rcode())}"
                else:
                    reason = "empty answer"
            except Exception:  # noqa: BLE001
                reason = "invalid dns wireformat payload"

        ok = status_ok and payload_ok
        if not reason:
            reason = f"http status failed: {status_line}"

        return CheckResult("doh", ok, latency, checked_at, reason)
    except ssl.SSLCertVerificationError as exc:
        return CheckResult("doh", False, None, checked_at, f"tls verify failed: {exc}")
    except Exception as exc:  # noqa: BLE001
        return CheckResult("doh", False, None, checked_at, str(exc))


def _check_dot(ip: str, hostname: str, timeout: float) -> CheckResult:
    started = time.perf_counter()
    checked_at = utcnow()
    query = dns.message.make_query("hnsdoh.com", dns.rdatatype.A)
    context = ssl.create_default_context()
    try:
        response = dns.query.tls(
            query,
            where=ip,
            timeout=timeout,
            port=853,
            ssl_context=context,
            server_hostname=hostname,
        )
        latency = (time.perf_counter() - started) * 1000
        return CheckResult(
            protocol="dot",
            ok=bool(response.answer),
            latency_ms=latency,
            checked_at=checked_at,
            reason="ok" if response.answer else "empty answer",
        )
    except ssl.SSLCertVerificationError as exc:
        return CheckResult("dot", False, None, checked_at, f"tls verify failed: {exc}")
    except Exception as exc:  # noqa: BLE001
        return CheckResult("dot", False, None, checked_at, str(exc))


def check_node(
    ip: str,
    hostname: str,
    doh_path: str,
    dns_timeout: float,
    doh_timeout: float,
    dot_timeout: float,
) -> NodeSnapshot:
    results: dict[ProtocolName, CheckResult] = {
        "dns_udp": _check_dns_udp(ip, dns_timeout),
        "dns_tcp": _check_dns_tcp(ip, dns_timeout),
        "doh": _check_doh(ip, hostname, doh_path, doh_timeout),
        "dot": _check_dot(ip, hostname, dot_timeout),
    }
    return NodeSnapshot(ip=ip, results=results)


def run_full_check(
    domain: str,
    doh_path: str,
    dns_timeout: float,
    doh_timeout: float,
    dot_timeout: float,
) -> Snapshot:
    checked_at = utcnow()
    nodes, discovery_error = discover_nodes(domain)
    snapshots = [
        check_node(ip, domain, doh_path, dns_timeout, doh_timeout, dot_timeout)
        for ip in nodes
    ]
    return Snapshot(
        domain=domain,
        checked_at=checked_at,
        node_count=len(snapshots),
        nodes=snapshots,
        discovery_error=discovery_error,
    )
