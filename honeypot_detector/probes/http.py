import socket
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class HttpProbeResult:
    status_code: Optional[int] = None
    server_header: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)
    anomalies: List[str] = field(default_factory=list)
    raw_response: str = ""
    error: Optional[str] = None


def _send_raw_http(host: str, port: int, payload: bytes, timeout: float = 3.0) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        s.sendall(payload)
        buf = b""
        while len(buf) < 8192:
            chunk = s.recv(1024)
            if not chunk:
                break
            buf += chunk
        return buf.decode("latin1", errors="replace")
    finally:
        s.close()


def probe_http(host: str, port: int = 80, timeout: float = 3.0) -> HttpProbeResult:
    result = HttpProbeResult()
    standard_req = f"GET / HTTP/1.1\r\nHost: {host}\r\nAccept: */*\r\n\r\n".encode("ascii")

    try:
        res = _send_raw_http(host, port, standard_req, timeout=timeout)
        result.raw_response = res
        if not res:
            result.error = "empty response"
            return result

        lines = res.split("\r\n")
        status_line = lines[0]
        parts = status_line.split(" ", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            result.status_code = int(parts[1])

        for line in lines[1:]:
            if not line:
                break
            if ":" in line:
                k, v = line.split(":", 1)
                result.headers[k.strip().lower()] = v.strip()

        result.server_header = result.headers.get("server")

        # Common standard behavior check: HTTP/1.1 200 response should include a Date header
        if result.status_code == 200 and "date" not in result.headers:
            result.anomalies.append("missing Date header in HTTP/1.1 200 response")

        # Glastopf / Conpot / simple python socket honeypots often echo server banners
        # or crash on malformed methods and versions
        _test_malformed_requests(host, port, timeout, result)

    except Exception as exc:
        result.error = str(exc)

    return result


def _test_malformed_requests(host: str, port: int, timeout: float, result: HttpProbeResult):
    # 1. Non-standard HTTP version (Glastopf returns 200 OK to HTTP/9.9)
    weird_ver_req = f"GET / HTTP/9.9\r\nHost: {host}\r\n\r\n".encode("ascii")
    try:
        res_ver = _send_raw_http(host, port, weird_ver_req, timeout=timeout)
        if res_ver.startswith("HTTP/1.1 200") or res_ver.startswith("HTTP/1.0 200"):
            result.anomalies.append("accepted invalid HTTP/9.9 version with 200 OK (Glastopf/Conpot quirk)")
    except Exception:
        pass

    # 2. Bogus HTTP verb
    bogus_verb_req = f"HONEYPOTTEST / HTTP/1.1\r\nHost: {host}\r\n\r\n".encode("ascii")
    try:
        res_verb = _send_raw_http(host, port, bogus_verb_req, timeout=timeout)
        if "200 OK" in res_verb:
            result.anomalies.append("accepted arbitrary HTTP verb HONEYPOTTEST with 200 OK")
        elif "Traceback (most recent call last)" in res_verb:
            result.anomalies.append("leaked python traceback on unhandled HTTP verb")
    except Exception:
        pass

    # 3. HTTP/1.1 request missing Host header
    no_host_req = b"GET / HTTP/1.1\r\nUser-Agent: test\r\n\r\n"
    try:
        res_nohost = _send_raw_http(host, port, no_host_req, timeout=timeout)
        # RFC 2616 requires 400 Bad Request if Host header is missing in 1.1
        if res_nohost.startswith("HTTP/1.1 200"):
            result.anomalies.append("ignored missing Host header under HTTP/1.1")
    except Exception:
        pass
