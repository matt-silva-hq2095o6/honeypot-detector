import hashlib
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Optional, List, Tuple


@dataclass
class SshProbeResult:
    """Results from probing an SSH endpoint."""
    banner: Optional[str] = None
    banner_delay_ms: float = 0.0
    kex_algorithms: List[str] = field(default_factory=list)
    server_host_key_algorithms: List[str] = field(default_factory=list)
    enc_algorithms: List[str] = field(default_factory=list)
    mac_algorithms: List[str] = field(default_factory=list)
    comp_algorithms: List[str] = field(default_factory=list)
    hassh: Optional[str] = None
    hassh_raw: Optional[str] = None
    cowrie_indicators: List[str] = field(default_factory=list)
    error: Optional[str] = None


# Known default hassh fingerprints for common honeypot configs
KNOWN_HONEYPOT_HASSH = {
    "ec445a6669f4682c0b70ff9f91a561db": "Cowrie default (Debian/Twisted)",
    "d451b6dd0154884260d5b51b34ad260c": "Cowrie legacy twisted backend",
    "89f925e0037a34493ec1ebc5ab733670": "Twisted Conch default",
    "bf7b1b0b7274db4cc5a2ad02798e4f13": "Infinite SSH tarpit / Endlessh",
}


def _parse_ssh_string(data: bytes, offset: int) -> Tuple[str, int]:
    if offset + 4 > len(data):
        return "", offset
    str_len = struct.unpack(">I", data[offset:offset + 4])[0]
    offset += 4
    val = data[offset:offset + str_len].decode("ascii", errors="ignore")
    return val, offset + str_len


def _parse_kexinit(payload: bytes) -> dict:
    # SSH_MSG_KEXINIT starts with message type byte (20) followed by 16-byte cookie
    if len(payload) < 17 or payload[0] != 20:
        return {}

    idx = 17
    fields = [
        "kex_algorithms",
        "server_host_key_algorithms",
        "encryption_algorithms_client_to_server",
        "encryption_algorithms_server_to_client",
        "mac_algorithms_client_to_server",
        "mac_algorithms_server_to_client",
        "compression_algorithms_client_to_server",
        "compression_algorithms_server_to_client",
        "languages_client_to_server",
        "languages_server_to_client",
    ]

    parsed = {}
    for name in fields:
        if idx >= len(payload):
            break
        val, idx = _parse_ssh_string(payload, idx)
        parsed[name] = val.split(",") if val else []

    return parsed


def probe_ssh(host: str, port: int = 22, timeout: float = 4.0) -> SshProbeResult:
    result = SshProbeResult()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)

    try:
        t0 = time.monotonic()
        s.connect((host, port))

        raw_banner = b""
        while b"\n" not in raw_banner and len(raw_banner) < 256:
            chunk = s.recv(1)
            if not chunk:
                break
            raw_banner += chunk

        result.banner_delay_ms = (time.monotonic() - t0) * 1000.0
        if not raw_banner:
            result.error = "empty banner"
            return result

        line = raw_banner.decode("utf-8", errors="replace").strip()
        result.banner = line

        # Client banner exchange
        s.sendall(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n")

        # Read SSH packet header (length + pad_length)
        header = s.recv(5)
        if len(header) < 5:
            return result

        pkt_len, pad_len = struct.unpack(">IB", header)
        # FIXME: handle multi-packet kexinit when key list > 1460 bytes
        payload_len = pkt_len - pad_len - 1
        if payload_len <= 0 or payload_len > 32768:
            return result

        payload = b""
        while len(payload) < payload_len:
            chunk = s.recv(payload_len - len(payload))
            if not chunk:
                break
            payload += chunk

        # discard padding
        if pad_len > 0:
            s.recv(pad_len)

        # print(f"DEBUG: raw kex payload len={len(payload)}")
        kex_info = _parse_kexinit(payload)
        if not kex_info:
            return result

        result.kex_algorithms = kex_info.get("kex_algorithms", [])
        result.server_host_key_algorithms = kex_info.get("server_host_key_algorithms", [])
        result.enc_algorithms = kex_info.get("encryption_algorithms_client_to_server", [])
        result.mac_algorithms = kex_info.get("mac_algorithms_client_to_server", [])
        result.comp_algorithms = kex_info.get("compression_algorithms_client_to_server", [])

        # Standard hassh format: kex;enc;mac;cmp
        hassh_raw = ";".join([
            ",".join(result.kex_algorithms),
            ",".join(result.enc_algorithms),
            ",".join(result.mac_algorithms),
            ",".join(result.comp_algorithms),
        ])
        result.hassh_raw = hassh_raw
        result.hassh = hashlib.md5(hassh_raw.encode("ascii")).hexdigest()

        if result.hassh in KNOWN_HONEYPOT_HASSH:
            result.cowrie_indicators.append(
                f"hassh matches {KNOWN_HONEYPOT_HASSH[result.hassh]}"
            )

        # Twisted / Cowrie specific default key exchange quirk:
        # Conch includes diffie-hellman-group1-sha1 and twisted specific ciphers first
        if "diffie-hellman-group14-sha1" in result.kex_algorithms and "curve25519-sha256" not in result.kex_algorithms:
            if result.banner and "OpenSSH" in result.banner:
                result.cowrie_indicators.append(
                    "banner claims OpenSSH but lacks curve25519 in kex algorithms"
                )

    except socket.timeout:
        result.error = "socket timeout during exchange"
    except Exception as exc:
        result.error = str(exc)
    finally:
        s.close()

    return result
