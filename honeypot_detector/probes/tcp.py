import os
import random
import socket
import struct
import time
from typing import Optional, Dict, Any


def _checksum(msg: bytes) -> int:
    s = 0
    if len(msg) % 2 == 1:
        msg += b'\x00'
    for i in range(0, len(msg), 2):
        w = (msg[i] << 8) + msg[i + 1]
        s += w
    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)
    return ~s & 0xffff


def _build_syn_packet(src_ip: str, dst_ip: str, src_port: int, dst_port: int, seq: int) -> bytes:
    # MSS option (kind=2, len=4, value=1460) + SACK permitted (kind=4, len=2) + NOP
    # Honeypots often echo strange MSS or omit standard option ordering.
    options = b'\x02\x04\x05\xb4\x04\x02\x01\x00'
    opt_len = len(options)
    doff = 5 + (opt_len // 4)
    flags = 0x02  # SYN
    window = socket.htons(29200)
    urg_ptr = 0
    offset_res = (doff << 4) + 0

    tcp_header = struct.pack(
        '!HHLLBBHHH',
        src_port,
        dst_port,
        seq,
        0,  # ack
        offset_res,
        flags,
        window,
        0,  # checksum placeholder
        urg_ptr
    ) + options

    # Pseudo header for checksum calc
    src_addr = socket.inet_aton(src_ip)
    dst_addr = socket.inet_aton(dst_ip)
    psh = struct.pack('!4s4sBBH', src_addr, dst_addr, 0, socket.IPPROTO_TCP, len(tcp_header))
    chk = _checksum(psh + tcp_header)

    # Rebuild header with valid checksum
    return struct.pack(
        '!HHLLBB',
        src_port,
        dst_port,
        seq,
        0,
        offset_res,
        flags
    ) + struct.pack('!H', window) + struct.pack('H', chk) + struct.pack('!H', urg_ptr) + options


def _parse_tcp_options(opt_bytes: bytes) -> Dict[str, Any]:
    options = {}
    idx = 0
    while idx < len(opt_bytes):
        kind = opt_bytes[idx]
        if kind == 0:  # EOL
            break
        if kind == 1:  # NOP
            idx += 1
            continue
        if idx + 1 >= len(opt_bytes):
            break
        length = opt_bytes[idx + 1]
        if length < 2 or idx + length > len(opt_bytes):
            break
        data = opt_bytes[idx + 2:idx + length]
        if kind == 2 and len(data) == 2:  # MSS
            options['mss'] = struct.unpack('!H', data)[0]
        elif kind == 3 and len(data) == 1:  # Window scale
            options['wscale'] = data[0]
        elif kind == 4 and len(data) == 0:  # SACK
            options['sack_perm'] = True
        elif kind == 8 and len(data) == 8:  # Timestamps
            ts_val, ts_ecr = struct.unpack('!II', data)
            options['ts'] = (ts_val, ts_ecr)
        idx += length
    return options


def _fallback_unprivileged_check(host: str, port: int, timeout: float) -> Optional[Dict[str, Any]]:
    # When non-root, regular socket connect won't give raw TCP header details
    # but we can at least measure response latency and detect open state.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    t0 = time.monotonic()
    try:
        sock.connect((host, port))
        elapsed = time.monotonic() - t0
        # print(f"fallback connected to {host}:{port} in {elapsed:.3f}s")
        return {
            'window_size': None,
            'synack': True,
            'rst': False,
            'ttl': None,
            'options': {},
            'rtt_ms': round(elapsed * 1000, 2),
            'unprivileged': True,
        }
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None
    finally:
        sock.close()


def probe_tcp_syn(host: str, port: int, timeout: float = 2.0) -> Optional[Dict[str, Any]]:
    """Sends a raw SYN packet to inspect SYN-ACK window size and TCP options."""
    # Raw sockets require root on linux / admin on windows
    if not hasattr(os, 'geteuid') or os.geteuid() != 0:
        return _fallback_unprivileged_check(host, port, timeout)

    try:
        target_ip = socket.gethostbyname(host)
    except socket.gaierror:
        return None

    # Find source IP for pseudo header
    s_route = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s_route.connect((target_ip, port or 80))
        src_ip = s_route.getsockname()[0]
    except Exception:
        src_ip = '0.0.0.0'
    finally:
        s_route.close()

    src_port = random.randint(32768, 61000)
    seq_num = random.randint(100000, 9000000)

    try:
        raw_send = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        raw_recv = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        raw_recv.settimeout(timeout)
    except PermissionError:
        return _fallback_unprivileged_check(host, port, timeout)

    syn_pkt = _build_syn_packet(src_ip, target_ip, src_port, port, seq_num)

    try:
        raw_send.sendto(syn_pkt, (target_ip, port))
        deadline = time.time() + timeout

        while time.time() < deadline:
            packet, addr = raw_recv.recvfrom(65535)
            if addr[0] != target_ip:
                continue

            ihl = (packet[0] & 0x0f) * 4
            tcp_packet = packet[ihl:]
            if len(tcp_packet) < 20:
                continue

            p_src, p_dst, p_seq, p_ack, doff_flags = struct.unpack('!HHLLH', tcp_packet[:14])
            if p_dst != src_port or p_src != port:
                continue

            flags = doff_flags & 0x1ff
            tcp_header_len = ((doff_flags >> 12) & 0x0f) * 4
            window_size = struct.unpack('!H', tcp_packet[14:16])[0]

            is_synack = (flags & 0x12) == 0x12
            is_rst = bool(flags & 0x04)

            opts = {}
            if tcp_header_len > 20 and len(tcp_packet) >= tcp_header_len:
                opts = _parse_tcp_options(tcp_packet[20:tcp_header_len])

            # Dionaea and older Cowrie versions often report static windows (e.g. 5840 or 65535)
            # with no window scale or timestamp negotiation even when client offered it.
            return {
                'window_size': window_size,
                'synack': is_synack,
                'rst': is_rst,
                'ttl': packet[8],
                'options': opts,
                'unprivileged': False,
            }
    except socket.timeout:
        return None
    finally:
        raw_send.close()
        raw_recv.close()

    return None
