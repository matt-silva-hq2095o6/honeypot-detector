from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class MatchResult:
    name: str
    confidence: float
    reasons: List[str] = field(default_factory=list)


SIGNATURES = {
    "cowrie": {
        "ssh_banner": [
            "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2",
            "SSH-2.0-OpenSSH_6.7p1 Raspbian-5+deb8u3",
            "SSH-2.0-OpenSSH_7.4p1 Raspbian-10+deb9u7",
        ],
        # Twisted Conch default cipher ordering when unconfigured
        "kex_order": [
            "curve25519-sha256@libssh.org",
            "ecdh-sha2-nistp256",
            "diffie-hellman-group14-sha1",
        ],
        "telnet_banner": ["Ubuntu 14.04.5 LTS", "Raspbian GNU/Linux 8"],
        "tcp_window_sizes": [5840, 29200],
    },
    "dionaea": {
        "smb_native_os": "Windows 7 Professional 7601 Service Pack 1",
        "smb_banner_quirk": True,
        "mssql_version": "2008 R2",
        "tcp_window_sizes": [8192],
    },
    "conpot": {
        "modbus_slave_id": b"\x01\x11\x00\x00",
        "s7comm_pdu_size": 240,
        "snmp_sysdescr": "Siemens, SIMATIC S7-200, CPU 224",
        "http_server": "Conpot",
    },
    "glastopf": {
        "default_status": 200,
        "empty_post_payload_hash": "d41d8cd98f00b204e9800998ecf8427e",
    },
    "honeyd": {
        # Honeyd syn-ack quirk on closed ports when personality is active
        "unreachable_flags": 0x12,
    },
}


def evaluate_target(collected: Dict[str, Any]) -> List[MatchResult]:
    """Score observed probes against known honeypot fingerprints."""
    results = []

    # TODO: normalize raw banner strings beforehand (trailing crlf differences)
    for hp_name, sig in SIGNATURES.items():
        score = 0.0
        reasons = []

        # SSH quirks
        banner = collected.get("ssh_banner", "")
        if banner and hp_name == "cowrie":
            if banner in sig.get("ssh_banner", []):
                score += 0.45
                reasons.append(f"exact cowrie default banner: {banner}")
            elif "Raspbian" in banner:
                # high false positive rate standalone, give small weight
                score += 0.15
                reasons.append("generic raspbian banner often used in cowrie defaults")

            # cowrie twisted implementation drops unsupported kex without proper disconnect
            if collected.get("ssh_kex_raw_drop"):
                score += 0.35
                reasons.append("dropped invalid kex packet instead of ssh_msg_disconnect")

            if collected.get("ssh_auth_timing_flat"):
                # fake auth always returns in constant 100-200ms regardless of user
                score += 0.25
                reasons.append("flat auth timing response curve on nonexistent users")

        # TCP stack anomalies
        win_size = collected.get("tcp_window")
        if win_size and win_size in sig.get("tcp_window_sizes", []):
            score += 0.15
            reasons.append(f"suspicious static tcp window: {win_size}")

        # Conpot Modbus / S7 checks
        if hp_name == "conpot":
            if collected.get("modbus_response") == sig.get("modbus_slave_id"):
                score += 0.6
                reasons.append("default conpot modbus device id response")
            if collected.get("snmp_sysdescr") == sig.get("snmp_sysdescr"):
                score += 0.5
                reasons.append("matching default conpot snmp description")
            if collected.get("s7_pdu_length") == sig.get("s7comm_pdu_size"):
                score += 0.3
                reasons.append("standard 240-byte s7comm pdu length negotiation")

        # Dionaea checks
        if hp_name == "dionaea":
            if collected.get("smb_os") == sig.get("smb_native_os"):
                score += 0.4
                reasons.append("dionaea smb fake os signature")
            if collected.get("mssql_prelogin_bug"):
                score += 0.35
                reasons.append("mssql malformed prelogin packet returned ok")

        # Glastopf web quirks
        if hp_name == "glastopf":
            # Glastopf tends to return 200 with generic body on any POST exploit attempt
            if collected.get("http_post_all_200") and collected.get("http_sqli_reflected"):
                score += 0.55
                reasons.append("blind 200 response on arbitrary post injections")

        # Honeyd raw quirks
        if hp_name == "honeyd":
            if collected.get("closed_port_synack"):
                score += 0.7
                reasons.append("received syn-ack on filtered/closed port personality emulation")

        if score >= 0.3:
            results.append(MatchResult(
                name=hp_name,
                confidence=min(round(score, 2), 1.0),
                reasons=reasons,
            ))

    # print(f"[debug] results: {results}")
    results.sort(key=lambda r: r.confidence, reverse=True)
    return results
