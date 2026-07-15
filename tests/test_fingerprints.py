import pytest
from honeypot_detector.fingerprints import evaluate_signatures, FingerprintMatch


COWRIE_SAMPLE_BANNER = "SSH-2.0-OpenSSH_6.0p1 Debian-4+deb7u2"
COWRIE_KEXINIT_PAYLOAD = {
    "banner": COWRIE_SAMPLE_BANNER,
    "kex_algorithms": [
        "curve25519-sha256@libssh.org",
        "ecdh-sha2-nistp256",
        "diffie-hellman-group-exchange-sha256",
        "diffie-hellman-group14-sha1",
    ],
    "server_host_key_algorithms": ["ssh-rsa", "ssh-dss"],
    "encryption_algorithms_client_to_server": ["aes128-ctr", "aes192-ctr", "aes256-ctr", "aes128-cbc", "3des-cbc"],
    "hassh": "e7d705a32420e49339088251814b50b6",
    "tcp_window_size": 5840,
    "tcp_options": [("MSS", 1460), ("NOP", None), ("WScale", 7), ("SAckOK", None)],
}

CONPOT_SAMPLE_S7 = {
    "port": 102,
    "cotp_connect_ack": b"\x03\x00\x00\x16\x11\xd0\x00\x01\x00\x00\x00\xc0\x01\n\xc1\x02\x01\x00\xc2\x02\x01\x02",
    "s7_system_info": {
        "module_type": "CPU 315-2 PN/DP",
        "order_code": "6ES7 315-2EH14-0AB0",
        "version": "V3.2.6",
        "system_name": "SIMATIC 300(1)",
    }
}

GLASTOPF_HTTP_PAYLOAD = {
    "status_code": 200,
    "headers": {
        "Server": "Apache/2.2.22 (Ubuntu)",
        "Content-Type": "text/html; charset=utf-8",
    },
    # Glastopf returns 200 with empty / canned form body on arbitrary POST / LFI probes
    "post_reflected": True,
    "lfi_dummy_response": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/bin/sh",
    "non_standard_header_order": ["Content-Type", "Server"],
}

DIONAEA_FTP_PAYLOAD = {
    "banner": "220 Gene6 FTP Server v3.10.0 (Build 2) ready...",
    "auth_tls_response": "500 Unknown command",
    "help_response": "214-The following commands are recognized:\nUSER PASS QUIT",
    "smb_native_os": "Windows 5.1",
    "smb_lanman": "Windows 2000 LAN Manager",
    "tcp_window_size": 16384,
}


def test_cowrie_kex_and_banner_match():
    matches = evaluate_signatures("ssh", COWRIE_KEXINIT_PAYLOAD)
    assert len(matches) > 0
    top = matches[0]
    assert top.honeypot_type == "cowrie"
    assert top.confidence >= 0.80
    assert "hassh_match" in top.matched_quirks or "known_default_banner" in top.matched_quirks


def test_conpot_s7comm_match():
    matches = evaluate_signatures("s7comm", CONPOT_SAMPLE_S7)
    assert len(matches) > 0
    top = matches[0]
    assert top.honeypot_type == "conpot"
    assert top.confidence >= 0.75
    assert any("s7_order_code" in q for q in top.matched_quirks)


def test_glastopf_lfi_quirk():
    matches = evaluate_signatures("http", GLASTOPF_HTTP_PAYLOAD)
    assert len(matches) > 0
    top = matches[0]
    assert top.honeypot_type == "glastopf"
    assert top.confidence >= 0.70
    assert "lfi_dummy_passwd" in top.matched_quirks


def test_dionaea_ftp_and_smb():
    matches = evaluate_signatures("dionaea_multi", DIONAEA_FTP_PAYLOAD)
    assert len(matches) > 0
    top = matches[0]
    assert top.honeypot_type == "dionaea"
    assert top.confidence >= 0.65
    # Dionaea mimics ancient Gene6 or archaic Windows 5.1 LanMan signatures
    assert any("gene6_banner" in q or "smb_os_mismatch" in q for q in top.matched_quirks)


def test_clean_ssh_server_low_score():
    clean_payload = {
        "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
        "kex_algorithms": ["curve25519-sha256", "schnorr-something"],
        "hassh": "00000000000000000000000000000000",
        "tcp_window_size": 64240,
    }
    matches = evaluate_signatures("ssh", clean_payload)
    high_conf = [m for m in matches if m.confidence > 0.40]
    assert len(high_conf) == 0


def test_empty_payload_graceful_handling():
    matches = evaluate_signatures("unknown_proto", {})
    assert matches == []
