# honeypot-detector

CLI scanner that probes IP targets and subnets for honeypot emulation artifacts.

Instead of just checking banners (which are trivial to spoof), it tests protocol-level quirks, malformed packet handling, fixed TCP window sizes, and oddities in handshake state machines.

Detected honeypots:
- **Cowrie**: SSH kex sequence anomalies, fixed SSH payload sizes, default DSA key fingerprints, missing subsystem errors.
- **Dionaea**: static TCP window sizes on non-standard ports, SMB dialect negotiation quirks, generic reject packets.
- **Conpot**: s7comm / Modbus fixed transaction IDs, deterministic TCP options order, missing ISO-on-TCP header checks.
- **Glastopf**: standard dummy headers order, broken status codes on unknown methods.

## Requirements

- Python 3.10+
- Linux / macOS (raw socket probes for TCP SYN require root permissions)

## Install

```bash
git clone https://github.com/dank/honeypot-detector.git
cd honeypot-detector
pip install .
```

## Quick Start

Scan a single target across all default probes:
```bash
sudo hpdetect 192.168.1.50
```

Scan a CIDR block with higher concurrency and JSON output:
```bash
sudo hpdetect 10.0.0.0/24 -t 64 --format json -o results.json
```

Run specific probe modules only:
```bash
sudo hpdetect 192.168.1.50 -p ssh,http --confidence-threshold 60
```

## Options

- `target`: IP address, hostname, or CIDR notation.
- `-p, --probes`: Comma-separated list of probes (`tcp`, `ssh`, `http`). Defaults to all.
- `-t, --threads`: Worker thread count for scanning (default: 20).
- `--timeout`: Socket timeout in seconds per probe (default: 2.5).
- `--format`: Output format, either `table` (default) or `json`.
- `-o, --output`: Write results to file instead of stdout.
- `-v, --verbose`: Show skipped ports and failed probes.

## JSON Output Example

```json
[
  {
    "ip": "192.168.1.50",
    "port": 2222,
    "service": "ssh",
    "matched_honeypot": "Cowrie",
    "confidence": 85,
    "reasons": [
      "SSH kex init payload matches cowrie default cipher list",
      "TCP window size 5840 is static across retransmits"
    ]
  }
]
```

<!-- generated: 2026-09-08 -->
