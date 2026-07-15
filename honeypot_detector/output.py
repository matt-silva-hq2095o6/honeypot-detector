import json
import sys
import os
from typing import Any, Dict, List, Optional, TextIO

# Terminal formatting helpers without pulling extra dependencies
_USE_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ

RESET = "\033[0m" if _USE_COLOR else ""
BOLD = "\033[1m" if _USE_COLOR else ""
RED = "\033[31m" if _USE_COLOR else ""
YELLOW = "\033[33m" if _USE_COLOR else ""
GREEN = "\033[32m" if _USE_COLOR else ""
CYAN = "\033[36m" if _USE_COLOR else ""
DIM = "\033[2m" if _USE_COLOR else ""


def _color_confidence(score: float) -> str:
    if not _USE_COLOR:
        return f"{score:.2f}"
    if score >= 0.85:
        return f"{RED}{score:.2f}{RESET}"
    elif score >= 0.50:
        return f"{YELLOW}{score:.2f}{RESET}"
    return f"{DIM}{score:.2f}{RESET}"


def _strip_ansi(text: str) -> int:
    # Rough length calculation ignoring ANSI escape codes for alignment
    in_escape = False
    length = 0
    for ch in text:
        if ch == "\033":
            in_escape = True
        elif in_escape:
            if ch == "m":
                in_escape = False
        else:
            length += 1
    return length


def format_jsonl(results: List[Dict[str, Any]], stream: Optional[TextIO] = None) -> None:
    out = stream or sys.stdout
    for item in results:
        line = json.dumps(item, ensure_ascii=False)
        out.write(line + "\n")
    out.flush()


def format_table(results: List[Dict[str, Any]], stream: Optional[TextIO] = None) -> None:
    """Render scan findings to stdout or a file descriptor as a fixed-width table."""
    out = stream or sys.stdout
    if not results:
        out.write("No honeypot indicators detected.\n")
        return

    headers = ["Target", "Proto", "Suspected Honeypot", "Confidence", "Matched Signals"]
    raw_rows = []
    display_rows = []

    for r in results:
        target = f"{r.get('ip', '')}:{r.get('port', '')}"
        service = str(r.get("service", "tcp"))
        hp_type = r.get("honeypot_type", "unknown").upper()
        conf_val = float(r.get("confidence", 0.0))
        
        signals = r.get("matched_quirks", []) or r.get("signals", [])
        signals_str = ", ".join(signals)
        if len(signals_str) > 48:
            signals_str = signals_str[:45] + "..."

        # Keep raw text for calculating padding widths
        raw_rows.append([
            target,
            service,
            hp_type,
            f"{conf_val:.2f}",
            signals_str
        ])

        display_rows.append([
            f"{BOLD}{target}{RESET}" if _USE_COLOR else target,
            service,
            f"{CYAN}{hp_type}{RESET}" if _USE_COLOR else hp_type,
            _color_confidence(conf_val),
            signals_str
        ])

    # print(f"DEBUG: rendering {len(raw_rows)} rows")
    col_widths = [len(h) for h in headers]
    for row in raw_rows:
        for i, val in enumerate(row):
            col_widths[i] = max(col_widths[i], len(val))

    # Header line
    hdr_line = "  ".join([f"{headers[i]:<{col_widths[i]}}" for i in range(len(headers))])
    sep_line = "  ".join(["-" * col_widths[i] for i in range(len(headers))])

    out.write(f"{BOLD}{hdr_line}{RESET}\n")
    out.write(f"{DIM}{sep_line}{RESET}\n")

    for row_idx, disp_row in enumerate(display_rows):
        line_parts = []
        for i, cell in enumerate(disp_row):
            # Pad based on visible characters, not terminal escape codes
            visible_len = _strip_ansi(cell)
            padding = " " * max(0, col_widths[i] - visible_len)
            line_parts.append(cell + padding)
        out.write("  ".join(line_parts) + "\n")

    out.flush()
