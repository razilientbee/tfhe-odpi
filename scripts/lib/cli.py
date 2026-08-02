"""Shared CLI scaffolding so every extract_*.py script looks and behaves the same."""

from __future__ import annotations

import argparse


def base_parser(description: str) -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=description)
    p.add_argument("--pcap", required=True, help="Path to the source .pcap file")
    p.add_argument("--out-dir", default="scripts/reservoirs", help="Directory for reservoir_*.txt + manifest output")
    p.add_argument("--cap", type=int, default=1000, help="Max payloads to keep per (category, sub-label)")
    p.add_argument("--min-printable-ratio", type=float, default=0.30, help="Minimum printable-ASCII fraction to accept a payload (checked on raw bytes)")
    p.add_argument("--min-len", type=int, default=4, help="Minimum payload length in characters after cleaning (must match window_len in the Rust pipeline; default 4)")
    p.add_argument("--progress-every", type=int, default=500_000, help="Log a progress line every N packets scanned (0 to disable)")
    p.add_argument("--quiet", action="store_true", help="Suppress per-packet progress logging")
    p.add_argument("--no-stop-at-cap", action="store_true",
                   help="Scan the whole file even after every reservoir is full "
                        "(gives an exact packets_scanned count; slower on huge captures)")
    return p


def log_factory(quiet: bool):
    if quiet:
        return lambda *_args, **_kwargs: None
    return print


def print_summary(title: str, stats_list: list) -> None:
    print()
    print(f"=== {title} ===")
    for stats in stats_list:
        d = stats.as_dict() if hasattr(stats, "as_dict") else stats
        label = d.get("sublabel") or d.get("category", "?")
        cap_flag = "CAP HIT" if d.get("cap_hit") else "exhausted source"
        print(
            f"  {label:<24} accepted={d['accepted']:<6} "
            f"candidates={d['candidates_seen']:<7} "
            f"rejected_printable={d['rejected_not_printable']:<6} "
            f"rejected_short={d.get('rejected_too_short', 0):<6} "
            f"rejected_dup={d['rejected_duplicate']:<6} "
            f"[{cap_flag}] {d['elapsed_seconds']}s"
        )
    print()
