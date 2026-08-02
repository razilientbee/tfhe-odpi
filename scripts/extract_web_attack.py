#!/usr/bin/env python3
"""
Extract Web-Attack-category payloads from the Thursday-Morning CICIDS2017
capture. Filter: CSV Label starts with "Web Attack" (prefix match, not exact
match) - the separator character between "Web Attack" and the sub-type
(Brute Force / XSS / SQL Injection) is corrupted in the source CSV and
renders as a replacement character, so exact string matching on the full
label is unreliable. The prefix lands before the corrupted byte, so it's
unaffected.

Matches by (src_ip, src_port, dst_ip, dst_port) alone - no timestamp
involved, see lib/flow_labels.py for why.

Each distinct raw label still gets its own reservoir file, slugified from
known sub-strings ("Brute Force" / "XSS" / "SQL Injection") rather than the
raw label text, so reservoir filenames stay clean regardless of the
corrupted byte. An unrecognized label falls back to a generic ASCII-stripped
slug and a warning is logged, so it's still captured rather than silently
dropped.

Sub-labels are enumerated from the CSV up front, same reasoning as
extract_dos.py - every reservoir writer exists before the pcap scan
starts, so it's safe to stop early once all of them are full.

    python scripts/extract_web_attack.py \\
        --pcap /path/to/Thursday-WorkingHours-Morning-WebAttacks.pcap \\
        --csv /path/to/Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv \\
        --out-dir scripts/reservoirs
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from lib.cli import base_parser, log_factory, print_summary
from lib.flow_labels import FlowLabelIndex
from lib.pcap_source import iter_tcp_payloads
from lib.reservoir import ReservoirWriter, slugify

CATEGORY = "Web-Attack"
LABEL_PREFIX = "Web Attack"

# Known sub-type keywords, checked in order, case-insensitive substring match
# against the raw label. Keeps output filenames stable and readable even
# though the raw label's separator byte is corrupted in the source CSV.
KNOWN_SUBTYPES = {
    "brute force": "Brute-Force",
    "xss": "XSS",
    "sql injection": "SQL-Injection",
}


def resolve_subtype_slug(raw_label: str, log) -> str:
    lowered = raw_label.lower()
    for keyword, slug in KNOWN_SUBTYPES.items():
        if keyword in lowered:
            return slug
    log(f"  warning: unrecognized Web Attack sub-label {raw_label!r}, "
        f"falling back to a generic slug")
    return slugify(raw_label)


def run(pcap_path: str, csv_path: str, out_dir: str, cap: int,
        min_printable_ratio: float, min_len: int, progress_every: int, quiet: bool,
        stop_at_cap: bool = True):
    log = log_factory(quiet)
    index = FlowLabelIndex(csv_path, verbose=not quiet)

    sub_labels = index.distinct_labels(lambda l: l.startswith(LABEL_PREFIX))
    if not sub_labels:
        log(f"  warning: no label starting with {LABEL_PREFIX!r} found in this CSV - check the CSV path")
    writers: dict[str, ReservoirWriter] = {}
    for raw_label in sub_labels:
        slug = resolve_subtype_slug(raw_label, log)
        writers[raw_label] = ReservoirWriter(
            out_dir=out_dir,
            category=CATEGORY,
            sublabel=slug,
            cap=cap,
            min_printable_ratio=min_printable_ratio,
            min_len=min_len,
            source_pcap=pcap_path,
            source_csv=csv_path,
            filter_description=f'CSV Label starts with "{LABEL_PREFIX}", raw label {raw_label!r}',
        )
        log(f"  pre-created reservoir for sub-label {raw_label!r} -> slug {slug!r}")

    stopped_early = False
    total_scanned = 0
    for pkt in iter_tcp_payloads(pcap_path, progress_every=progress_every, log=log):
        total_scanned += 1
        if stop_at_cap and all(w.full for w in writers.values()):
            stopped_early = True
            break
        label = index.lookup(pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port)
        w = writers.get(label)
        if w is not None:
            w.try_add(pkt.payload)

    stats_list = []
    for raw_label, w in writers.items():
        stats_list.append(
            w.finalize({
                "raw_label": raw_label,
                "stopped_early": stopped_early,
                "run_packets_scanned": total_scanned,
                "flow_index_stats": index.stats(),
            })
        )
    print_summary("Web-Attack", stats_list)
    log(f"  flow label match rate: {index.stats()}")
    return stats_list


def main():
    parser = base_parser(__doc__)
    parser.add_argument("--csv", required=True, help="Path to the matching GeneratedLabelledFlows CSV")
    args = parser.parse_args()
    run(args.pcap, args.csv, args.out_dir, args.cap, args.min_printable_ratio, args.min_len,
        args.progress_every, args.quiet, stop_at_cap=not args.no_stop_at_cap)


if __name__ == "__main__":
    main()
