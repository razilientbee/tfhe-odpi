#!/usr/bin/env python3
"""
Extract DoS-category attack payloads from the Wednesday CICIDS2017 capture.
Filter: CSV Label != "BENIGN" (Wednesday's non-benign labels are DoS
GoldenEye/Hulk/Slowhttptest/slowloris plus Heartbleed, which doesn't carry a
"DoS" prefix - matching on != BENIGN rather than a hardcoded label list
picks all of them up without needing to know the exact set in advance).

Matches by (src_ip, src_port, dst_ip, dst_port) alone - no timestamp
involved, see lib/flow_labels.py for why.

Each distinct non-BENIGN label gets its own reservoir file
(reservoir_DoS_<sublabel>.txt) instead of being collapsed into one combined
file - this is what lets a later sampling step apply different rules per
sub-type (e.g. exclude Slowhttptest, which realistically only ever yields
~1 usable payload in this capture).

Sub-labels are enumerated from the CSV up front (a fast, CSV-only pass)
rather than discovered mid-scan, so every reservoir writer already exists
before the pcap scan starts - which makes it safe to stop early once every
writer is full, since there's no risk of a not-yet-seen label showing up
later in the file.

    python scripts/extract_dos.py \\
        --pcap /path/to/Wednesday-workingHours.pcap \\
        --csv /path/to/Wednesday-workingHours.pcap_ISCX.csv \\
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

CATEGORY = "DoS"
BENIGN_LABEL = "BENIGN"


def run(pcap_path: str, csv_path: str, out_dir: str, cap: int,
        min_printable_ratio: float, min_len: int, progress_every: int, quiet: bool,
        stop_at_cap: bool = True):
    log = log_factory(quiet)
    index = FlowLabelIndex(csv_path, verbose=not quiet)

    sub_labels = index.distinct_labels(lambda l: l != BENIGN_LABEL)
    if not sub_labels:
        log("  warning: no non-BENIGN labels found in this CSV - check the CSV path")
    writers: dict[str, ReservoirWriter] = {}
    for raw_label in sub_labels:
        slug = slugify(raw_label)
        writers[raw_label] = ReservoirWriter(
            out_dir=out_dir,
            category=CATEGORY,
            sublabel=slug,
            cap=cap,
            min_printable_ratio=min_printable_ratio,
            min_len=min_len,
            source_pcap=pcap_path,
            source_csv=csv_path,
            filter_description=f'CSV Label == "{raw_label}" (Label != "{BENIGN_LABEL}" on Wednesday)',
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
    print_summary("DoS (+ Heartbleed)", stats_list)
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
