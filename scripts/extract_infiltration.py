#!/usr/bin/env python3
"""
Extract Infiltration attack payloads from the Thursday-Afternoon CICIDS2017
capture, using the GeneratedLabelledFlows CSV as ground truth
(Label == "Infiltration").

Matches by (src_ip, src_port, dst_ip, dst_port) alone - no timestamp
involved, see lib/flow_labels.py for why.

Note from prior runs: this category only has ~6 unique underlying flow
tuples and its payloads are cleartext Windows shell session I/O (banner,
prompt, an internal nmap command) rather than protocol-header attack
payloads - structurally different from the other categories. A cap of 1000
is unlikely to bind; this run mainly confirms the true ceiling.

    python scripts/extract_infiltration.py \\
        --pcap /path/to/Thursday-WorkingHours-Afternoon-Infilteration.pcap \\
        --csv /path/to/Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv \\
        --out-dir scripts/reservoirs
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from lib.cli import base_parser, log_factory, print_summary
from lib.flow_labels import FlowLabelIndex
from lib.pcap_source import iter_tcp_payloads
from lib.reservoir import ReservoirWriter

CATEGORY = "Infiltration"
TARGET_LABEL = "Infiltration"


def run(pcap_path: str, csv_path: str, out_dir: str, cap: int,
        min_printable_ratio: float, min_len: int, progress_every: int, quiet: bool,
        stop_at_cap: bool = True):
    log = log_factory(quiet)
    index = FlowLabelIndex(csv_path, verbose=not quiet)
    writer = ReservoirWriter(
        out_dir=out_dir,
        category=CATEGORY,
        cap=cap,
        min_printable_ratio=min_printable_ratio,
        min_len=min_len,
        source_pcap=pcap_path,
        source_csv=csv_path,
        filter_description=f'CSV Label == "{TARGET_LABEL}"',
    )
    stopped_early = False
    for pkt in iter_tcp_payloads(pcap_path, progress_every=progress_every, log=log):
        writer.note_packet_scanned()
        if writer.full:
            if stop_at_cap:
                stopped_early = True
                break
            continue
        label = index.lookup(pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port)
        if label == TARGET_LABEL:
            writer.try_add(pkt.payload)
    stats = writer.finalize({"stopped_early": stopped_early, "flow_index_stats": index.stats()})
    print_summary("Infiltration", [stats])
    log(f"  flow label match rate: {index.stats()}")
    return stats


def main():
    parser = base_parser(__doc__)
    parser.add_argument("--csv", required=True, help="Path to the matching GeneratedLabelledFlows CSV")
    args = parser.parse_args()
    run(args.pcap, args.csv, args.out_dir, args.cap, args.min_printable_ratio, args.min_len,
        args.progress_every, args.quiet, stop_at_cap=not args.no_stop_at_cap)


if __name__ == "__main__":
    main()
