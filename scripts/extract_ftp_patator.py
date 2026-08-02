#!/usr/bin/env python3
"""
Extract FTP-Patator attack payloads from the Tuesday CICIDS2017 capture.

Uses the ORIGINAL hardcoded attacker-IP + dst-port-21 filter (not the CSV
flow-label method the other new categories use). This is deliberate: the
published v1 baseline (99.19% accuracy etc.) was reproduced against payloads
extracted this exact way, and Tuesday's CSV also cleanly labels this attack
via Label == "FTP-Patator" if you ever want to cross-check or switch -
see flow_labels.FlowLabelIndex.

    python scripts/extract_ftp_patator.py \\
        --pcap /path/to/Tuesday-WorkingHours.pcap \\
        --out-dir scripts/reservoirs
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from lib.cli import base_parser, log_factory, print_summary
from lib.pcap_source import iter_tcp_payloads
from lib.reservoir import ReservoirWriter

ATTACKER_IP = "192.168.10.51"
TARGET_PORT = 21
CATEGORY = "FTP-Patator"


def run(pcap_path: str, out_dir: str, cap: int, min_printable_ratio: float, min_len: int,
        progress_every: int, quiet: bool, stop_at_cap: bool = True):
    log = log_factory(quiet)
    writer = ReservoirWriter(
        out_dir=out_dir,
        category=CATEGORY,
        cap=cap,
        min_printable_ratio=min_printable_ratio,
        min_len=min_len,
        source_pcap=pcap_path,
        filter_description=f"src IP == {ATTACKER_IP} and dst port == {TARGET_PORT} (forward direction only)",
    )
    stopped_early = False
    for pkt in iter_tcp_payloads(pcap_path, progress_every=progress_every, log=log):
        writer.note_packet_scanned()
        if writer.full:
            if stop_at_cap:
                stopped_early = True
                break
            continue
        # Forward-direction only: attacker -> victim:21. Deliberately NOT
        # "src or dst == attacker" - that would also match the FTP server's
        # replies flowing back to the attacker, mislabeling ordinary
        # protocol-response content as attack payload. See flow_labels.py's
        # module docstring for the fuller version of this same bug.
        matches = pkt.src_ip == ATTACKER_IP and pkt.dst_port == TARGET_PORT
        if matches:
            writer.try_add(pkt.payload)
    stats = writer.finalize({"stopped_early": stopped_early})
    print_summary("FTP-Patator", [stats])
    return stats


def main():
    parser = base_parser(__doc__)
    args = parser.parse_args()
    run(args.pcap, args.out_dir, args.cap, args.min_printable_ratio, args.min_len,
        args.progress_every, args.quiet, stop_at_cap=not args.no_stop_at_cap)


if __name__ == "__main__":
    main()
