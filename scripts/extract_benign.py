#!/usr/bin/env python3
"""
Extract benign payloads from the Monday CICIDS2017 capture (Monday carries
no attack traffic in CICIDS2017, so no CSV/label matching is needed here).

Matches the original pcap_to_dataset.py "benign-http" mode exactly:
dst port == 80 AND src IP starts with the internal subnet prefix
"192.168." - i.e. internal clients making outbound HTTP requests.

Forward-direction only, same reasoning as extract_ftp_patator.py and
flow_labels.py: matching on dst_port only (not "src or dst port == 80")
means we capture the client's request, not the server's HTTP response
flowing back on the same connection.

    python scripts/extract_benign.py \\
        --pcap /path/to/Monday-WorkingHours.pcap \\
        --out-dir scripts/reservoirs \\
        --cap 5000
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from lib.cli import base_parser, log_factory, print_summary
from lib.pcap_source import iter_tcp_payloads
from lib.reservoir import ReservoirWriter

CATEGORY = "BENIGN"
HTTP_PORT = 80
INTERNAL_PREFIX = "192.168."


def run(pcap_path: str, out_dir: str, cap: int, min_printable_ratio: float, min_len: int,
        progress_every: int, quiet: bool, port: int, internal_prefix: str | None,
        stop_at_cap: bool = True):
    log = log_factory(quiet)
    filter_desc = f"dst port == {port}"
    if internal_prefix:
        filter_desc += f" and src IP startswith {internal_prefix!r}"
    filter_desc += " (forward direction only, Monday has no attack traffic in CICIDS2017)"
    writer = ReservoirWriter(
        out_dir=out_dir,
        category=CATEGORY,
        cap=cap,
        min_printable_ratio=min_printable_ratio,
        min_len=min_len,
        source_pcap=pcap_path,
        filter_description=filter_desc,
    )
    stopped_early = False
    for pkt in iter_tcp_payloads(pcap_path, progress_every=progress_every, log=log):
        writer.note_packet_scanned()
        if writer.full:
            if stop_at_cap:
                stopped_early = True
                break
            continue
        port_matches = pkt.dst_port == port
        ip_matches = True if not internal_prefix else pkt.src_ip.startswith(internal_prefix)
        if port_matches and ip_matches:
            writer.try_add(pkt.payload)
    stats = writer.finalize({"stopped_early": stopped_early})
    print_summary("BENIGN", [stats])
    return stats


def main():
    parser = base_parser(__doc__)
    parser.add_argument("--port", type=int, default=HTTP_PORT, help="TCP dst port to filter on (default: 80/HTTP)")
    parser.add_argument("--internal-prefix", default=INTERNAL_PREFIX,
                         help='Require src IP to start with this prefix (default: "192.168.", matching the '
                              'original benign-http mode). Pass "" to disable.')
    args = parser.parse_args()
    run(args.pcap, args.out_dir, args.cap, args.min_printable_ratio, args.min_len,
        args.progress_every, args.quiet, args.port, args.internal_prefix or None,
        stop_at_cap=not args.no_stop_at_cap)


if __name__ == "__main__":
    main()
