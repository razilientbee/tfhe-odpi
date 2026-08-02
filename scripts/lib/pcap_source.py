"""
Streams TCP payloads out of a pcap file one packet at a time.

Uses scapy's PcapReader (not rdpcap/sniff(offline=...)) specifically because
PcapReader lazily reads one packet at a time from disk instead of loading the
entire capture into memory first - the difference between this working and
OOM-killing itself on a 13M-packet file like the Wednesday CICIDS capture.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

from scapy.all import IP, TCP, PcapReader


@dataclass
class TcpPacket:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    ts: float
    payload: bytes


def iter_tcp_payloads(
    pcap_path: str | Path,
    progress_every: int = 500_000,
    log: Callable[[str], None] = print,
) -> Iterator[TcpPacket]:
    """
    Yields a TcpPacket for every packet that has an IP+TCP layer and a
    non-empty TCP payload. Packets without a payload (pure ACKs, SYN/FIN
    control packets, etc.) are skipped before the caller ever sees them,
    since no extraction script wants those.
    """
    pcap_path = Path(pcap_path)
    scanned = 0
    yielded = 0
    t0 = time.monotonic()
    with PcapReader(str(pcap_path)) as reader:
        for pkt in reader:
            scanned += 1
            if progress_every and scanned % progress_every == 0:
                elapsed = time.monotonic() - t0
                rate = scanned / elapsed if elapsed > 0 else 0.0
                log(f"  [{pcap_path.name}] scanned {scanned:,} packets, "
                    f"{yielded:,} with payload ({rate:,.0f} pkt/s)")
            if IP not in pkt or TCP not in pkt:
                continue
            tcp = pkt[TCP]
            payload = bytes(tcp.payload)
            if not payload:
                continue
            ip = pkt[IP]
            yielded += 1
            yield TcpPacket(
                src_ip=ip.src,
                src_port=int(tcp.sport),
                dst_ip=ip.dst,
                dst_port=int(tcp.dport),
                ts=float(pkt.time),
                payload=payload,
            )
    elapsed = time.monotonic() - t0
    log(f"  [{pcap_path.name}] done: {scanned:,} packets scanned, "
        f"{yielded:,} had a TCP payload, {elapsed:.1f}s total")
