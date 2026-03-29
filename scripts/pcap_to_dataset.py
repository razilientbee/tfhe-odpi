#!/usr/bin/env python3
# =============================================================
# pcap_to_dataset.py
# =============================================================
# Module 0 — PCAP to TFHE-ODPI Dataset Converter
#
# Purpose
# -------
# Extracts raw application-layer payload bytes from PCAP files
# and converts them into the line-per-payload text format
# consumed by the Rust TFHE-ODPI pipeline.
#
# Supported modes
# ---------------
#   attack      : FTP-Patator payloads from Tuesday PCAP
#                 (src=192.168.10.51, dst_port=21)
#
#   benign-ftp  : Benign FTP payloads from Monday PCAP
#                 (dst_port=21, excluding attacker IPs,
#                  excluding payloads containing USER/PASS)
#
#   benign-http : Benign HTTP payloads from Monday PCAP
#                 (dst_port=80, src in internal subnet,
#                  has TCP payload)
#                 RECOMMENDED — clearly distinct from attack
#                 traffic, diverse payloads, no credential
#                 keyword overlap with FTP rules
#
# Output format
# -------------
# One payload per line, UTF-8 encoded, whitespace trimmed.
# Payloads shorter than MIN_LEN bytes are skipped.
# Pure binary payloads are skipped.
#
# Usage
# -----
#   # Extract 500 FTP-Patator attack payloads
#   python3 scripts/pcap_to_dataset.py \
#       --mode attack \
#       --pcap data/pcap/Tuesday-WorkingHours.pcap \
#       --out  data/ftp_attack_payloads.txt \
#       --labels data/ftp_attack_labels.txt \
#       --limit 500
#
#   # Extract 500 benign HTTP payloads
#   python3 scripts/pcap_to_dataset.py \
#       --mode benign-http \
#       --pcap data/pcap/Monday-WorkingHours.pcap \
#       --out  data/http_benign_payloads.txt \
#       --labels data/http_benign_labels.txt \
#       --limit 500
#
#   # Combine into final dataset
#   cat data/ftp_attack_payloads.txt data/http_benign_payloads.txt \
#       > data/cicids_dataset.txt
#   cat data/ftp_attack_labels.txt data/http_benign_labels.txt \
#       > data/cicids_labels.txt
#
# Pipeline position
# -----------------
#   PCAP file
#       ↓
#   pcap_to_dataset.py  (this script)
#       ↓
#   data/cicids_dataset.txt + data/cicids_labels.txt
#       ↓
#   TFHE-ODPI Rust pipeline (main.rs)
#
# =============================================================

import argparse
import sys
import os
from scapy.all import PcapReader, TCP, UDP, Raw
from scapy.layers.inet import IP

# =============================================================
# Configuration
# =============================================================

# Known attacker IP for FTP-Patator in CIC-IDS2017 Tuesday
ATTACKER_IPS = {"192.168.10.51"}

# Internal subnet prefix — used to filter benign HTTP clients
INTERNAL_PREFIX = "192.168."

# FTP control port
FTP_PORT = 21

# HTTP port
HTTP_PORT = 80

# Minimum payload length (must match window_len in Rust pipeline)
MIN_LEN = 4

# FTP credential keywords — exclude from benign-ftp mode
FTP_CREDENTIAL_KEYWORDS = {b"USER", b"PASS"}

# Labels
LABEL_ATTACK = "FTP-Patator"
LABEL_BENIGN = "BENIGN"


# =============================================================
# Shared utilities
# =============================================================

def is_printable(payload_bytes: bytes, threshold: float = 0.3) -> bool:
    """
    Return True if at least threshold fraction of bytes are
    printable ASCII (0x20-0x7E) or common whitespace.

    Threshold of 30% keeps binary-heavy FTP payloads that
    still contain rule keywords. Pure binary is excluded.
    """
    if len(payload_bytes) == 0:
        return False
    printable = sum(
        1 for b in payload_bytes
        if 0x20 <= b <= 0x7E or b in (0x09, 0x0A, 0x0D)
    )
    return (printable / len(payload_bytes)) >= threshold


def extract_raw_payload(packet) -> bytes | None:
    """
    Extract raw TCP payload bytes from a packet.
    Returns None if no payload or payload too short.
    """
    if not packet.haslayer(TCP) or not packet.haslayer(Raw):
        return None
    payload = bytes(packet[Raw].load)
    if len(payload) < MIN_LEN:
        return None
    return payload


def bytes_to_line(payload_bytes: bytes) -> str | None:
    """
    Convert payload bytes to a clean text line.
    Returns None if payload is not suitable for the pipeline.
    """
    if not is_printable(payload_bytes):
        return None

    try:
        line = payload_bytes.decode("utf-8", errors="replace").strip()
    except Exception:
        line = payload_bytes.decode("latin-1", errors="replace").strip()

    # Remove null bytes and non-printable control characters
    line = "".join(
        c for c in line
        if c >= " " or c in ("\t",)
    ).strip()

    if len(line) < MIN_LEN:
        return None
    return line


def contains_credential_keyword(payload_bytes: bytes) -> bool:
    """
    Return True if payload starts with a FTP credential keyword.
    Used to exclude USER/PASS from benign-ftp mode.
    """
    upper = payload_bytes.upper()
    for kw in FTP_CREDENTIAL_KEYWORDS:
        if upper.startswith(kw):
            return True
    return False


# =============================================================
# Mode: attack — FTP-Patator from Tuesday PCAP
# =============================================================

def extract_attack_payloads(pcap_path: str, limit: int) -> list[tuple[str, str]]:
    """
    Extract FTP-Patator attack payloads from Tuesday PCAP.

    Filter:
      - src IP in ATTACKER_IPS
      - dst port 21 (FTP control)
      - has TCP payload

    Returns list of (payload_line, label) tuples.
    Deduplicates identical payloads.
    """
    print(f"[attack] Loading: {pcap_path}")
    print(f"[attack] Streaming through file (this may take several minutes)...")

    results = []
    seen = set()
    count = 0
    processed = 0

    with PcapReader(pcap_path) as reader:
        for packet in reader:
            processed += 1

            if processed % 100_000 == 0:
                print(f"  Scanned {processed:>10,} packets | found {count} attack payloads")

            if count >= limit:
                break

            if not packet.haslayer(IP) or not packet.haslayer(TCP):
                continue

            src_ip = packet[IP].src
            dst_port = packet[TCP].dport

            if src_ip not in ATTACKER_IPS or dst_port != FTP_PORT:
                continue

            raw = extract_raw_payload(packet)
            if raw is None:
                continue

            line = bytes_to_line(raw)
            if line is None or line in seen:
                continue

            seen.add(line)
            results.append((line, LABEL_ATTACK))
            count += 1

    print(f"[attack] Done — {len(results)} unique attack payloads from {processed:,} packets")
    return results


# =============================================================
# Mode: benign-ftp — Benign FTP from Monday PCAP
# =============================================================

def extract_benign_ftp_payloads(pcap_path: str, limit: int) -> list[tuple[str, str]]:
    """
    Extract benign FTP payloads from Monday PCAP.

    Filter:
      - dst port 21
      - src IP NOT in ATTACKER_IPS
      - payload does NOT start with USER or PASS
        (avoids overlap with attack rule keywords)

    Returns list of (payload_line, label) tuples.
    """
    print(f"[benign-ftp] Loading: {pcap_path}")
    print(f"[benign-ftp] Streaming through file...")

    results = []
    seen = set()
    count = 0
    processed = 0

    with PcapReader(pcap_path) as reader:
        for packet in reader:
            processed += 1

            if processed % 100_000 == 0:
                print(f"  Scanned {processed:>10,} packets | found {count} benign-ftp payloads")

            if count >= limit:
                break

            if not packet.haslayer(IP) or not packet.haslayer(TCP):
                continue

            src_ip = packet[IP].src
            dst_port = packet[TCP].dport

            if dst_port != FTP_PORT or src_ip in ATTACKER_IPS:
                continue

            raw = extract_raw_payload(packet)
            if raw is None:
                continue

            # Exclude credential keywords — these overlap with attack rules
            if contains_credential_keyword(raw):
                continue

            line = bytes_to_line(raw)
            if line is None or line in seen:
                continue

            seen.add(line)
            results.append((line, LABEL_BENIGN))
            count += 1

    print(f"[benign-ftp] Done — {len(results)} unique benign-ftp payloads from {processed:,} packets")
    return results


# =============================================================
# Mode: benign-http — Benign HTTP from Monday PCAP
# =============================================================

def extract_benign_http_payloads(pcap_path: str, limit: int) -> list[tuple[str, str]]:
    """
    Extract benign HTTP payloads from Monday PCAP.

    Filter:
      - dst port 80 (HTTP)
      - src IP starts with INTERNAL_PREFIX (internal clients only)
      - has TCP payload

    Why HTTP benign traffic is the best negative class:
      - Clearly distinct from FTP attack traffic
      - No USER/PASS keyword overlap
      - Rich diverse payloads (GET, POST, Host, headers)
      - Abundant in Monday PCAP (25 simulated HTTP users)

    Returns list of (payload_line, label) tuples.
    """
    print(f"[benign-http] Loading: {pcap_path}")
    print(f"[benign-http] Streaming through file...")

    results = []
    seen = set()
    count = 0
    processed = 0

    with PcapReader(pcap_path) as reader:
        for packet in reader:
            processed += 1

            if processed % 100_000 == 0:
                print(f"  Scanned {processed:>10,} packets | found {count} benign-http payloads")

            if count >= limit:
                break

            if not packet.haslayer(IP) or not packet.haslayer(TCP):
                continue

            src_ip = packet[IP].src
            dst_port = packet[TCP].dport

            # Internal clients sending HTTP requests
            if dst_port != HTTP_PORT or not src_ip.startswith(INTERNAL_PREFIX):
                continue

            raw = extract_raw_payload(packet)
            if raw is None:
                continue

            line = bytes_to_line(raw)
            if line is None or line in seen:
                continue

            seen.add(line)
            results.append((line, LABEL_BENIGN))
            count += 1

    print(f"[benign-http] Done — {len(results)} unique benign-http payloads from {processed:,} packets")
    return results


# =============================================================
# Output writing
# =============================================================

def write_outputs(
    results: list[tuple[str, str]],
    payload_path: str,
    label_path: str
) -> None:
    """
    Write payload lines and labels to separate output files.
    One entry per line, aligned by line number.
    """
    os.makedirs(os.path.dirname(payload_path) or ".", exist_ok=True)
    os.makedirs(os.path.dirname(label_path) or ".", exist_ok=True)

    with open(payload_path, "w", encoding="utf-8") as pf, \
         open(label_path,  "w", encoding="utf-8") as lf:
        for line, label in results:
            pf.write(line + "\n")
            lf.write(label + "\n")

    print(f"[output] Payloads → {payload_path}")
    print(f"[output] Labels   → {label_path}")
    print(f"[output] Records  : {len(results)}")


# =============================================================
# Summary
# =============================================================

def print_summary(results: list[tuple[str, str]], mode: str) -> None:
    """
    Print extraction statistics and sample payloads.
    """
    labels   = [r[1] for r in results]
    payloads = [r[0] for r in results]
    lengths  = [len(p) for p in payloads]

    attack_count = sum(1 for l in labels if l != LABEL_BENIGN)
    benign_count = sum(1 for l in labels if l == LABEL_BENIGN)

    print()
    print("=" * 55)
    print(" Dataset Summary")
    print("=" * 55)
    print(f" Mode            : {mode}")
    print(f" Total payloads  : {len(results)}")
    print(f" Attack          : {attack_count}")
    print(f" Benign          : {benign_count}")
    if lengths:
        print(f" Min length      : {min(lengths)} bytes")
        print(f" Max length      : {max(lengths)} bytes")
        print(f" Avg length      : {sum(lengths)/len(lengths):.1f} bytes")
    print()
    print(" Sample payloads:")
    for line, label in results[:8]:
        preview = line[:60] + "..." if len(line) > 60 else line
        print(f"  [{label:12}] {preview}")
    print("=" * 55)


# =============================================================
# Entry point
# =============================================================

def main():
    parser = argparse.ArgumentParser(
        description="TFHE-ODPI Module 0 — PCAP to dataset converter",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
modes:
  attack      FTP-Patator attack payloads (Tuesday PCAP)
  benign-ftp  Benign FTP payloads excluding USER/PASS (Monday PCAP)
  benign-http Benign HTTP payloads — RECOMMENDED negative class (Monday PCAP)
        """
    )
    parser.add_argument(
        "--mode",
        choices=["attack", "benign-ftp", "benign-http"],
        required=True,
        help="Extraction mode"
    )
    parser.add_argument(
        "--pcap",
        required=True,
        help="Path to input PCAP file"
    )
    parser.add_argument(
        "--out",
        required=True,
        help="Path to output payload text file"
    )
    parser.add_argument(
        "--labels",
        required=True,
        help="Path to output labels text file"
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=500,
        help="Maximum unique payloads to extract (default: 500)"
    )

    args = parser.parse_args()

    if not os.path.exists(args.pcap):
        print(f"ERROR: PCAP file not found: {args.pcap}")
        sys.exit(1)

    # Dispatch to correct extractor
    if args.mode == "attack":
        results = extract_attack_payloads(args.pcap, args.limit)
    elif args.mode == "benign-ftp":
        results = extract_benign_ftp_payloads(args.pcap, args.limit)
    else:
        results = extract_benign_http_payloads(args.pcap, args.limit)

    if not results:
        print("ERROR: No payloads extracted. Check PCAP path and filters.")
        sys.exit(1)

    write_outputs(results, args.out, args.labels)
    print_summary(results, args.mode)


if __name__ == "__main__":
    main()
