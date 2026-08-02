#!/usr/bin/env python3
"""
Self-contained tests for scripts/lib/*.py. Deliberately dependency-light
(plain asserts, no pytest) so they run anywhere the extraction scripts do:

    python3 scripts/tests/test_pcap_extract.py

Builds a tiny synthetic pcap (via scapy) and a tiny synthetic CICIDS-style
CSV in a temp dir - this validates the extraction *logic* (filtering,
matching, escaping, capping) without needing the real multi-GB CICIDS
captures, which is the point: correctness bugs here should be caught in
seconds, not after an 8-hour scan of the real Wednesday file.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from lib.filters import DedupSet, is_printable_enough, printable_ratio
from lib.flow_labels import FlowLabelIndex
from lib.pcap_source import iter_tcp_payloads
from lib.reservoir import (
    ReservoirWriter,
    clean_payload_to_line,
    read_reservoir,
    slugify,
)

_FAILURES = []


def check(name: str, condition: bool, detail: str = ""):
    if condition:
        print(f"  ok   {name}")
    else:
        msg = f"  FAIL {name}" + (f" - {detail}" if detail else "")
        print(msg)
        _FAILURES.append(name)


# ---------------------------------------------------------------------------
# filters.py
# ---------------------------------------------------------------------------

def test_printable_ratio():
    check("printable_ratio empty", printable_ratio(b"") == 0.0)
    check("printable_ratio all-printable", printable_ratio(b"GET / HTTP/1.1\r\n") == 1.0)
    mixed = bytes([65, 66, 0, 1, 2]) # "AB" + 3 non-printable
    check("printable_ratio mixed", abs(printable_ratio(mixed) - 0.4) < 1e-9, printable_ratio(mixed))
    check("is_printable_enough gate", is_printable_enough(b"AAAA", 0.30) is True)
    check("is_printable_enough rejects binary", is_printable_enough(bytes([0, 1, 2, 3]), 0.30) is False)


def test_dedup():
    d = DedupSet()
    check("dedup first seen is new", d.seen_before(b"payload-a") is False)
    check("dedup repeat is seen", d.seen_before(b"payload-a") is True)
    check("dedup different payload is new", d.seen_before(b"payload-b") is False)
    check("dedup size tracks unique", len(d) == 2, len(d))


# ---------------------------------------------------------------------------
# reservoir.py: payload cleaning (mirrors the original bytes_to_line)
# ---------------------------------------------------------------------------

def test_clean_payload_to_line():
    check(
        "strips a trailing CRLF rather than escaping it",
        clean_payload_to_line(b"USER admin\r\n") == "USER admin",
    )
    check(
        "strips an embedded control byte out of the middle (no separator left behind)",
        clean_payload_to_line(b"AB\x01CD") == "ABCD",
    )
    check(
        "rejects a payload that cleans to fewer than min_len characters",
        clean_payload_to_line(b"\x01\x02ab", min_len=4) is None,
    )
    check(
        "accepts a payload that meets min_len after cleaning",
        clean_payload_to_line(b"\x01\x02abcd", min_len=4) == "abcd",
    )
    result = clean_payload_to_line(b"AB\xffCD")
    check(
        "an invalid UTF-8 byte becomes a replacement character rather than being dropped "
        "(matches the original's lossy-but-deterministic decode behavior)",
        result == "AB\ufffdCD",
        result,
    )


def test_unicode_line_separator_stays_one_line(tmp_dir: Path):
    """Regression test for a bug found on the real SSH-Patator extraction:
    a payload that happens to decode to a Unicode line-separator character
    (U+2028 etc.) must still count as ONE reservoir line, not get split.
    Also demonstrates concretely why read_reservoir() is used rather than
    str.splitlines() anywhere reservoirs are read back."""
    out_dir = tmp_dir / "unicode_sep_reservoir"
    w = ReservoirWriter(out_dir=out_dir, category="TEST", sublabel="unicode", cap=10, min_printable_ratio=0.30)
    payload = b"line-one" + "\u2028".encode("utf-8") + b"-still-one-line"
    check("payload with an embedded U+2028 is accepted", w.try_add(payload) is True)
    stats = w.finalize()
    check("manifest reports exactly 1 accepted", stats.accepted == 1, stats.accepted)

    lines = read_reservoir(w.payload_path)
    check("read_reservoir() correctly counts this as ONE line, not two", len(lines) == 1, lines)

    raw_text = w.payload_path.read_text(encoding="utf-8")
    check(
        "str.splitlines() would have over-counted this as two lines - confirms why "
        "verify_reservoir.py must use read_reservoir(), not splitlines()",
        len(raw_text.splitlines()) == 2,
        raw_text.splitlines(),
    )


def test_slugify():
    check("slugify simple", slugify("DoS Hulk") == "DoS-Hulk")
    check("slugify corrupted separator", slugify("Web Attack \ufffd Brute Force") == "Web-Attack-Brute-Force")
    check("slugify empty falls back", slugify("") == "unknown")


# ---------------------------------------------------------------------------
# reservoir.py: ReservoirWriter end to end
# ---------------------------------------------------------------------------

def test_reservoir_writer(tmp_dir: Path):
    out_dir = tmp_dir / "reservoirs"
    w = ReservoirWriter(out_dir=out_dir, category="TEST", sublabel="sub", cap=3, min_printable_ratio=0.30)

    check("accepts printable payload", w.try_add(b"GET /index.html HTTP/1.1\r\n") is True)
    check("rejects low-printable payload", w.try_add(bytes([0, 1, 2, 3, 4])) is False)
    check("rejects exact duplicate", w.try_add(b"GET /index.html HTTP/1.1\r\n") is False)
    check(
        "dedup catches two different raw byte sequences that clean to the same line "
        "(matches the original, which dedupes post-cleaning)",
        w.try_add(b"GET /index.html HTTP/1.1\r\n\r\n") is False,
    )
    check("accepts second distinct payload", w.try_add(b"POST /login HTTP/1.1\r\n") is True)
    check("accepts third distinct payload", w.try_add(b"HEAD / HTTP/1.1\r\n") is True)
    check("cap enforced: fourth distinct payload rejected", w.try_add(b"PUT /x HTTP/1.1\r\n") is False)

    stats = w.finalize()
    check("stats.accepted == 3", stats.accepted == 3, stats.accepted)
    check("stats.cap_hit is True", stats.cap_hit is True)
    check("stats.rejected_not_printable == 1", stats.rejected_not_printable == 1)
    check("stats.rejected_duplicate == 2", stats.rejected_duplicate == 2, stats.rejected_duplicate)
    check("manifest file exists", w.manifest_path.exists())

    lines = read_reservoir(w.payload_path)
    check("payload file has 3 lines", len(lines) == 3, lines)
    check(
        "written line has no embedded CRLF (control-character-free by construction)",
        lines[0] == "GET /index.html HTTP/1.1",
        lines[0],
    )


# ---------------------------------------------------------------------------
# pcap_source.py + flow_labels.py: build a synthetic pcap + CSV and match them
# ---------------------------------------------------------------------------

def _build_synthetic_pcap(path: Path):
    from scapy.all import IP, TCP, Ether, Raw, wrpcap

    packets = []
    base_ts = 1_600_000_000.0

    # Flow A: attacker -> victim on port 21 (should match an "FTP-Patator"-style filter)
    pkt = Ether() / IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=51000, dport=21) / Raw(b"USER admin\r\n")
    pkt.time = base_ts + 1.0
    packets.append(pkt)

    # Flow B: victim -> attacker reply, same 4-tuple reversed
    pkt = Ether() / IP(src="10.0.0.9", dst="10.0.0.5") / TCP(sport=21, dport=51000) / Raw(b"331 Password required\r\n")
    pkt.time = base_ts + 1.2
    packets.append(pkt)

    # Flow C: a CSV-labeled SSH-Patator-style flow, forward direction
    pkt = Ether() / IP(src="10.0.0.6", dst="10.0.0.9") / TCP(sport=52000, dport=22) / Raw(b"SSH-2.0-paramiko_2.0.0\r\n")
    pkt.time = base_ts + 10.0
    packets.append(pkt)

    # Flow D: pure ACK, no payload - must be skipped entirely by iter_tcp_payloads
    pkt = Ether() / IP(src="10.0.0.6", dst="10.0.0.9") / TCP(sport=52000, dport=22, flags="A")
    pkt.time = base_ts + 10.1
    packets.append(pkt)

    wrpcap(str(path), packets)
    return base_ts


def _build_synthetic_csv(path: Path):
    import pandas as pd

    rows = [
        {
            " Source IP": "10.0.0.5", " Source Port": 51000,
            " Destination IP": "10.0.0.9", " Destination Port": 21,
            " Protocol": 6, " Label": "FTP-Patator",
        },
        {
            " Source IP": "10.0.0.6", " Source Port": 52000,
            " Destination IP": "10.0.0.9", " Destination Port": 22,
            " Protocol": 6, " Label": "SSH-Patator",
        },
    ]
    pd.DataFrame(rows).to_csv(path, index=False)


def test_pcap_and_flow_labels(tmp_dir: Path):
    pcap_path = tmp_dir / "synthetic.pcap"
    csv_path = tmp_dir / "synthetic.csv"
    _build_synthetic_pcap(pcap_path)
    _build_synthetic_csv(csv_path)

    packets = list(iter_tcp_payloads(pcap_path, progress_every=0, log=lambda *_: None))
    check("iter_tcp_payloads skips the empty ACK packet", len(packets) == 3, len(packets))
    check(
        "iter_tcp_payloads preserves payload bytes",
        any(p.payload == b"USER admin\r\n" for p in packets),
    )

    index = FlowLabelIndex(csv_path, verbose=False)

    ftp_pkt = next(p for p in packets if p.payload == b"USER admin\r\n")
    label = index.lookup(ftp_pkt.src_ip, ftp_pkt.src_port, ftp_pkt.dst_ip, ftp_pkt.dst_port)
    check("flow label matches forward direction", label == "FTP-Patator", label)

    reply_pkt = next(p for p in packets if p.payload == b"331 Password required\r\n")
    label_rev = index.lookup(reply_pkt.src_ip, reply_pkt.src_port, reply_pkt.dst_ip, reply_pkt.dst_port)
    check(
        "flow label lookup rejects the reverse/reply direction (regression test for bidirectional contamination)",
        label_rev is None,
        label_rev,
    )

    ssh_pkt = next(p for p in packets if p.payload == b"SSH-2.0-paramiko_2.0.0\r\n")
    label_ssh = index.lookup(ssh_pkt.src_ip, ssh_pkt.src_port, ssh_pkt.dst_ip, ssh_pkt.dst_port)
    check("flow label matches SSH-Patator flow", label_ssh == "SSH-Patator", label_ssh)

    stats = index.stats()
    check("flow index stats: hit_rate is between 0 and 1", 0.0 <= stats["hit_rate"] <= 1.0, stats)


def test_collision_last_one_wins(tmp_dir: Path):
    """The same directed 4-tuple can legitimately appear more than once in
    a real CICIDS CSV with different labels. Matches pcap_to_datasetv2.py's
    proven behavior: the last row read wins, and it's tracked via
    stats()['collisions'] rather than silently hidden."""
    import pandas as pd

    csv_path = tmp_dir / "collision.csv"
    rows = [
        {" Source IP": "10.0.0.1", " Source Port": 1000, " Destination IP": "10.0.0.2",
         " Destination Port": 80, " Protocol": 6, " Label": "BENIGN"},
        {" Source IP": "10.0.0.1", " Source Port": 1000, " Destination IP": "10.0.0.2",
         " Destination Port": 80, " Protocol": 6, " Label": "DoS Hulk"},
    ]
    pd.DataFrame(rows).to_csv(csv_path, index=False)

    index = FlowLabelIndex(csv_path, verbose=False)
    check(
        "a repeated directed 4-tuple with conflicting labels: the last CSV row wins",
        index.lookup("10.0.0.1", 1000, "10.0.0.2", 80) == "DoS Hulk",
    )
    check("the collision is counted, not silently dropped", index.stats()["collisions"] == 1, index.stats())


def test_distinct_labels(tmp_dir: Path):
    """Sub-labels must be enumerable from the CSV alone, before any pcap
    scan starts - this is what makes early-stopping safe in
    extract_dos.py/extract_web_attack.py."""
    import pandas as pd

    csv_path = tmp_dir / "distinct_labels.csv"
    rows = [
        {" Source IP": "10.0.0.1", " Source Port": 1, " Destination IP": "10.0.0.9",
         " Destination Port": 80, " Protocol": 6, " Label": "BENIGN"},
        {" Source IP": "10.0.0.2", " Source Port": 2, " Destination IP": "10.0.0.9",
         " Destination Port": 80, " Protocol": 6, " Label": "DoS Hulk"},
        {" Source IP": "10.0.0.3", " Source Port": 3, " Destination IP": "10.0.0.9",
         " Destination Port": 80, " Protocol": 6, " Label": "Heartbleed"},
    ]
    pd.DataFrame(rows).to_csv(csv_path, index=False)

    index = FlowLabelIndex(csv_path, verbose=False)
    check(
        "distinct_labels() enumerates non-BENIGN labels from the CSV alone",
        index.distinct_labels(lambda l: l != "BENIGN") == ["DoS Hulk", "Heartbleed"],
        index.distinct_labels(lambda l: l != "BENIGN"),
    )


def test_ftp_patator_forward_only(tmp_dir: Path):
    import extract_ftp_patator
    from scapy.all import IP, TCP, Ether, Raw, wrpcap

    pcap_path = tmp_dir / "ftp_direction.pcap"
    base_ts = 1_600_000_000.0
    packets = []

    fwd = Ether() / IP(src="192.168.10.51", dst="10.0.0.9") / TCP(sport=51000, dport=21) / Raw(b"USER admin\r\n")
    fwd.time = base_ts
    packets.append(fwd)

    reply = Ether() / IP(src="10.0.0.9", dst="192.168.10.51") / TCP(sport=21, dport=51000) / Raw(b"331 Password required\r\n")
    reply.time = base_ts + 0.1
    packets.append(reply)

    wrpcap(str(pcap_path), packets)
    out_dir = tmp_dir / "ftp_reservoir"
    stats = extract_ftp_patator.run(
        str(pcap_path), str(out_dir), cap=10, min_printable_ratio=0.30, min_len=4,
        progress_every=0, quiet=True, stop_at_cap=False,
    )
    check(
        "extract_ftp_patator accepts only the forward (attacker->victim) packet, "
        "not the server's reply (regression test for bidirectional contamination)",
        stats.accepted == 1,
        stats.accepted,
    )


def test_benign_forward_only(tmp_dir: Path):
    import extract_benign
    from scapy.all import IP, TCP, Ether, Raw, wrpcap

    pcap_path = tmp_dir / "benign_direction.pcap"
    base_ts = 1_600_000_000.0
    packets = []

    req = Ether() / IP(src="192.168.1.20", dst="10.0.0.9") / TCP(sport=40000, dport=80) / Raw(b"GET / HTTP/1.1\r\n")
    req.time = base_ts
    packets.append(req)

    resp = Ether() / IP(src="10.0.0.9", dst="192.168.1.20") / TCP(sport=80, dport=40000) / Raw(b"HTTP/1.1 200 OK\r\n")
    resp.time = base_ts + 0.1
    packets.append(resp)

    wrpcap(str(pcap_path), packets)
    out_dir = tmp_dir / "benign_reservoir"
    stats = extract_benign.run(
        str(pcap_path), str(out_dir), cap=10, min_printable_ratio=0.30, min_len=4,
        progress_every=0, quiet=True, port=80, internal_prefix="192.168.",
        stop_at_cap=False,
    )
    check(
        "extract_benign accepts only the client request, not the server's response "
        "(regression test for bidirectional contamination)",
        stats.accepted == 1,
        stats.accepted,
    )


def main():
    tmp_dir = Path(tempfile.mkdtemp(prefix="tfhe_odpi_reservoir_tests_"))
    try:
        print("== filters.py ==")
        test_printable_ratio()
        test_dedup()
        print("== reservoir.py: payload cleaning/slugify ==")
        test_clean_payload_to_line()
        test_unicode_line_separator_stays_one_line(tmp_dir)
        test_slugify()
        print("== reservoir.py: ReservoirWriter ==")
        test_reservoir_writer(tmp_dir)
        print("== pcap_source.py + flow_labels.py ==")
        test_pcap_and_flow_labels(tmp_dir)
        test_collision_last_one_wins(tmp_dir)
        test_distinct_labels(tmp_dir)
        print("== extract_ftp_patator.py / extract_benign.py: direction regression ==")
        test_ftp_patator_forward_only(tmp_dir)
        test_benign_forward_only(tmp_dir)
    except Exception:
        traceback.print_exc()
        _FAILURES.append("unhandled exception")
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    print()
    if _FAILURES:
        print(f"=== {len(_FAILURES)} test(s) FAILED ===")
        for name in _FAILURES:
            print(f"  - {name}")
        sys.exit(1)
    print("=== all tests passed ===")


if __name__ == "__main__":
    main()
