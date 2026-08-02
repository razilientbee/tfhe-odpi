"""
Reservoir output format: one payload per line, one file per (category, sub-label),
plus a JSON manifest sitting next to it with the extraction's audit trail.

Payload-to-line conversion deliberately mirrors the original pcap_to_dataset.py's
bytes_to_line() exactly: decode as UTF-8 (replacing invalid sequences), strip out
control characters (keep only >= 0x20, plus tab), then re-check a minimum length.
This means a cleaned line can never contain an embedded \\n or \\r - the payload
is single-line by construction, not by escaping. That matters downstream: the
Rust data_loader.rs reads these files with a plain trim()-per-line, no unescape
step, because that's the format the validated v1 baseline (99.19% accuracy etc.)
was built and read against. An earlier version of this module used a lossless
latin-1 + backslash-escaping scheme instead, which preserved raw bytes exactly
but produced a format the existing Rust loader can't consume as-is - reverted in
favor of matching the original exactly.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from .filters import DedupSet, is_printable_enough, printable_ratio

DEFAULT_MIN_LEN = 4  # must match window_len in the Rust pipeline


def clean_payload_to_line(raw: bytes, min_len: int = DEFAULT_MIN_LEN) -> str | None:
    """Mirrors the original bytes_to_line(): decode, strip control chars,
    strip whitespace, re-check length. Returns None if the payload is too
    short to be usable after cleaning (this is a SEPARATE, later check than
    the printable-ratio gate, which runs on the raw bytes before this)."""
    try:
        line = raw.decode("utf-8", errors="replace").strip()
    except Exception:
        line = raw.decode("latin-1", errors="replace").strip()
    line = "".join(c for c in line if c >= " " or c == "\t").strip()
    if len(line) < min_len:
        return None
    return line


def slugify(text: str) -> str:
    """ASCII-safe, filesystem-safe slug for a raw CSV label. Needed because
    some CICIDS labels (Web Attack sub-types) contain a corrupted separator
    byte that renders as a replacement character - dropping non-ASCII bytes
    here keeps filenames clean without needing to guess the "correct" glyph."""
    ascii_text = text.encode("ascii", errors="ignore").decode("ascii").strip()
    out = []
    prev_dash = False
    for ch in ascii_text:
        if ch.isalnum():
            out.append(ch)
            prev_dash = False
        elif not prev_dash:
            out.append("-")
            prev_dash = True
    slug = "".join(out).strip("-")
    return slug or "unknown"


def reservoir_paths(out_dir: Path, category: str, sublabel: str | None) -> tuple[Path, Path]:
    slug = category if not sublabel else f"{category}_{sublabel}"
    slug = slug.replace(" ", "_")
    payload_path = out_dir / f"reservoir_{slug}.txt"
    manifest_path = out_dir / f"reservoir_{slug}.manifest.json"
    return payload_path, manifest_path


@dataclass
class ReservoirStats:
    packets_scanned: int = 0
    candidates_seen: int = 0        # matched the category filter (IP/port or CSV label)
    rejected_not_printable: int = 0
    rejected_too_short: int = 0
    rejected_duplicate: int = 0
    accepted: int = 0
    cap_hit: bool = False
    elapsed_seconds: float = 0.0
    extra: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        d = dict(
            packets_scanned=self.packets_scanned,
            candidates_seen=self.candidates_seen,
            rejected_not_printable=self.rejected_not_printable,
            rejected_too_short=self.rejected_too_short,
            rejected_duplicate=self.rejected_duplicate,
            accepted=self.accepted,
            cap_hit=self.cap_hit,
            elapsed_seconds=round(self.elapsed_seconds, 2),
        )
        d.update(self.extra)
        return d


class ReservoirWriter:
    """
    Accepts candidate payloads one at a time (already filtered down to the
    category's flow/IP match by the caller). Pipeline per candidate:
    printable-ratio gate on raw bytes -> clean to a single text line
    (matching the original bytes_to_line) -> dedup on the CLEANED line
    (matching the original, which dedupes post-cleaning, not on raw bytes)
    -> write. Enforces `cap`. Call finalize() once at the end to flush the
    manifest.
    """

    def __init__(
        self,
        out_dir: Path,
        category: str,
        sublabel: str | None = None,
        cap: int = 1000,
        min_printable_ratio: float = 0.30,
        min_len: int = DEFAULT_MIN_LEN,
        source_pcap: str | None = None,
        source_csv: str | None = None,
        filter_description: str = "",
    ) -> None:
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        self.category = category
        self.sublabel = sublabel
        self.cap = cap
        self.min_printable_ratio = min_printable_ratio
        self.min_len = min_len
        self.payload_path, self.manifest_path = reservoir_paths(out_dir, category, sublabel)
        self._fh = open(self.payload_path, "w", encoding="utf-8", newline="\n")
        self._dedup = DedupSet()
        self.stats = ReservoirStats()
        self.stats.extra.update(
            source_pcap=source_pcap,
            source_csv=source_csv,
            filter_description=filter_description,
            category=category,
            sublabel=sublabel,
            min_printable_ratio=min_printable_ratio,
            min_len=min_len,
            cap=cap,
        )
        self._t0 = time.monotonic()

    @property
    def full(self) -> bool:
        return self.stats.accepted >= self.cap

    def try_add(self, payload: bytes) -> bool:
        """Call this once per candidate payload that already matched the
        category's selection rule. Returns True iff it was written."""
        self.stats.candidates_seen += 1
        if self.full:
            self.stats.cap_hit = True
            return False
        if not is_printable_enough(payload, self.min_printable_ratio):
            self.stats.rejected_not_printable += 1
            return False
        line = clean_payload_to_line(payload, self.min_len)
        if line is None:
            self.stats.rejected_too_short += 1
            return False
        if self._dedup.seen_before(line.encode("utf-8", errors="replace")):
            self.stats.rejected_duplicate += 1
            return False
        self._fh.write(line)
        self._fh.write("\n")
        self.stats.accepted += 1
        if self.stats.accepted >= self.cap:
            self.stats.cap_hit = True
        return True

    def note_packet_scanned(self) -> None:
        self.stats.packets_scanned += 1

    def finalize(self, extra_stats: dict | None = None) -> ReservoirStats:
        self._fh.close()
        self.stats.elapsed_seconds = time.monotonic() - self._t0
        if extra_stats:
            self.stats.extra.update(extra_stats)
        manifest = self.stats.as_dict()
        manifest["payload_file"] = str(self.payload_path)
        with open(self.manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=2, sort_keys=True)
        return self.stats


def read_reservoir(payload_path: Path) -> list[str]:
    """Read a reservoir file back as cleaned line strings (already
    control-character-free, no unescape step needed)."""
    out = []
    with open(payload_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if line == "" and not out:
                continue
            out.append(line)
    return out
