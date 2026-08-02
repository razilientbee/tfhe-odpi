#!/usr/bin/env python3
"""
Independently re-checks every reservoir_*.txt + .manifest.json pair in a
directory, without trusting the manifest's own self-reported numbers:

  - re-reads the payload file and confirms the line count matches the
    manifest's `accepted` count
  - confirms every line is idempotent under clean_payload_to_line (i.e. it
    really is fully cleaned - no leftover control characters, nothing that
    would change if cleaned again), which is what guarantees the file has
    no embedded newlines splitting a payload across lines
  - confirms every line meets the manifest's min_len
  - recomputes dedup within the file and flags any duplicate that slipped
    through
  - if the manifest is CSV-backed, reports the flow-label match rate so a
    low hit rate (likely column/timestamp mismatch) is visible immediately

Exits non-zero if any reservoir fails a check, so it's usable as a CI-style
gate before the orchestrator/randomizer step consumes these files.

    python scripts/verify_reservoir.py --dir scripts/reservoirs
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from lib.reservoir import clean_payload_to_line, read_reservoir


def verify_one(manifest_path: Path) -> list[str]:
    problems = []
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload_path = Path(manifest["payload_file"])
    label = manifest.get("sublabel") or manifest.get("category", "?")

    if not payload_path.exists():
        return [f"{label}: payload file {payload_path} referenced by manifest does not exist"]

    # read_reservoir() splits strictly on '\n' via plain file iteration, not
    # str.splitlines() - splitlines() also breaks on things like U+2028/
    # U+0085 that can legitimately appear as literal payload content (seen
    # in practice in SSH-Patator's near-random encrypted-noise payloads),
    # which would over-count lines that were never actually split on disk.
    lines = read_reservoir(payload_path)
    if len(lines) != manifest["accepted"]:
        problems.append(
            f"{label}: line count {len(lines)} != manifest accepted={manifest['accepted']}"
        )

    min_len = manifest.get("min_len", 4)
    seen = set()
    for i, line in enumerate(lines):
        recleaned = clean_payload_to_line(line.encode("utf-8", errors="replace"), min_len=0)
        if recleaned != line:
            problems.append(
                f"{label}: line {i} is not idempotent under clean_payload_to_line - "
                f"likely a leftover control character or format drift: {line!r}"
            )
        if len(line) < min_len:
            problems.append(f"{label}: line {i} is shorter than min_len={min_len}: {line!r}")
        if line in seen:
            problems.append(f"{label}: line {i} is a duplicate that slipped past dedup")
        seen.add(line)

    flow_stats = manifest.get("flow_index_stats")
    hit_rate_note = ""
    if flow_stats:
        hit_rate_note = f", CSV flow-label hit rate: {flow_stats.get('hit_rate', 0):.1%}"
        if flow_stats.get("hit_rate", 1.0) < 0.5:
            problems.append(
                f"{label}: flow-label hit rate is only {flow_stats['hit_rate']:.1%} - "
                f"likely a CSV column or timestamp-format mismatch, worth checking before trusting this reservoir"
            )

    status = "OK" if not any(p.startswith(label) for p in problems) else "ISSUES"
    print(f"[{status}] {label}: {manifest['accepted']} payloads, "
          f"cap_hit={manifest.get('cap_hit')}{hit_rate_note}")
    return problems


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dir", default="scripts/reservoirs", help="Directory containing reservoir_*.manifest.json files")
    args = parser.parse_args()

    manifests = sorted(Path(args.dir).glob("*.manifest.json"))
    if not manifests:
        print(f"No manifest files found under {args.dir}")
        sys.exit(1)

    all_problems = []
    for m in manifests:
        all_problems.extend(verify_one(m))

    print()
    if all_problems:
        print(f"=== {len(all_problems)} problem(s) found ===")
        for p in all_problems:
            print(f"  - {p}")
        sys.exit(1)
    else:
        print(f"=== all {len(manifests)} reservoirs passed verification ===")


if __name__ == "__main__":
    main()
