"""
Loads a CICIDS2017-style GeneratedLabelledFlows CSV (CICFlowMeter output) and
answers: "what Label applies to this packet's 5-tuple?"

Design notes (read before changing matching behaviour):

- Matching is a plain (src_ip, src_port, dst_ip, dst_port) -> label
  dictionary lookup. NO TIMESTAMP INVOLVED. This is a deliberate rebuild
  around what Rosh's earlier, already-validated pcap_to_datasetv2.py did
  (it produced 500 SSH-Patator / 308 DoS / 308 Web-Attack / 500
  Infiltration payloads successfully) - that script never touched the CSV's
  Timestamp column at all. An earlier version of this module added
  timestamp-window matching on top of the 4-tuple key, reasoning it would
  guard against the same 4-tuple being reused later in the capture for an
  unrelated flow. That reasoning wasn't wrong in principle, but it turned
  out to be unnecessary complexity that introduced three real bugs in a
  row (a pandas datetime-unit mismatch, day-first vs month-first date
  parsing, and a local-time-vs-UTC offset) chasing a risk that apparently
  doesn't materialize in practice on this dataset. Removed entirely rather
  than patched a fourth time - simpler and matches what's actually been
  proven to work.
- Matching is FORWARD-DIRECTION-ONLY, on purpose. CICFlowMeter records
  "Source IP/Port" as whoever sent the flow's first packet (the
  attacker/client), and "Destination IP/Port" as the other side (the
  victim/server). A packet only matches a flow's label if its own
  (src_ip, src_port) equals that flow's Source and its (dst_ip, dst_port)
  equals that flow's Destination - i.e. only the attacker's outbound
  packets. The victim's replies (same 4-tuple, reversed) deliberately do
  NOT match. This is the fix for a genuinely real bug found earlier
  (bidirectional/canonical-key matching pulled in victim response packets
  and mislabeled them with the attack's label) and is unrelated to the
  timestamp removal above - it stays.
- CICIDS2017 CSVs are notorious for leading spaces in column headers
  (" Source IP", " Label", ...). Columns are stripped and matched
  case-insensitively so this doesn't bite silently.
- Only Protocol == 6 (TCP) rows are indexed, since every extraction script
  in this pipeline only ever looks at TCP payloads.
- KNOWN, ACCEPTED LIMITATION: if the exact same directed 4-tuple appears in
  the CSV more than once with DIFFERENT labels, the last row read wins -
  matching pcap_to_datasetv2.py's dict-overwrite behavior exactly, since
  that's the behavior that was actually validated. `collisions` in
  stats() reports how often this happened; check it if a hit rate looks
  suspiciously wrong, but a low nonzero count is expected and not itself
  a bug.
- No fallback: if the 4-tuple doesn't match anything, lookup() returns
  None and the caller drops the packet rather than risk mislabeling
  attack/benign data. Check `unmatched` in stats() if the match rate
  looks low - it usually means a column-name mismatch worth fixing, not a
  genuinely unlabeled packet.
"""

from __future__ import annotations

from pathlib import Path

import pandas as pd

_DEFAULT_COLUMN_CANDIDATES = {
    "src_ip": ["source ip", "src ip", "srcip"],
    "src_port": ["source port", "src port", "srcport"],
    "dst_ip": ["destination ip", "dst ip", "dstip"],
    "dst_port": ["destination port", "dst port", "dstport"],
    "protocol": ["protocol"],
    "label": ["label"],
}


def _resolve_columns(columns: list[str]) -> dict[str, str]:
    lowered = {c.lower().strip(): c for c in columns}
    resolved = {}
    missing = []
    for field, candidates in _DEFAULT_COLUMN_CANDIDATES.items():
        found = next((lowered[c] for c in candidates if c in lowered), None)
        if found is None:
            missing.append(field)
        else:
            resolved[field] = found
    if missing:
        raise ValueError(
            f"Could not find columns for {missing} in CSV. "
            f"Available columns: {sorted(lowered.values())}"
        )
    return resolved


class FlowLabelIndex:
    def __init__(self, csv_path: str | Path, verbose: bool = True) -> None:
        self.csv_path = Path(csv_path)
        df = pd.read_csv(self.csv_path, low_memory=False, encoding_errors='replace')
        df.columns = [c.strip() for c in df.columns]
        cols = _resolve_columns(list(df.columns))
        if verbose:
            print(f"[flow_labels] {self.csv_path.name}: resolved columns -> {cols}")

        df = df[pd.to_numeric(df[cols["protocol"]], errors="coerce") == 6]

        self._index: dict[tuple, str] = {}
        collisions = 0
        n_rows = 0
        for src_ip, src_port, dst_ip, dst_port, label in zip(
            df[cols["src_ip"]], df[cols["src_port"]],
            df[cols["dst_ip"]], df[cols["dst_port"]], df[cols["label"]],
        ):
            key = (str(src_ip), int(src_port), str(dst_ip), int(dst_port))
            label = str(label).strip()
            if key in self._index and self._index[key] != label:
                collisions += 1
            self._index[key] = label  # last row wins - matches the validated reference behavior
            n_rows += 1

        self.label_counts = df[cols["label"]].astype(str).str.strip().value_counts().to_dict()
        self._collisions = collisions
        self._lookups = 0
        self._hits = 0
        if verbose:
            print(f"[flow_labels] indexed {n_rows} TCP flow rows, {len(self._index)} unique directed 4-tuples"
                  f"{f' ({collisions} had conflicting labels, last one kept)' if collisions else ''}")
            print(f"[flow_labels] label distribution in CSV: {self.label_counts}")

    def lookup(self, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> str | None:
        """Forward-direction-only: only matches if this packet's own
        (src_ip, src_port, dst_ip, dst_port) equals a flow's recorded
        (Source, Destination) exactly. For a reply/reverse-direction
        packet this correctly returns None."""
        self._lookups += 1
        label = self._index.get((src_ip, src_port, dst_ip, dst_port))
        if label is not None:
            self._hits += 1
        return label

    def distinct_labels(self, predicate=lambda label: True) -> list[str]:
        """Sorted distinct labels present in the index matching predicate.
        Lets callers pre-create one output reservoir per sub-label before
        scanning the (possibly huge) pcap, rather than discovering
        sub-labels mid-scan."""
        return sorted({lbl for lbl in self._index.values() if predicate(lbl)})

    def stats(self) -> dict:
        return dict(
            lookups=self._lookups,
            hits=self._hits,
            unmatched=self._lookups - self._hits,
            hit_rate=(self._hits / self._lookups) if self._lookups else 0.0,
            collisions=self._collisions,
        )
