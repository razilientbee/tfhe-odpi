# Reservoir extraction pipeline

Step 1 of the redesigned dataset pipeline: per-category scripts that scan a
CICIDS2017 pcap and produce capped "reservoir" files of candidate payloads.
The orchestrator/randomizer that samples from these reservoirs per a `--p`
tier config (fixed / flexible / rare_include_all / excluded) is step 2, not
built yet.

## Layout

```
scripts/
├── lib/
│   ├── filters.py       # printable-ratio gate, dedup
│   ├── reservoir.py      # ReservoirWriter (cap + cleaning + manifest), slugify
│   ├── flow_labels.py     # CSV flow-label matching (4-tuple only, no timestamp)
│   ├── pcap_source.py     # streaming (constant-memory) TCP payload iterator
│   └── cli.py             # shared argparse + summary printer
├── extract_ftp_patator.py   # Tuesday, hardcoded IP+port (legacy method)
├── extract_ssh_patator.py   # Tuesday, CSV Label == "SSH-Patator"
├── extract_dos.py            # Wednesday, CSV Label != "BENIGN", auto-splits sub-labels
├── extract_web_attack.py     # Thu-Morning, CSV Label prefix "Web Attack", auto-splits sub-labels
├── extract_infiltration.py   # Thu-Afternoon, CSV Label == "Infiltration"
├── extract_benign.py         # Monday, port filter (no CSV needed, Monday has no attacks)
├── verify_reservoir.py       # independent re-check of every reservoir + manifest
└── tests/test_pcap_extract.py  # synthetic self-test, no real data needed
```

Every `extract_*.py` is a thin CLI wrapper around the shared `lib/` modules -
the actual filtering/matching/cleaning/capping logic lives in exactly one
place per concern, so a bug fix in `lib/` fixes every category at once.

## Usage

```bash
python3 scripts/tests/test_pcap_extract.py        # run this first, ~1s, no real data needed

python3 scripts/extract_ftp_patator.py  --pcap /path/Tuesday-WorkingHours.pcap --out-dir scripts/reservoirs
python3 scripts/extract_ssh_patator.py  --pcap /path/Tuesday-WorkingHours.pcap --csv /path/Tuesday-WorkingHours.pcap_ISCX.csv --out-dir scripts/reservoirs
python3 scripts/extract_dos.py          --pcap /path/Wednesday-workingHours.pcap --csv /path/Wednesday-workingHours.pcap_ISCX.csv --out-dir scripts/reservoirs
python3 scripts/extract_web_attack.py   --pcap /path/Thursday-Morning-WebAttacks.pcap --csv /path/Thursday-Morning-WebAttacks.pcap_ISCX.csv --out-dir scripts/reservoirs
python3 scripts/extract_infiltration.py --pcap /path/Thursday-Afternoon-Infilteration.pcap --csv /path/Thursday-Afternoon-Infilteration.pcap_ISCX.csv --out-dir scripts/reservoirs
python3 scripts/extract_benign.py       --pcap /path/Monday-WorkingHours.pcap --out-dir scripts/reservoirs --cap 5000

python3 scripts/verify_reservoir.py --dir scripts/reservoirs
```

All scripts default `--cap` to 1000 and `--min-printable-ratio` to 0.30. Every
script supports `--quiet` and `--progress-every N` (default: log every
500k packets scanned - important on Wednesday's ~13.8M-packet file).

## Output format

Each reservoir is a pair of files: `reservoir_<category>[_<sublabel>].txt`
(one payload per line) and a matching `.manifest.json` (extraction stats:
packets scanned, candidates matched, rejected-not-printable,
rejected-too-short, rejected-duplicate, accepted, cap_hit, elapsed time,
source paths, and for CSV-backed categories the flow-label match rate).

Payload lines are cleaned to match the original `pcap_to_dataset.py`'s
`bytes_to_line()` exactly: UTF-8 decoded (invalid bytes replaced), control
characters stripped out (keeping only printable characters and tab), then
re-checked against `--min-len` (default 4, matching `window_len` in the
Rust pipeline). A payload containing an embedded `\r\n` - common in HTTP -
ends up as one clean line with the control bytes simply removed, not
escaped, so there's nothing to unescape on read and `data_loader.rs` can
keep using a plain per-line `trim()`. Dedup happens on this cleaned text,
not the raw bytes, again matching the original. Read reservoirs back with
`lib.reservoir.read_reservoir()`.

## Design decisions carried over from the redesign discussion

- **DoS and Web-Attack are no longer collapsed into one file per day.**
  Each distinct CSV `Label` value gets its own reservoir
  (`reservoir_DoS_Hulk.txt`, `reservoir_DoS_Heartbleed.txt`,
  `reservoir_Web-Attack_XSS.txt`, ...). Sub-labels are enumerated from the
  CSV up front via `FlowLabelIndex.distinct_labels()` (a fast, CSV-only
  pass) rather than discovered mid-scan, so every reservoir writer already
  exists before the pcap scan starts. This is what lets the orchestrator
  apply a different sampling rule per sub-type later (e.g. exclude
  Slowhttptest), and what makes it safe to stop the scan early once every
  writer is full - there's no risk of an unseen label showing up later,
  because the full label set was already known from the CSV.
- **FTP-Patator keeps the original hardcoded-IP/port method** rather than
  moving to CSV-label matching, specifically so it keeps producing the same
  payload set the published v1 baseline (99.19% accuracy etc.) was measured
  against. Tuesday's CSV does label FTP-Patator cleanly if you ever want to
  cross-check the two methods.
- **Web-Attack sub-label filenames are keyword-matched**
  ("brute force"/"xss"/"sql injection" substrings), not derived from the raw
  label text, because the raw label's separator character is corrupted in
  the source CSV and would otherwise land in a filename.
- **CSV column names are resolved case-insensitively with whitespace
  stripped**, since CICIDS2017 CSVs are known to ship with leading spaces
  in every header (`" Source IP"`, `" Label"`, ...).
- **All matching is forward-direction-only.** A packet only gets a flow's
  label if its own (src_ip, src_port, dst_ip, dst_port) equals that flow's
  recorded (Source, Destination) exactly - the victim/server's replies on
  the same connection deliberately do not match. Same logic in the two
  hardcoded-filter scripts: `extract_ftp_patator.py` matches
  `src_ip == attacker` (not "src or dst"), `extract_benign.py` matches
  `dst_port == 80` (not "src or dst port").
- **CSV flow-label matching uses ONLY the 4-tuple, no timestamp at all.**
  See "the timestamp detour" below for why - this was a real design
  correction, not a minor tweak.

## Confirmed against an earlier session

`extract_benign.py`'s filter matches the original `pcap_to_dataset.py`
`benign-http` mode exactly: `dst port == 80` AND `src IP` starting with
`"192.168."` (the internal subnet prefix), both required. Override with
`--port` / `--internal-prefix` if needed.

## The timestamp detour (read this if you're ever tempted to re-add it)

The first rebuild of `flow_labels.py` matched on (4-tuple + timestamp
window), reasoning that a bare 4-tuple could theoretically be reused later
in a long capture for an unrelated flow with a different label. That
reasoning produced three real bugs in a row against actual data: a pandas
datetime-unit mismatch (every epoch off by 1000x), day-first vs
month-first date parsing (every epoch off by ~88 days), and a local-time-
vs-UTC offset specific to the capture site (every epoch off by ~3 hours).
Each was found, diagnosed, and fixed correctly - but only after Rosh
shared the actual, already-validated `pcap_to_datasetv2.py` from an
earlier session, which turned out to never touch the CSV's `Timestamp`
column at all. It matches on the bare 4-tuple and got 500 SSH-Patator /
308 DoS / 308 Web-Attack / 500 Infiltration payloads doing so. The
"same 4-tuple reused for a different flow" risk that motivated the
timestamp window apparently doesn't materialize enough to matter on this
dataset in practice.

`flow_labels.py` now matches on the 4-tuple only, matching that proven
design. If the same directed 4-tuple appears in the CSV more than once
with different labels, the last row read wins (same dict-overwrite
behavior as the reference script) - tracked via `stats()['collisions']`
rather than silently hidden, so it's visible if it ever becomes a real
problem on a different dataset. `verify_reservoir.py`'s "flow-label hit
rate under 50%" check still applies; a low hit rate now points at a
column-name mismatch, not a timestamp issue, since there isn't one anymore.

## Bugs the test suite (and outside review) caught before they could do real damage

**Bidirectional contamination, reintroduced.** The original pipeline had
already fixed this once: matching a flow's label bidirectionally pulls in
the victim's response packets (a plain FTP `331 Password required` or an
HTTP `200 OK`) and mislabels them with the attack's label, contaminating
the attack class with ordinary protocol-response content that was never
part of the attack itself. Rebuilding `flow_labels.py` from scratch (the
original fixed version wasn't committed to git) reintroduced exactly this
bug via a canonical/sorted matching key - and so did the two
hardcoded-filter scripts independently, via `src or dst == target`
conditions. All three are forward-direction-only now, each covered by a
regression test in `tests/test_pcap_extract.py` that builds a synthetic
attacker/victim exchange and asserts the reply is excluded.

**Per-sub-label balancing.** The other bug fixed once before - one
high-volume sub-type exhausting a shared flat cap before a rarer sub-type
is ever reached - doesn't need re-fixing here: `extract_dos.py` and
`extract_web_attack.py` give each sub-label its own independent
`ReservoirWriter` with its own cap, so Slowhttptest (n=1) or slowloris
(n=7) can't be crowded out by Hulk or GoldenEye filling first.

**Payload format wasn't compatible with the Rust loader.** Caught by
diffing against the original `pcap_to_dataset.py` reference script rather
than by the test suite. The first version of this pipeline preserved raw
payload bytes exactly, escaping embedded `\r`/`\n` (`\\r`, `\\n`) so
nothing was lost. That's a reasonable design in isolation, but it doesn't
match what `data_loader.rs` actually expects - the format the validated v1
baseline was built on strips control characters out of each payload
entirely rather than escaping them, so every line is safe by construction
and the Rust side never needs to unescape anything. The shipped version
now mirrors `bytes_to_line()` exactly (`clean_payload_to_line()` in
`lib/reservoir.py`), including its `MIN_LEN` filter (default 4, `--min-len`
to override) and its dedup-after-cleaning behavior, both of which were
missing before.

**`verify_reservoir.py` over-counted lines, found on the real SSH-Patator
run.** The extraction itself was correct - 1000 accepted, cap hit - but
verification reported `line count 1005 != manifest accepted=1000`. Root
cause: `verify_reservoir.py` read the file with `str.splitlines()`, which
splits on a wider set of characters than a plain `\n` (including U+2028,
U+0085, and others) - `read_reservoir()` (used everywhere else, including
by whatever eventually consumes these files) reads correctly via plain
per-line file iteration, which only splits on `\n`. SSH-Patator's payloads
are mostly encrypted handshake noise decoded through UTF-8-with-replace,
which is exactly the kind of content likely to occasionally decode into
one of those extra separator characters. `verify_reservoir.py` now reuses
`read_reservoir()` instead of duplicating (and getting wrong) its own file
reading, and `test_unicode_line_separator_stays_one_line` covers this
specifically - a payload containing an embedded U+2028 must still count as
one line.
