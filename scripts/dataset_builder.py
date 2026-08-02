#!/usr/bin/env python3
"""
Dataset builder: samples payloads per category from the reservoir files
produced by the extract_*.py pipeline (plus the already-committed
FTP-Patator baseline), assigns each sample its category label, combines
everything, and shuffles with a fixed seed for reproducibility.

Design goal for this build: a defensible, low-bias dataset rather than
one that simply uses everything extracted. Every malicious category
contributes an equal number of samples (CAP), so no category dominates
an aggregate metric just because more of its traffic happened to survive
extraction. Benign is sized to automatically match the malicious total,
so the malicious:benign ratio stays 1:1 no matter how CAP or the category
list changes below.

--- HOW TO CHANGE THIS FOR A DIFFERENT BUILD ---
- To change every category's sample size at once: edit CAP below.
- To change ONE category's sample size only: replace CAP with a literal
  number in that category's tuple in MALICIOUS_CATEGORIES.
- To point a category at a different source file (e.g. after re-extracting
  with new parameters, or a higher --cap run): edit the file path in that
  category's tuple. Nothing else needs to change.
- To add or remove a malicious category: add/remove a line in
  MALICIOUS_CATEGORIES. BENIGN_COUNT recalculates automatically, no
  manual arithmetic needed.
- To build a different named variant (e.g. dataset2) instead of
  overwriting dataset1: change DATASET_NAME.
Each run is fully deterministic given the same SEED and CATEGORIES.
"""
import random

SEED = 42
DATASET_NAME = "dataset1"

RESERVOIR_DIR = "scripts/reservoirs"
OUTPUT_DIR = "data"

# Uniform sample count applied to every malicious category below.
# Set to 185 (FTP-Patator's natural, fully-exhausted yield - the smallest
# category with a usable amount of data) so every attack category
# contributes equally to any aggregate metric, rather than the categories
# that happened to hit a higher extraction cap (SSH-Patator, Brute-Force,
# DoS-GoldenEye, DoS-Hulk all reached 1000) dominating the results.
CAP = 185

# name -> (source file, label written to the labels file, sample count)
#
# Every entry here pulls CAP samples by default. Swap CAP for a literal
# number on any line to give that one category a different size.
MALICIOUS_CATEGORIES = {
    "FTP-Patator":   ("data/cicids_attack_payloads.txt",                        "FTP-Patator",   CAP),
    "SSH-Patator":   (f"{RESERVOIR_DIR}/reservoir_SSH-Patator.txt",              "SSH-Patator",   CAP),
    "Infiltration":  (f"{RESERVOIR_DIR}/reservoir_Infiltration.txt",             "Infiltration",  CAP),
    "Brute-Force":   (f"{RESERVOIR_DIR}/reservoir_Web-Attack_Brute-Force.txt",   "Brute-Force",   CAP),
    "XSS":           (f"{RESERVOIR_DIR}/reservoir_Web-Attack_XSS.txt",           "XSS",           CAP),
    "DoS-GoldenEye": (f"{RESERVOIR_DIR}/reservoir_DoS_DoS-GoldenEye.txt",        "DoS-GoldenEye", CAP),
    "DoS-Hulk":      (f"{RESERVOIR_DIR}/reservoir_DoS_DoS-Hulk.txt",             "DoS-Hulk",      CAP),
    # SQL-Injection intentionally left out: only 8 payloads were ever
    # extracted (source genuinely exhausted, not cap-limited), too few to
    # reach CAP. Uncomment and give it its own count (max 8) to include it
    # as a deliberately small-sample category instead:
    # "SQL-Injection": (f"{RESERVOIR_DIR}/reservoir_Web-Attack_SQL-Injection.txt", "SQL-Injection", 8),
}

# Benign is derived, not hardcoded: it always equals the current malicious
# total, so the 1:1 ratio holds automatically even after editing CAP or
# the category list above. No manual recalculation needed.
BENIGN_COUNT = sum(count for _, _, count in MALICIOUS_CATEGORIES.values())

CATEGORIES = {
    **MALICIOUS_CATEGORIES,
    "BENIGN": (f"{RESERVOIR_DIR}/reservoir_BENIGN.txt", "BENIGN", BENIGN_COUNT),
}


def read_lines(path):
    with open(path, encoding="utf-8") as f:
        return [line for line in f.read().split("\n") if line]


def main():
    random.seed(SEED)

    all_payloads = []
    all_labels = []
    report = []

    for name, (path, label, count) in CATEGORIES.items():
        lines = read_lines(path)
        available = len(lines)
        if count > available:
            raise ValueError(
                f"{name}: requested {count} but only {available} available in {path}"
            )
        sample = lines if count == available else random.sample(lines, count)
        all_payloads.extend(sample)
        all_labels.extend([label] * count)
        report.append((name, count, available))

    pairs = list(zip(all_payloads, all_labels))
    random.shuffle(pairs)
    payloads, labels = zip(*pairs)

    out_payloads = f"{OUTPUT_DIR}/cicids_{DATASET_NAME}_payloads.txt"
    out_labels = f"{OUTPUT_DIR}/cicids_{DATASET_NAME}_labels.txt"

    with open(out_payloads, "w", encoding="utf-8") as f:
        f.write("\n".join(payloads))
    with open(out_labels, "w", encoding="utf-8") as f:
        f.write("\n".join(labels))

    malicious_total = sum(c for n, c, a in report if n != "BENIGN")
    benign_total = sum(c for n, c, a in report if n == "BENIGN")

    print(f"=== {DATASET_NAME} ===")
    for name, count, available in report:
        flag = "" if count == available else "  (down-sampled)"
        print(f"  {name:<15} used={count:<6} available={available}{flag}")
    print(f"  {'TOTAL':<15} used={len(payloads)}")
    print(f"  malicious={malicious_total}  benign={benign_total}  ratio={malicious_total/benign_total:.2f}:1")
    print(f"Done -> {out_payloads} + {out_labels}")


if __name__ == "__main__":
    main()
