"""
plot_results.py
---------------
Generates Figure: Accuracy progression + Wall time progression
for TFHE-ODPI evaluation results.
 
Usage
-----
Place this file anywhere in your project (e.g. src/ or the root).
Run after a pipeline run that has written results to results/
 
    python plot_results.py
 
Output
------
results/figures/odpi_results.pdf   — vector, for LaTeX inclusion
results/figures/odpi_results.png   — raster, for quick preview
 
Customisation
-------------
Edit the RUN_DATA list below to add or remove runs.
Each entry is a dict with keys:
    label       : x-axis label (e.g. "Run 2")
    accuracy    : accuracy %  (e.g. 98.11)
    precision   : precision % (e.g. 97.85)
    wall_time   : wall time in seconds (e.g. 1195)
 
You can also populate RUN_DATA automatically from your summary
CSVs — see the commented-out section at the bottom.
"""
 
import os
import matplotlib
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import numpy as np
 
matplotlib.rcParams.update({
    "font.family":      "serif",
    "font.size":        9,
    "axes.titlesize":   9,
    "axes.labelsize":   9,
    "xtick.labelsize":  8,
    "ytick.labelsize":  8,
    "figure.dpi":       150,
    "pdf.fonttype":     42,   # embeds fonts for IEEE submission
    "ps.fonttype":      42,
})
 
# ============================================================
# DATA — edit these entries to match your run results
# ============================================================
 
RUN_DATA = [
    {"label": "Run 2", "accuracy": 98.11, "precision": 97.85, "wall_time": 1195},
    {"label": "Run 4", "accuracy": 99.19, "precision": 100.0, "wall_time": 399},
    {"label": "Run 5", "accuracy": 99.19, "precision": 100.0, "wall_time": 399},
]
 
# ============================================================
# COLOURS — matching the paper figure (blue / pink / orange)
# ============================================================
 
COL_ACCURACY  = "#7B8CDE"   # muted blue
COL_PRECISION = "#E8A0A8"   # muted pink/rose
COL_WALL      = "#E8A060"   # muted orange
 
# ============================================================
# LAYOUT
# ============================================================
 
fig, (ax_top, ax_bot) = plt.subplots(
    2, 1,
    figsize=(3.5, 5.0),       # single-column IEEE width
    gridspec_kw={"hspace": 0.45},
)
 
labels     = [r["label"]     for r in RUN_DATA]
accuracies = [r["accuracy"]  for r in RUN_DATA]
precisions = [r["precision"] for r in RUN_DATA]
wall_times = [r["wall_time"] for r in RUN_DATA]
 
x     = np.arange(len(labels))
width = 0.32
 
# ============================================================
# (a) Accuracy progression — grouped bar chart
# ============================================================
 
bars_acc  = ax_top.bar(x - width/2, accuracies, width, color=COL_ACCURACY,  zorder=3)
bars_prec = ax_top.bar(x + width/2, precisions, width, color=COL_PRECISION, zorder=3)
 
ax_top.set_title("(a) Accuracy progression", pad=6)
ax_top.set_ylabel("Accuracy (%)")
ax_top.set_xticks(x)
ax_top.set_xticklabels(labels)
ax_top.set_ylim(96, 101.5)
ax_top.yaxis.set_major_locator(matplotlib.ticker.MultipleLocator(1))
ax_top.grid(axis="y", linestyle="--", linewidth=0.5, alpha=0.6, zorder=0)
ax_top.spines["top"].set_visible(False)
ax_top.spines["right"].set_visible(False)
 
# Value labels above each bar
for bar in bars_acc:
    h = bar.get_height()
    ax_top.text(
        bar.get_x() + bar.get_width() / 2, h + 0.05,
        f"{h:.2f}".rstrip("0").rstrip("."),
        ha="center", va="bottom", fontsize=7,
    )
for bar in bars_prec:
    h = bar.get_height()
    ax_top.text(
        bar.get_x() + bar.get_width() / 2, h + 0.05,
        f"{h:.2f}".rstrip("0").rstrip("."),
        ha="center", va="bottom", fontsize=7,
    )
 
# Legend
legend_patches = [
    mpatches.Patch(color=COL_ACCURACY,  label="Accuracy"),
    mpatches.Patch(color=COL_PRECISION, label="Precision"),
]
ax_top.legend(
    handles=legend_patches,
    loc="lower right",
    fontsize=7,
    frameon=False,
    ncol=2,
)
 
# ============================================================
# (b) Wall time progression — single bar chart
# ============================================================
 
bars_wall = ax_bot.bar(x, wall_times, width * 1.8, color=COL_WALL, zorder=3)
 
ax_bot.set_title("(b) Wall time progression", pad=6)
ax_bot.set_ylabel("Wall time (s)")
ax_bot.set_xticks(x)
ax_bot.set_xticklabels(labels)
ax_bot.set_ylim(0, max(wall_times) * 1.25)
ax_bot.yaxis.set_major_locator(matplotlib.ticker.MultipleLocator(300))
ax_bot.grid(axis="y", linestyle="--", linewidth=0.5, alpha=0.6, zorder=0)
ax_bot.spines["top"].set_visible(False)
ax_bot.spines["right"].set_visible(False)
 
# Value labels above each bar
for bar in bars_wall:
    h = bar.get_height()
    ax_bot.text(
        bar.get_x() + bar.get_width() / 2, h + 10,
        f"{int(h):,}",
        ha="center", va="bottom", fontsize=7,
    )
 
# Legend
wall_patch = mpatches.Patch(color=COL_WALL, label="Wall time")
ax_bot.legend(
    handles=[wall_patch],
    loc="upper right",
    fontsize=7,
    frameon=False,
)
 
# ============================================================
# SAVE
# ============================================================
 
out_dir = os.path.join("results", "figures")
os.makedirs(out_dir, exist_ok=True)
 
pdf_path = os.path.join(out_dir, "odpi_results.pdf")
png_path = os.path.join(out_dir, "odpi_results.png")
 
fig.savefig(pdf_path, bbox_inches="tight")
fig.savefig(png_path, bbox_inches="tight")
 
print(f"[plot] Saved → {pdf_path}")
print(f"[plot] Saved → {png_path}")
 
plt.close(fig)
 
 
# ============================================================
# OPTIONAL: auto-populate RUN_DATA from summary CSVs
# ============================================================
# Uncomment this block and remove the hardcoded RUN_DATA above
# to pull values directly from your metrics output files.
#
# import glob, csv
#
# RUN_DATA = []
# for path in sorted(glob.glob("results/*_summary.csv")):
#     with open(path) as f:
#         rows = list(csv.DictReader(f))
#         if rows:
#             r = rows[0]
#             RUN_DATA.append({
#                 "label":     r["run"],
#                 "accuracy":  float(r["accuracy"])  * 100,
#                 "precision": float(r["precision"]) * 100,
#                 "wall_time": float(r["wall_time_s"]),
#             })
 
