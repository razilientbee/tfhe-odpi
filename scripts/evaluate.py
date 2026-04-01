#!/usr/bin/env python3
# =============================================================
# evaluate.py
# =============================================================
# TFHE-ODPI Post-run Visualisation and Reporting
#
# Purpose
# -------
# Reads pipeline result CSV files and generates publication-
# ready figures for the thesis evaluation section.
#
# Usage
# -----
#   python3 scripts/evaluate.py
#
# Outputs (all written to results/)
# ----------------------------------
#   confusion_matrix.png      — heatmap of TP/TN/FP/FN
#   timing_distribution.png   — per-packet timing histogram
#   pruning_analysis.png       — pruning rate vs payload size
#   optimisation_progression.png — F1/accuracy across runs
#   all_metrics_table.png      — formatted metrics summary table
#
# =============================================================

import os
import re
import sys
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use('Agg')  # non-interactive backend for VM
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns
from pathlib import Path

# =============================================================
# Configuration
# =============================================================

RESULTS_DIR  = Path("results")
SCRIPTS_DIR  = Path("scripts")
PACKET_CSV   = RESULTS_DIR / "Run5-normalised-multigroup_packets.csv"
SUMMARY_CSV  = RESULTS_DIR / "Run5-normalised-multigroup_summary.csv"

# Publication style
plt.rcParams.update({
    'font.family':      'DejaVu Sans',
    'font.size':        11,
    'axes.titlesize':   13,
    'axes.labelsize':   11,
    'xtick.labelsize':  10,
    'ytick.labelsize':  10,
    'legend.fontsize':  10,
    'figure.dpi':       150,
    'savefig.dpi':      300,
    'savefig.bbox':     'tight',
    'axes.spines.top':  False,
    'axes.spines.right':False,
})

PALETTE = {
    'tp':      '#2d7d46',   # green
    'tn':      '#1a6b9e',   # blue
    'fp':      '#c0392b',   # red
    'fn':      '#e67e22',   # orange
    'pruned':  '#5b7fa6',   # steel blue
    'fhe':     '#d4821a',   # amber
    'attack':  '#c0392b',
    'benign':  '#2980b9',
    'neutral': '#7f8c8d',
}

# =============================================================
# Load data
# =============================================================

def load_packet_data() -> pd.DataFrame:
    if not PACKET_CSV.exists():
        print(f"ERROR: {PACKET_CSV} not found. Run the pipeline first.")
        sys.exit(1)
    df = pd.read_csv(PACKET_CSV)
    df['is_attack'] = df['label'] == 'FTP-Patator'
    df['outcome']   = 'TN'
    df.loc[df['tp'] == 1, 'outcome'] = 'TP'
    df.loc[df['fp'] == 1, 'outcome'] = 'FP'
    df.loc[(df['fn'] == 1), 'outcome'] = 'FN'
    return df

def load_summary() -> dict:
    if not SUMMARY_CSV.exists():
        print(f"ERROR: {SUMMARY_CSV} not found.")
        sys.exit(1)
    df = pd.read_csv(SUMMARY_CSV)
    return df.iloc[0].to_dict()

# =============================================================
# Plot 1 — Confusion matrix heatmap
# =============================================================

def plot_confusion_matrix(summary: dict):
    tp = int(summary['tp'])
    tn = int(summary['tn'])
    fp = int(summary['fp'])
    fn = int(summary['fn'])

    cm    = np.array([[tp, fn], [fp, tn]])
    total = tp + tn + fp + fn

    labels = np.array([
        [f'TP\n{tp}\n({tp/total*100:.1f}%)',  f'FN\n{fn}\n({fn/total*100:.1f}%)'],
        [f'FP\n{fp}\n({fp/total*100:.1f}%)',  f'TN\n{tn}\n({tn/total*100:.1f}%)'],
    ])

    fig, ax = plt.subplots(figsize=(6, 5))

    sns.heatmap(
        cm,
        annot=labels,
        fmt='',
        cmap='Blues',
        linewidths=1,
        linecolor='white',
        ax=ax,
        cbar_kws={'label': 'Packet count'},
        xticklabels=['Predicted attack', 'Predicted benign'],
        yticklabels=['Actual attack', 'Actual benign'],
        annot_kws={'size': 12, 'weight': 'bold'},
    )

    ax.set_title('Confusion matrix — TFHE-ODPI on CIC-IDS2017\n'
                 f'Accuracy={summary["accuracy"]*100:.2f}%  '
                 f'Precision={summary["precision"]*100:.2f}%  '
                 f'Recall={summary["recall"]*100:.2f}%  '
                 f'F1={summary["f1"]*100:.2f}%',
                 pad=12)
    ax.set_ylabel('Ground truth')
    ax.set_xlabel('Pipeline output')

    out = RESULTS_DIR / 'confusion_matrix.png'
    fig.savefig(out)
    plt.close(fig)
    print(f'[plot] Confusion matrix       → {out}')

# =============================================================
# Plot 2 — Per-packet timing distribution
# =============================================================

def plot_timing_distribution(df: pd.DataFrame):
    active = df[~df['skipped']].copy() if 'skipped' in df.columns else df.copy()
    # duration_ms already in ms
    attack = active[active['is_attack']]['duration_ms']
    benign = active[~active['is_attack']]['duration_ms']

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))

    # Left — histogram by class
    ax = axes[0]
    bins = np.linspace(0, active['duration_ms'].max() * 1.05, 40)
    ax.hist(attack, bins=bins, alpha=0.7, color=PALETTE['attack'],
            label=f'Attack (n={len(attack)})', edgecolor='white')
    ax.hist(benign, bins=bins, alpha=0.7, color=PALETTE['benign'],
            label=f'Benign (n={len(benign)})', edgecolor='white')
    ax.set_xlabel('Packet inspection time (ms)')
    ax.set_ylabel('Packet count')
    ax.set_title('Per-packet inspection time distribution')
    ax.legend()

    # Right — box plot by class
    ax2 = axes[1]
    data_bp  = [attack.values, benign.values]
    bp = ax2.boxplot(data_bp, patch_artist=True, notch=False,
                     medianprops={'color': 'white', 'linewidth': 2})
    bp['boxes'][0].set_facecolor(PALETTE['attack'])
    bp['boxes'][1].set_facecolor(PALETTE['benign'])
    for whisker in bp['whiskers']:
        whisker.set(color='gray', linewidth=1)
    for cap in bp['caps']:
        cap.set(color='gray', linewidth=1)
    for flier in bp['fliers']:
        flier.set(marker='o', color='gray', alpha=0.4, markersize=3)

    ax2.set_xticklabels(['Attack', 'Benign'])
    ax2.set_ylabel('Inspection time (ms)')
    ax2.set_title('Inspection time by traffic class')

    fig.suptitle('TFHE-ODPI Per-packet timing analysis', fontsize=13, y=1.01)
    fig.tight_layout()

    out = RESULTS_DIR / 'timing_distribution.png'
    fig.savefig(out)
    plt.close(fig)
    print(f'[plot] Timing distribution     → {out}')

# =============================================================
# Plot 3 — Pruning analysis
# =============================================================

def plot_pruning_analysis(df: pd.DataFrame):
    active = df[df['windows'] > 0].copy()
    active['pruning_pct'] = 100.0 * (1.0 - active['candidates'] / active['windows'])

    fig, axes = plt.subplots(1, 2, figsize=(12, 5))

    # Left — scatter: windows vs candidates coloured by class
    ax = axes[0]
    attack_df = active[active['is_attack']]
    benign_df = active[~active['is_attack']]

    ax.scatter(benign_df['windows'],  benign_df['candidates'],
               alpha=0.5, s=20, color=PALETTE['benign'],  label='Benign')
    ax.scatter(attack_df['windows'],  attack_df['candidates'],
               alpha=0.7, s=30, color=PALETTE['attack'],  label='Attack', zorder=5)
    ax.set_xlabel('Total windows (payload size proxy)')
    ax.set_ylabel('Candidates passed to FHE')
    ax.set_title('Bloom filter: windows vs FHE candidates')
    ax.legend()

    # Reference line: 1% pass-through
    max_w = active['windows'].max()
    ax.plot([0, max_w], [0, max_w * 0.01], 'k--', alpha=0.3, linewidth=1,
            label='1% pass-through')

    # Right — pruning rate histogram
    ax2 = axes[1]
    ax2.hist(active['pruning_pct'], bins=20,
             color=PALETTE['pruned'], edgecolor='white', alpha=0.85)
    ax2.axvline(active['pruning_pct'].mean(), color='red', linewidth=1.5,
                linestyle='--', label=f"Mean {active['pruning_pct'].mean():.1f}%")
    ax2.set_xlabel('Bloom filter pruning rate (%)')
    ax2.set_ylabel('Packet count')
    ax2.set_title('Pruning rate distribution')
    ax2.legend()

    fig.suptitle('TFHE-ODPI Bloom filter pruning analysis', fontsize=13, y=1.01)
    fig.tight_layout()

    out = RESULTS_DIR / 'pruning_analysis.png'
    fig.savefig(out)
    plt.close(fig)
    print(f'[plot] Pruning analysis        → {out}')

# =============================================================
# Plot 4 — Optimisation progression across runs
# =============================================================

def plot_optimisation_progression():
    runs = [
        {'run': 'Run 1\n(wrong ruleset)',    'accuracy': 3.78,   'precision': 2.23,   'recall': 2.16,   'f1': 2.20,   'wall_time': 319,  'fp': 175, 'fn': 181},
        {'run': 'Run 2\n(4-byte rules)',      'accuracy': 98.11,  'precision': 97.85,  'recall': 98.38,  'f1': 98.11,  'wall_time': 1195, 'fp': 4,   'fn': 3},
        {'run': 'Run 4\n(multi-group)',        'accuracy': 99.19,  'precision': 100.0,  'recall': 98.38,  'f1': 99.18,  'wall_time': 318,  'fp': 0,   'fn': 3},
        {'run': 'Run 5\n(+ normalisation)',    'accuracy': 99.19,  'precision': 100.0,  'recall': 98.38,  'f1': 99.18,  'wall_time': 399,  'fp': 0,   'fn': 3},
    ]
    df = pd.DataFrame(runs)

    fig, axes = plt.subplots(1, 3, figsize=(15, 5))

    # Left — F1 and accuracy progression
    ax = axes[0]
    x   = np.arange(len(df))
    w   = 0.35
    b1  = ax.bar(x - w/2, df['accuracy'], w, label='Accuracy',  color='#2980b9', alpha=0.85)
    b2  = ax.bar(x + w/2, df['f1'],       w, label='F1 Score',  color='#27ae60', alpha=0.85)
    ax.set_xticks(x)
    ax.set_xticklabels(df['run'], fontsize=9)
    ax.set_ylabel('Score (%)')
    ax.set_ylim(0, 107)
    ax.set_title('Accuracy and F1 progression')
    ax.legend()
    for bar in list(b1) + list(b2):
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2, h + 0.5,
                f'{h:.1f}', ha='center', va='bottom', fontsize=8)

    # Middle — FP and FN counts
    ax2 = axes[1]
    b3 = ax2.bar(x - w/2, df['fp'], w, label='False Positives', color=PALETTE['fp'], alpha=0.85)
    b4 = ax2.bar(x + w/2, df['fn'], w, label='False Negatives', color=PALETTE['fn'], alpha=0.85)
    ax2.set_xticks(x)
    ax2.set_xticklabels(df['run'], fontsize=9)
    ax2.set_ylabel('Packet count')
    ax2.set_title('False positive / negative progression')
    ax2.legend()
    for bar in list(b3) + list(b4):
        h = bar.get_height()
        if h > 0:
            ax2.text(bar.get_x() + bar.get_width()/2, h + 1,
                     str(int(h)), ha='center', va='bottom', fontsize=9)

    # Right — wall time
    ax3 = axes[2]
    colors = ['#e74c3c' if t > 500 else '#27ae60' for t in df['wall_time']]
    bars   = ax3.bar(x, df['wall_time'], color=colors, alpha=0.85, edgecolor='white')
    ax3.set_xticks(x)
    ax3.set_xticklabels(df['run'], fontsize=9)
    ax3.set_ylabel('Wall time (seconds)')
    ax3.set_title('Pipeline wall time')
    for bar, t in zip(bars, df['wall_time']):
        ax3.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 10,
                 f'{t}s', ha='center', va='bottom', fontsize=9)

    fig.suptitle('TFHE-ODPI optimisation progression — CIC-IDS2017 (370 packets)',
                 fontsize=13, y=1.02)
    fig.tight_layout()

    out = RESULTS_DIR / 'optimisation_progression.png'
    fig.savefig(out)
    plt.close(fig)
    print(f'[plot] Optimisation progression → {out}')

# =============================================================
# Plot 5 — Summary metrics table
# =============================================================

def plot_metrics_table(summary: dict):
    rows = [
        ['Metric',          'Value'],
        ['Total packets',   '370 (185 attack + 185 benign)'],
        ['True Positives',  str(int(summary['tp']))],
        ['True Negatives',  str(int(summary['tn']))],
        ['False Positives', str(int(summary['fp']))],
        ['False Negatives', str(int(summary['fn']))],
        ['Accuracy',        f"{summary['accuracy']*100:.2f}%"],
        ['Precision',       f"{summary['precision']*100:.2f}%"],
        ['Recall',          f"{summary['recall']*100:.2f}%"],
        ['F1 Score',        f"{summary['f1']*100:.2f}%"],
        ['FPR',             f"{summary['fpr']*100:.2f}%"],
        ['FNR',             f"{summary['fnr']*100:.2f}%"],
        ['MCC',             f"{summary['mcc']:.4f}"],
        ['Wall time',       f"{summary['wall_time_s']:.1f}s"],
        ['Avg packet time', f"{summary['avg_time_ms']:.0f}ms"],
        ['Total windows',   f"{int(summary['total_windows']):,}"],
        ['FHE candidates',  f"{int(summary['total_candidates']):,}"],
        ['Pruning rate',    f"{summary['pruning_rate']*100:.2f}%"],
    ]

    fig, ax = plt.subplots(figsize=(7, 7))
    ax.axis('off')

    col_widths = [0.55, 0.45]
    table = ax.table(
        cellText  = rows[1:],
        colLabels = rows[0],
        cellLoc   = 'left',
        loc       = 'center',
        colWidths = col_widths,
    )
    table.auto_set_font_size(False)
    table.set_fontsize(11)
    table.scale(1, 1.6)

    # Style header
    for j in range(2):
        table[0, j].set_facecolor('#2c3e50')
        table[0, j].set_text_props(color='white', fontweight='bold')

    # Alternating row colours
    for i in range(1, len(rows)):
        bg = '#f2f2f2' if i % 2 == 0 else 'white'
        for j in range(2):
            table[i, j].set_facecolor(bg)

    # Highlight key metrics
    highlight_rows = {
        7: '#d5e8d4',   # Accuracy
        8: '#d5e8d4',   # Precision
        9: '#d5e8d4',   # Recall
        10: '#d5e8d4',  # F1
        4: '#f8cecc',   # FP
        5: '#fff2cc',   # FN
    }
    for row_idx, color in highlight_rows.items():
        for j in range(2):
            table[row_idx, j].set_facecolor(color)

    ax.set_title(
        'TFHE-ODPI Evaluation Summary\nRun: normalised multigroup — CIC-IDS2017',
        fontsize=12, pad=20, fontweight='bold'
    )

    out = RESULTS_DIR / 'all_metrics_table.png'
    fig.savefig(out)
    plt.close(fig)
    print(f'[plot] Metrics summary table   → {out}')

# =============================================================
# Entry point
# =============================================================

def main():
    print('=' * 55)
    print(' TFHE-ODPI Post-run Evaluation')
    print('=' * 55)

    RESULTS_DIR.mkdir(exist_ok=True)

    print(f'\nLoading data from {PACKET_CSV}...')
    df      = load_packet_data()
    summary = load_summary()

    print(f'  Loaded {len(df)} packet records')
    print(f'  Summary: TP={int(summary["tp"])} TN={int(summary["tn"])} '
          f'FP={int(summary["fp"])} FN={int(summary["fn"])}')
    print(f'  F1={summary["f1"]*100:.2f}%  Accuracy={summary["accuracy"]*100:.2f}%')

    print('\nGenerating plots...')
    plot_confusion_matrix(summary)
    plot_timing_distribution(df)
    plot_pruning_analysis(df)
    plot_optimisation_progression()
    plot_metrics_table(summary)

    print()
    print('=' * 55)
    print(' All plots written to results/')
    print('=' * 55)
    print()
    print(' Files:')
    for f in sorted(RESULTS_DIR.glob('*.png')):
        size_kb = f.stat().st_size // 1024
        print(f'   {f.name:<45} {size_kb:>4} KB')

if __name__ == '__main__':
    # Must run from project root: python3 scripts/evaluate.py
    os.chdir(Path(__file__).parent.parent)
    main()
