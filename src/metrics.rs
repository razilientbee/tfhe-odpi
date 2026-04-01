// ============================================================
// metrics.rs
// ============================================================
// Evaluation Metrics for TFHE-ODPI
//
// Purpose
// -------
// Computes, displays, and exports evaluation metrics from
// pipeline results. Designed for publishable paper output.
//
// Metrics computed
// ----------------
// Accuracy, Precision, Recall, F1 Score, MCC,
// FPR, FNR, Bloom pruning rate, per-packet timing stats
//
// Output formats
// --------------
// • Formatted console table
// • CSV file  → results/<run_name>_metrics.csv
// • LaTeX table → results/<run_name>_metrics.tex
//
// ============================================================

use crate::payload_processor::PacketResult;
use std::fs;
use std::io::Write;

// ============================================================
// EvalMetrics — all computed evaluation metrics
// ============================================================

#[derive(Debug, Clone)]
pub struct EvalMetrics {
    pub run_name:      String,

    // Confusion matrix
    pub tp:            usize,
    pub tn:            usize,
    pub fp:            usize,
    pub r#fn:          usize,
    pub total:         usize,
    pub skipped:       usize,

    // Classification metrics
    pub accuracy:      f64,
    pub precision:     f64,
    pub recall:        f64,
    pub f1:            f64,
    pub fpr:           f64,
    pub fnr:           f64,
    pub mcc:           f64,

    // Performance metrics
    pub wall_time_s:   f64,
    pub avg_time_ms:   f64,
    pub min_time_ms:   f64,
    pub max_time_ms:   f64,
    pub total_windows: usize,
    pub total_candidates: usize,
    pub pruning_rate:  f64,
}

// ============================================================
// compute
// ============================================================

/// Compute all evaluation metrics from pipeline results
/// and ground truth labels.
///
/// Parameters
/// ----------
/// run_name  : label for this run (e.g. "Run4-multigroup")
/// results   : per-packet results from process_payloads_multigroup
/// labels    : ground truth labels, one per packet
///             "FTP-Patator" = attack, anything else = benign
/// wall_time : total pipeline wall time in seconds
pub fn compute(
    run_name:  &str,
    results:   &[PacketResult],
    labels:    &[String],
    wall_time: f64,
) -> EvalMetrics {
    let mut tp = 0usize;
    let mut tn = 0usize;
    let mut fp = 0usize;
    let mut r#fn = 0usize;
    let mut skipped = 0usize;

    for r in results {
        let is_attack = labels
            .get(r.packet_id)
            .map(|l| l.trim() == "FTP-Patator")
            .unwrap_or(false);

        if r.skipped {
            if is_attack { r#fn += 1; } else { tn += 1; }
            skipped += 1;
            continue;
        }

        match (is_attack, r.alert) {
            (true,  true)  => tp += 1,
            (true,  false) => r#fn += 1,
            (false, true)  => fp += 1,
            (false, false) => tn += 1,
        }
    }

    let total = tp + tn + fp + r#fn;

    let precision = if tp + fp > 0 {
        tp as f64 / (tp + fp) as f64
    } else { 0.0 };

    let recall = if tp + r#fn > 0 {
        tp as f64 / (tp + r#fn) as f64
    } else { 0.0 };

    let f1 = if precision + recall > 0.0 {
        2.0 * precision * recall / (precision + recall)
    } else { 0.0 };

    let accuracy = if total > 0 {
        (tp + tn) as f64 / total as f64
    } else { 0.0 };

    let fpr = if fp + tn > 0 {
        fp as f64 / (fp + tn) as f64
    } else { 0.0 };

    let fnr = if r#fn + tp > 0 {
        r#fn as f64 / (r#fn + tp) as f64
    } else { 0.0 };

    // Matthews Correlation Coefficient
    let mcc_denom = ((tp + fp) as f64
        * (tp + r#fn) as f64
        * (tn + fp) as f64
        * (tn + r#fn) as f64)
        .sqrt();
    let mcc = if mcc_denom > 0.0 {
        ((tp * tn) as f64 - (fp * r#fn) as f64) / mcc_denom
    } else { 0.0 };

    // Performance stats (exclude skipped packets)
    let active: Vec<&PacketResult> = results.iter().filter(|r| !r.skipped).collect();

    let avg_time_ms = if !active.is_empty() {
        active.iter().map(|r| r.duration_ms).sum::<f64>() / active.len() as f64
    } else { 0.0 };

    let min_time_ms = active.iter().map(|r| r.duration_ms)
        .fold(f64::INFINITY, f64::min);
    let max_time_ms = active.iter().map(|r| r.duration_ms)
        .fold(f64::NEG_INFINITY, f64::max);

    let total_windows: usize = active.iter().map(|r| r.windows).sum();
    let total_candidates: usize = active.iter().map(|r| r.candidates).sum();

    let pruning_rate = if total_windows > 0 {
        1.0 - total_candidates as f64 / total_windows as f64
    } else { 0.0 };

    EvalMetrics {
        run_name: run_name.to_string(),
        tp, tn, fp, r#fn, total, skipped,
        accuracy, precision, recall, f1, fpr, fnr, mcc,
        wall_time_s: wall_time,
        avg_time_ms,
        min_time_ms: if min_time_ms.is_infinite() { 0.0 } else { min_time_ms },
        max_time_ms: if max_time_ms.is_infinite() { 0.0 } else { max_time_ms },
        total_windows, total_candidates, pruning_rate,
    }
}

// ============================================================
// print_table
// ============================================================

/// Print a formatted evaluation report to stdout.
pub fn print_table(m: &EvalMetrics) {
    println!();
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║  TFHE-ODPI Evaluation Report — {}  ║", pad(&m.run_name, 20));
    println!("╠══════════════════════════════════════════════════════╣");
    println!("║  Dataset                                             ║");
    println!("║    Total packets   : {:>6}                          ║", m.total);
    println!("║    Skipped packets : {:>6}  (payload < min window)  ║", m.skipped);
    println!("╠══════════════════════════════════════════════════════╣");
    println!("║  Confusion matrix                                    ║");
    println!("║    True  Positives : {:>6}                          ║", m.tp);
    println!("║    True  Negatives : {:>6}                          ║", m.tn);
    println!("║    False Positives : {:>6}                          ║", m.fp);
    println!("║    False Negatives : {:>6}                          ║", m.r#fn);
    println!("╠══════════════════════════════════════════════════════╣");
    println!("║  Classification metrics                              ║");
    println!("║    Accuracy        : {:>6.2}%                        ║", m.accuracy  * 100.0);
    println!("║    Precision       : {:>6.2}%                        ║", m.precision * 100.0);
    println!("║    Recall          : {:>6.2}%                        ║", m.recall    * 100.0);
    println!("║    F1 Score        : {:>6.2}%                        ║", m.f1        * 100.0);
    println!("║    FPR             : {:>6.2}%                        ║", m.fpr       * 100.0);
    println!("║    FNR             : {:>6.2}%                        ║", m.fnr       * 100.0);
    println!("║    MCC             : {:>6.3}                         ║", m.mcc);
    println!("╠══════════════════════════════════════════════════════╣");
    println!("║  Performance                                         ║");
    println!("║    Wall time       : {:>8.1}s                      ║", m.wall_time_s);
    println!("║    Avg packet time : {:>8.1}ms                     ║", m.avg_time_ms);
    println!("║    Min packet time : {:>8.1}ms                     ║", m.min_time_ms);
    println!("║    Max packet time : {:>8.1}ms                     ║", m.max_time_ms);
    println!("╠══════════════════════════════════════════════════════╣");
    println!("║  Bloom filter                                        ║");
    println!("║    Total windows   : {:>8}                        ║", m.total_windows);
    println!("║    Candidates (FHE): {:>8}                        ║", m.total_candidates);
    println!("║    Pruning rate    : {:>6.2}%                        ║", m.pruning_rate * 100.0);
    println!("╚══════════════════════════════════════════════════════╝");
    println!();
}

fn pad(s: &str, width: usize) -> String {
    format!("{:<width$}", s, width = width)
}

// ============================================================
// write_csv
// ============================================================

/// Write per-packet results and summary metrics to CSV.
pub fn write_csv(
    m:       &EvalMetrics,
    results: &[PacketResult],
    labels:  &[String],
) {
    let dir = "results";
    fs::create_dir_all(dir).ok();

    // Per-packet CSV
    let packet_path = format!("{}/{}_packets.csv", dir, m.run_name);
    if let Ok(mut f) = fs::File::create(&packet_path) {
        writeln!(f, "packet_id,alert,label,tp,tn,fp,fn,windows,candidates,pruning_pct,duration_ms").ok();
        for r in results {
            let label = labels.get(r.packet_id).map(|l| l.trim()).unwrap_or("UNKNOWN");
            let is_attack = label == "FTP-Patator";
            let (is_tp, is_tn, is_fp, is_fn) = if r.skipped {
                (false, !is_attack, false, is_attack)
            } else {
                match (is_attack, r.alert) {
                    (true,  true)  => (true,  false, false, false),
                    (true,  false) => (false, false, false, true),
                    (false, true)  => (false, false, true,  false),
                    (false, false) => (false, true,  false, false),
                }
            };
            let pruning = if r.windows > 0 {
                100.0 * (1.0 - r.candidates as f64 / r.windows as f64)
            } else { 100.0 };
            writeln!(f,
                "{},{},{},{},{},{},{},{},{},{:.1},{:.3}",
                r.packet_id,
                r.alert,
                label,
                is_tp as u8, is_tn as u8, is_fp as u8, is_fn as u8,
                r.windows, r.candidates, pruning, r.duration_ms
            ).ok();
        }
    }
    println!("[metrics] Per-packet CSV → {}", packet_path);

    // Summary metrics CSV
    let summary_path = format!("{}/{}_summary.csv", dir, m.run_name);
    if let Ok(mut f) = fs::File::create(&summary_path) {
        writeln!(f, "run,total,skipped,tp,tn,fp,fn,accuracy,precision,recall,f1,fpr,fnr,mcc,wall_time_s,avg_time_ms,total_windows,total_candidates,pruning_rate").ok();
        writeln!(f,
            "{},{},{},{},{},{},{},{:.4},{:.4},{:.4},{:.4},{:.4},{:.4},{:.4},{:.1},{:.1},{},{},{:.4}",
            m.run_name, m.total, m.skipped,
            m.tp, m.tn, m.fp, m.r#fn,
            m.accuracy, m.precision, m.recall, m.f1,
            m.fpr, m.fnr, m.mcc,
            m.wall_time_s, m.avg_time_ms,
            m.total_windows, m.total_candidates, m.pruning_rate
        ).ok();
    }
    println!("[metrics] Summary CSV    → {}", summary_path);
}

// ============================================================
// write_latex
// ============================================================

/// Write a publication-ready LaTeX table row for this run.
/// Appends to results/metrics_latex.tex so multiple runs
/// accumulate into one table.
pub fn write_latex(m: &EvalMetrics) {
    let path = "results/metrics_latex.tex";
    let append = std::path::Path::new(path).exists();

    let mut content = String::new();

    if !append {
        content.push_str("% TFHE-ODPI Evaluation Results\n");
        content.push_str("% Auto-generated by metrics.rs\n");
        content.push_str("\\begin{table}[htbp]\n");
        content.push_str("\\centering\n");
        content.push_str("\\caption{TFHE-ODPI Evaluation Results on CIC-IDS2017}\n");
        content.push_str("\\label{tab:results}\n");
        content.push_str("\\begin{tabular}{lrrrrrrrr}\n");
        content.push_str("\\toprule\n");
        content.push_str("Run & TP & TN & FP & FN & Acc (\\%) & Prec (\\%) & Rec (\\%) & F1 (\\%) \\\\\n");
        content.push_str("\\midrule\n");
    }

    content.push_str(&format!(
        "{} & {} & {} & {} & {} & {:.2} & {:.2} & {:.2} & {:.2} \\\\\n",
        m.run_name.replace('_', "\\_"),
        m.tp, m.tn, m.fp, m.r#fn,
        m.accuracy  * 100.0,
        m.precision * 100.0,
        m.recall    * 100.0,
        m.f1        * 100.0,
    ));

    let mode = if append {
        fs::OpenOptions::new().append(true).open(path)
    } else {
        fs::File::create(path).map(|f| f)
    };

    if let Ok(mut f) = mode {
        write!(f, "{}", content).ok();
    }
    println!("[metrics] LaTeX row      → {}", path);
}

/// Finalise the LaTeX table (call after all runs are logged).
pub fn finalise_latex() {
    let path = "results/metrics_latex.tex";
    if let Ok(mut f) = fs::OpenOptions::new().append(true).open(path) {
        writeln!(f, "\\bottomrule").ok();
        writeln!(f, "\\end{{tabular}}").ok();
        writeln!(f, "\\end{{table}}").ok();
    }
}
