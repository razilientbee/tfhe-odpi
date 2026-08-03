// ============================================================
// payload_processor.rs
// ============================================================
// ODPI Runtime Payload Evaluation Engine
//
// Purpose
// -------
// Executes the full per-packet inspection pipeline and
// returns structured results for downstream metrics analysis.
//
// Two entry points
// ----------------
// process_payloads()            — original single-group pipeline
// process_payloads_multigroup() — multi-group pipeline (primary)
//
// Both functions now return Vec<PacketResult> so metrics.rs
// can compute accuracy, timing, and pruning statistics.
//
// ============================================================

use crate::bloom::BloomFilter;
use crate::rules::EncryptedRules;
use crate::substring_matcher::encrypted_substring_match;
use crate::data_loader::encrypt_window;
use tfhe::boolean::prelude::*;
use rayon::prelude::*;
use std::time::Instant;

// ============================================================
// PacketResult — per-packet inspection outcome
// ============================================================

/// Structured result for a single packet inspection.
/// Returned by both process_payloads variants and consumed
/// by metrics.rs for evaluation reporting.
#[derive(Debug, Clone)]
pub struct PacketResult {
    /// Original packet index in the payload dataset
    pub packet_id:   usize,
    /// FHE decrypted alert result
    pub alert:       bool,
    /// Whether packet was skipped (payload too short)
    pub skipped:     bool,
    /// Total sliding windows scanned across all groups
    pub windows:     usize,
    /// Windows that passed Bloom filter (reached FHE)
    pub candidates:  usize,
    /// Wall time for this packet in milliseconds
    pub duration_ms: f64,
}

// ============================================================
// RuleGroup
// ============================================================

/// A self-contained inspection group for rules of one length.
pub struct RuleGroup {
    pub name:       String,
    pub rules:      EncryptedRules,
    pub bloom:      BloomFilter,
    pub window_len: usize,
}

// ============================================================
// process_payloads — original single-group pipeline
// ============================================================

pub fn process_payloads(
    server_key: &ServerKey,
    client_key: &ClientKey,
    rules:      &EncryptedRules,
    bloom:      &BloomFilter,
    payloads:   &[Vec<u8>],
    window_len: usize,
) -> Vec<PacketResult> {
    println!("== Starting Encrypted ODPI ==");
    println!("   Packets  : {}", payloads.len());
    println!("   Window   : {} bytes", window_len);
    println!("   Rules    : {}", rules.rule_bytes.len());
    println!();

    let global_start = Instant::now();

    let results: Vec<PacketResult> = payloads
        .par_iter()
        .enumerate()
        .map(|(packet_id, payload)| {
            let packet_start = Instant::now();

            if payload.len() < window_len {
                println!(
                    "[Packet {:>3}] SKIP  (len={} < window={})",
                    packet_id, payload.len(), window_len
                );
                return PacketResult {
                    packet_id,
                    alert:       false,
                    skipped:     true,
                    windows:     0,
                    candidates:  0,
                    duration_ms: packet_start.elapsed().as_secs_f64() * 1000.0,
                };
            }

            let total_windows  = payload.len() - window_len + 1;
            let enc_payload    = encrypt_window(client_key, payload);
            let mut accumulated = server_key.trivial_encrypt(false);
            let mut candidate_count = 0usize;

            for i in 0..total_windows {
                let window = &payload[i..i + window_len];
                if !bloom.might_contain(window) { continue; }
                candidate_count += 1;
                let enc_window = &enc_payload[i..i + window_len];
                let enc_result = encrypted_substring_match(server_key, enc_window, rules);
                accumulated = server_key.or(&accumulated, &enc_result);
            }

            let alert       = client_key.decrypt(&accumulated);
            let duration_ms = packet_start.elapsed().as_secs_f64() * 1000.0;
            let pruning     = 100.0 * (1.0 - candidate_count as f64 / total_windows as f64);

            println!(
                "[Packet {:>3}] Alert={:5}  windows={:>4}  candidates={:>4}  pruned={:.1}%  time={:.3?}ms",
                packet_id, alert, total_windows, candidate_count, pruning, duration_ms
            );

            PacketResult {
                packet_id,
                alert,
                skipped:     false,
                windows:     total_windows,
                candidates:  candidate_count,
                duration_ms,
            }
        })
        .collect();

    println!();
    println!(
        "== ODPI Complete — total elapsed: {:.3?} ==",
        global_start.elapsed()
    );

    results
}

// ============================================================
// process_payloads_multigroup — multi-length rule grouping
// ============================================================

pub fn process_payloads_multigroup(
    server_key: &ServerKey,
    client_key: &ClientKey,
    groups:     &[RuleGroup],
    payloads:   &[Vec<u8>],
) -> Vec<PacketResult> {
    let min_window = groups
        .iter()
        .map(|g| g.window_len)
        .min()
        .unwrap_or(1);

    println!("== Starting Encrypted ODPI (multi-group) ==");
    println!("   Packets  : {}", payloads.len());
    println!("   Groups   : {}", groups.len());
    for g in groups {
        println!(
            "     [{}]  window={} bytes  rules={}",
            g.name, g.window_len, g.rules.rule_bytes.len()
        );
    }
    println!();

    let global_start = Instant::now();

    let results: Vec<PacketResult> = payloads
        .par_iter()
        .enumerate()
        .map(|(packet_id, payload)| {
            let packet_start = Instant::now();

            if payload.len() < min_window {
                println!(
                    "[Packet {:>3}] SKIP  (len={} < min_window={})",
                    packet_id, payload.len(), min_window
                );
                return PacketResult {
                    packet_id,
                    alert:       false,
                    skipped:     true,
                    windows:     0,
                    candidates:  0,
                    duration_ms: packet_start.elapsed().as_secs_f64() * 1000.0,
                };
            }

            let enc_payload = encrypt_window(client_key, payload);
            let mut packet_accumulated   = server_key.trivial_encrypt(false);
            let mut total_windows_all    = 0usize;
            let mut total_candidates_all = 0usize;

            for group in groups {
                let window_len = group.window_len;
                if payload.len() < window_len { continue; }

                let total_windows  = payload.len() - window_len + 1;
                total_windows_all += total_windows;

                // Sequential prefilter: cheap, plaintext-only.
                let candidate_indices: Vec<usize> = (0..total_windows)
                    .filter(|&i| group.bloom.might_contain(&payload[i..i + window_len]))
                    .collect();
                total_candidates_all += candidate_indices.len();

                // Parallel FHE evaluation + OR-reduction over candidates.
                let group_accumulated = candidate_indices
                    .par_iter()
                    .map(|&i| {
                        let enc_window = &enc_payload[i..i + window_len];
                        encrypted_substring_match(server_key, enc_window, &group.rules)
                    })
                    .reduce(
                        || server_key.trivial_encrypt(false),
                        |a, b| server_key.or(&a, &b),
                    );

                packet_accumulated = server_key.or(&packet_accumulated, &group_accumulated);
            }

            let alert       = client_key.decrypt(&packet_accumulated);
            let duration_ms = packet_start.elapsed().as_secs_f64() * 1000.0;
            let pruning     = if total_windows_all > 0 {
                100.0 * (1.0 - total_candidates_all as f64 / total_windows_all as f64)
            } else { 0.0 };

            println!(
                "[Packet {:>3}] Alert={:5}  windows={:>4}  candidates={:>4}  pruned={:.1}%  time={:.1}ms",
                packet_id, alert, total_windows_all, total_candidates_all, pruning, duration_ms
            );

            PacketResult {
                packet_id,
                alert,
                skipped:     false,
                windows:     total_windows_all,
                candidates:  total_candidates_all,
                duration_ms,
            }
        })
        .collect();

    println!();
    println!(
        "== ODPI Complete — total elapsed: {:.3?} ==",
        global_start.elapsed()
    );

    results
}
