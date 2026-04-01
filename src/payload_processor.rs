// ============================================================
// payload_processor.rs
// ============================================================
// ODPI Runtime Payload Evaluation Engine
//
// Purpose
// -------
// Executes the full per-packet inspection pipeline:
//
//   1. Encrypt payload bytes once upfront
//   2. For each rule group (different window sizes):
//      a. Slide a window of group.window_len bytes
//      b. Prune each window using group Bloom filter
//      c. For candidate windows: run homomorphic substring match
//      d. Accumulate window results via homomorphic OR
//   3. OR all group results into a single ciphertext
//   4. Decrypt the accumulated result once per packet
//
// Two entry points
// ----------------
// process_payloads()            — original single-group pipeline
//                                 (preserved for baseline runs)
// process_payloads_multigroup() — new multi-group pipeline
//                                 (used for optimised runs)
//
// Parallelism
// -----------
// Packets are processed in parallel using Rayon par_iter.
// Each packet runs independently on its own thread.
// Rule evaluation within each packet is sequential (iter).
// This avoids nested Rayon thread pool contention.
//
// Privacy Guarantees
// ------------------
// • No plaintext payload data crosses the client/server boundary
// • Bloom filters operate on plaintext (client-side only)
// • All FHE operations use only ciphertexts
// • client_key.decrypt() is called ONCE per packet, AFTER
//   all groups and all windows have been evaluated
// • The server never learns:
//     - which window matched
//     - which rule matched
//     - which group matched
//     - the plaintext payload content
//     - the alert result (boolean)
//
// Multi-group privacy note
// ------------------------
// The server observes separate FHE evaluation counts per group
// (coarse timing side-channel). This is a known limitation
// documented in the threat model. The alert result itself
// remains private — only one decrypt occurs per packet.
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
// RuleGroup
// ============================================================

/// A self-contained inspection group for rules of one length.
///
/// Each group has its own Bloom filter and encrypted rules
/// tuned to a specific window size. Multiple groups can be
/// evaluated per packet, with results OR-accumulated before
/// a single final decrypt.
///
/// Fields
/// ------
/// name       : display label for benchmark output
/// rules      : pre-encrypted rule tokens for this group
/// bloom      : Bloom filter built from this group's rules
/// window_len : sliding window size = rule length for this group
pub struct RuleGroup {
    pub name:       String,
    pub rules:      EncryptedRules,
    pub bloom:      BloomFilter,
    pub window_len: usize,
}

// ============================================================
// process_payloads — original single-group pipeline
// ============================================================

/// Run encrypted ODPI inspection across all packets using a
/// single rule group. Preserved for baseline compatibility.
pub fn process_payloads(
    server_key: &ServerKey,
    client_key: &ClientKey,
    rules:      &EncryptedRules,
    bloom:      &BloomFilter,
    payloads:   &[Vec<u8>],
    window_len: usize,
) {
    println!("== Starting Encrypted ODPI ==");
    println!("   Packets  : {}", payloads.len());
    println!("   Window   : {} bytes", window_len);
    println!("   Rules    : {}", rules.rule_bytes.len());
    println!();

    let global_start = Instant::now();

    payloads
        .par_iter()
        .enumerate()
        .for_each(|(packet_id, payload)| {
            let packet_start = Instant::now();

            if payload.len() < window_len {
                println!(
                    "[Packet {:>3}] SKIP  (len={} < window={})",
                    packet_id, payload.len(), window_len
                );
                return;
            }

            let total_windows = payload.len() - window_len + 1;
            let enc_payload   = encrypt_window(client_key, payload);
            let mut accumulated    = server_key.trivial_encrypt(false);
            let mut candidate_count = 0usize;

            for i in 0..total_windows {
                let window = &payload[i..i + window_len];
                if !bloom.might_contain(window) {
                    continue;
                }
                candidate_count += 1;
                let enc_window = &enc_payload[i..i + window_len];
                let enc_result =
                    encrypted_substring_match(server_key, enc_window, rules);
                accumulated = server_key.or(&accumulated, &enc_result);
            }

            let alert    = client_key.decrypt(&accumulated);
            let duration = packet_start.elapsed();

            let pruning_ratio = if total_windows > 0 {
                100.0 * (1.0 - candidate_count as f64 / total_windows as f64)
            } else {
                0.0
            };

            println!(
                "[Packet {:>3}] Alert={:5}  windows={:>4}  candidates={:>4}  pruned={:.1}%  time={:.3?}",
                packet_id,
                alert,
                total_windows,
                candidate_count,
                pruning_ratio,
                duration
            );
        });

    println!();
    println!(
        "== ODPI Complete — total elapsed: {:.3?} ==",
        global_start.elapsed()
    );
}

// ============================================================
// process_payloads_multigroup — multi-length rule grouping
// ============================================================

/// Run encrypted ODPI inspection across all packets using
/// multiple rule groups of different window sizes.
///
/// Each packet is evaluated against all groups. The results
/// are OR-accumulated across groups before a single decrypt.
///
/// Alert logic per packet:
///   group_result[0] = OR of all window matches in group 0
///   group_result[1] = OR of all window matches in group 1
///   final_result    = group_result[0] OR group_result[1] OR ...
///   alert           = decrypt(final_result)
pub fn process_payloads_multigroup(
    server_key: &ServerKey,
    client_key: &ClientKey,
    groups:     &[RuleGroup],
    payloads:   &[Vec<u8>],
) {
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
            g.name,
            g.window_len,
            g.rules.rule_bytes.len()
        );
    }
    println!();

    let global_start = Instant::now();

    payloads
        .par_iter()
        .enumerate()
        .for_each(|(packet_id, payload)| {
            let packet_start = Instant::now();

            if payload.len() < min_window {
                println!(
                    "[Packet {:>3}] SKIP  (len={} < min_window={})",
                    packet_id, payload.len(), min_window
                );
                return;
            }

            // Encrypt payload once — shared across all groups
            let enc_payload = encrypt_window(client_key, payload);

            // Accumulated result across ALL groups
            let mut packet_accumulated = server_key.trivial_encrypt(false);

            let mut total_windows_all    = 0usize;
            let mut total_candidates_all = 0usize;

            for group in groups {
                let window_len = group.window_len;

                if payload.len() < window_len {
                    continue;
                }

                let total_windows     = payload.len() - window_len + 1;
                total_windows_all    += total_windows;

                let mut group_accumulated = server_key.trivial_encrypt(false);

                for i in 0..total_windows {
                    let window = &payload[i..i + window_len];

                    if !group.bloom.might_contain(window) {
                        continue;
                    }

                    total_candidates_all += 1;

                    let enc_window = &enc_payload[i..i + window_len];
                    let enc_result = encrypted_substring_match(
                        server_key,
                        enc_window,
                        &group.rules,
                    );

                    group_accumulated =
                        server_key.or(&group_accumulated, &enc_result);
                }

                // OR this group result into packet accumulator
                packet_accumulated =
                    server_key.or(&packet_accumulated, &group_accumulated);
            }

            // Single decrypt per packet — after all groups
            let alert    = client_key.decrypt(&packet_accumulated);
            let duration = packet_start.elapsed();

            let pruning_ratio = if total_windows_all > 0 {
                100.0 * (1.0 - total_candidates_all as f64
                    / total_windows_all as f64)
            } else {
                0.0
            };

            println!(
                "[Packet {:>3}] Alert={:5}  windows={:>4}  candidates={:>4}  pruned={:.1}%  time={:.3?}",
                packet_id,
                alert,
                total_windows_all,
                total_candidates_all,
                pruning_ratio,
                duration
            );
        });

    println!();
    println!(
        "== ODPI Complete — total elapsed: {:.3?} ==",
        global_start.elapsed()
    );
}
