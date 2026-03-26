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
//   2. Slide a window of window_len bytes across the payload
//   3. Prune each window using the Bloom filter (plaintext)
//   4. For candidate windows: run homomorphic substring match
//   5. Accumulate all window results via homomorphic OR
//   6. Decrypt the accumulated result once per packet
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
// • The Bloom filter operates on plaintext (client-side only)
// • All FHE operations use only ciphertexts
// • client_key.decrypt() is called ONCE per packet, AFTER
//   all windows have been evaluated and OR-accumulated
// • The server never learns:
//     - which window matched
//     - which rule matched
//     - the plaintext payload content
//     - the alert result (boolean)
//
// Why single decrypt matters
// --------------------------
// Decrypting per window (as done in the diagnostic version)
// leaks match position as a timing side-channel. An observer
// can count how many decryptions occurred and infer where
// in the payload the match was found, partially revealing
// rule structure. Single decrypt after full accumulation
// eliminates this channel entirely.
//
// Benchmark output
// ----------------
// Per packet:
//   Alert        : true/false
//   windows      : total sliding windows scanned
//   candidates   : windows that passed Bloom filter
//   pruned       : percentage of windows skipped by Bloom
//   time         : wall time for this packet
//
// ============================================================

use crate::bloom::BloomFilter;
use crate::rules::EncryptedRules;
use crate::substring_matcher::encrypted_substring_match;
use crate::data_loader::encrypt_window;
use tfhe::boolean::prelude::*;
use rayon::prelude::*;
use std::time::Instant;

/// ------------------------------------------------------------
/// process_payloads
///
/// Run encrypted ODPI inspection across all packets in
/// parallel. Prints one result line per packet.
///
/// Parameters
/// ----------
/// server_key : TFHE server key — used for all FHE gate ops
/// client_key : TFHE client key — used for encryption and
///              the single final decrypt per packet
/// rules      : pre-encrypted rule tokens
/// bloom      : pre-built Bloom filter for window pruning
/// payloads   : raw payload byte vectors to inspect
/// window_len : sliding window size in bytes (= max rule len)
/// ------------------------------------------------------------
pub fn process_payloads(
    server_key: &ServerKey,
    client_key: &ClientKey,
    rules: &EncryptedRules,
    bloom: &BloomFilter,
    payloads: &[Vec<u8>],
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

            // ------------------------------------------------
            // Skip payloads shorter than the rule window.
            // A payload of length L < window_len cannot
            // contain any rule match — skip immediately.
            // ------------------------------------------------
            if payload.len() < window_len {
                println!(
                    "[Packet {:>3}] SKIP  (len={} < window={})",
                    packet_id, payload.len(), window_len
                );
                return;
            }

            let total_windows = payload.len() - window_len + 1;

            // ------------------------------------------------
            // Encrypt the full payload once upfront.
            //
            // Each byte is encrypted exactly once into 8
            // Boolean ciphertexts. Overlapping windows share
            // encrypted bytes — no re-encryption per window.
            // enc_payload[i] is the encrypted form of
            // payload[i] (8 ciphertexts, LSB first).
            // ------------------------------------------------
            let enc_payload = encrypt_window(client_key, payload);

            // ------------------------------------------------
            // Accumulated result across all windows.
            //
            // Starts as encrypted false.
            // Each matching window ORs its result in.
            // Final value is true iff any window matched.
            //
            // PRIVACY: we never decrypt inside this loop.
            // One decrypt happens after the loop ends.
            // This prevents match-position timing leakage.
            // ------------------------------------------------
            let mut accumulated = server_key.trivial_encrypt(false);
            let mut candidate_count = 0usize;

            for i in 0..total_windows {
                let window = &payload[i..i + window_len];

                // --------------------------------------------
                // Bloom filter check (plaintext, O(k) hashes)
                //
                // Returns false  → window definitely not a
                //                  match — skip FHE entirely
                // Returns true   → possible match — proceed
                //                  to FHE evaluation
                //                  (may be a false positive)
                // --------------------------------------------
                if !bloom.might_contain(window) {
                    continue;
                }

                candidate_count += 1;

                // --------------------------------------------
                // Homomorphic substring match.
                //
                // Compares enc_payload[i..i+window_len]
                // against all encrypted rules.
                // Returns an encrypted boolean:
                //   true  → at least one rule matched
                //   false → no rule matched (or FP from Bloom)
                // --------------------------------------------
                let enc_window = &enc_payload[i..i + window_len];
                let enc_result =
                    encrypted_substring_match(server_key, enc_window, rules);

                // --------------------------------------------
                // Accumulate via homomorphic OR.
                //
                // accumulated = accumulated OR enc_result
                // This folds all window results into a single
                // ciphertext without any intermediate decrypt.
                // --------------------------------------------
                accumulated = server_key.or(&accumulated, &enc_result);
            }

            // ------------------------------------------------
            // Single decrypt per packet.
            //
            // Only happens here — after all windows have been
            // evaluated and accumulated. The server never sees
            // this result; it is decrypted by the client key.
            // ------------------------------------------------
            let alert = client_key.decrypt(&accumulated);
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
