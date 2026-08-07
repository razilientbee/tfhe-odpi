#!/usr/bin/env python3
import sys

path = "payload_processor.rs"

with open(path, "r") as f:
    content = f.read()

old = '''pub fn process_payloads_multigroup(
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
}'''

new = '''// Packets at or above this size skip phase 1 (packet-parallel) and are
// processed one at a time in phase 2, so their own window-level reduce
// gets all 8 cores with no sibling packet competing for threads. Tune
// this against your own dataset's windows/candidate distribution;
// the value here was sized for the FTP-isolated 2-group test, not any
// larger config.
const LARGE_PAYLOAD_THRESHOLD: usize = 1200;

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

    println!("== Starting Encrypted ODPI (multi-group, two-phase) ==");
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

    let (small_ids, large_ids): (Vec<usize>, Vec<usize>) = (0..payloads.len())
        .partition(|&i| payloads[i].len() < LARGE_PAYLOAD_THRESHOLD);

    println!(
        "   Phase 1 (packet-parallel)  : {} packets  (< {} bytes)",
        small_ids.len(), LARGE_PAYLOAD_THRESHOLD
    );
    println!(
        "   Phase 2 (one-at-a-time)    : {} packets  (>= {} bytes)",
        large_ids.len(), LARGE_PAYLOAD_THRESHOLD
    );
    println!();

    // Phase 1: small payloads, packet-level parallel, unchanged strategy.
    let mut results: Vec<PacketResult> = small_ids
        .par_iter()
        .map(|&packet_id| {
            process_single_packet(
                packet_id, &payloads[packet_id], server_key, client_key, groups, min_window,
            )
        })
        .collect();

    // Phase 2: large payloads, one at a time. Phase 1's .collect() above is
    // a hard barrier: nothing here starts until every phase-1 task is done,
    // so the other 7 cores are genuinely idle and available to steal into
    // this packet's own window-level reduce.
    for &packet_id in &large_ids {
        let result = process_single_packet(
            packet_id, &payloads[packet_id], server_key, client_key, groups, min_window,
        );
        results.push(result);
    }

    // Phase 1 + phase 2 concatenation scrambles packet_id order, restore
    // it, since metrics.rs indexes results against labels by packet_id.
    results.sort_by_key(|r| r.packet_id);

    println!();
    println!(
        "== ODPI Complete — total elapsed: {:.3?} ==",
        global_start.elapsed()
    );

    results
}

// Shared by both phases so their per-packet behavior is identical.
// This is the same logic the single-phase version ran per packet,
// just extracted so it can be called from either a parallel or a
// sequential outer driver.
fn process_single_packet(
    packet_id:  usize,
    payload:    &[u8],
    server_key: &ServerKey,
    client_key: &ClientKey,
    groups:     &[RuleGroup],
    min_window: usize,
) -> PacketResult {
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
}'''

count = content.count(old)
if count != 1:
    print(f"ERROR: expected exactly 1 match, found {count}. File NOT modified.")
    sys.exit(1)

content = content.replace(old, new)

with open(path, "w") as f:
    f.write(content)

print("Patched successfully.")
