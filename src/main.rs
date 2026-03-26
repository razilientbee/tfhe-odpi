// ============================================================
// main.rs
// ============================================================
// Entry Point for TFHE-ODPI
//
// Purpose
// -------
// Orchestrates the full TFHE-ODPI pipeline in order:
//
//   1. Generate TFHE keys
//   2. Load and encrypt detection rules
//   3. Build Bloom filter from rule n-grams
//   4. Load payload dataset
//   5. Run encrypted ODPI inspection
//
// Security Model
// --------------
// • ClientKey stays on the client (this process)
// • ServerKey is passed to server-side FHE evaluation
// • No plaintext payload ever reaches the FHE layer
// • No key material is logged or persisted
//
// Configuration
// -------------
// payload_file : path to plaintext payload dataset
//                one payload per line, UTF-8 encoded
//
// rule_file    : path to detection rule file
//                one rule string per line, UTF-8 encoded
//
// fp_rate      : Bloom filter false positive target rate
//                0.1 = 10% — appropriate for small rulesets
//                (3-20 rules). Lower values increase k and
//                can over-prune when m is small. Tune this
//                based on ruleset size and desired pruning.
//
// ============================================================

use tfhe_odpi::keys::generate_keys;
use tfhe_odpi::data_loader::load_payloads;
use tfhe_odpi::payload_processor::process_payloads;
use tfhe_odpi::bloom::BloomFilter;
use tfhe_odpi::rules::EncryptedRules;
use std::fs;
use std::time::Instant;

fn main() {
    // --------------------------------------------------------
    // Configuration
    // --------------------------------------------------------
    let payload_file = "data/test_dataset_2.txt";
    let rule_file    = "data/test_ruleset_1.txt";
    let fp_rate      = 0.1;

    // --------------------------------------------------------
    // Stage 1 — Generate TFHE keys
    //
    // ClientKey : used for encrypting payloads, rules, and
    //             decrypting the final alert result
    // ServerKey : used for all homomorphic gate operations
    //             safe to pass to the server-side evaluator
    // --------------------------------------------------------
    println!("Initializing TFHE keys...");
    let keygen_start = Instant::now();
    let (client_key, server_key) = generate_keys();
    println!("  Key generation: {:.3?}", keygen_start.elapsed());

    // --------------------------------------------------------
    // Stage 2a — Load detection rules
    //
    // Rules are loaded as raw byte sequences.
    // Each line in the rule file is one rule.
    // Empty lines are ignored.
    // --------------------------------------------------------
    println!("\nLoading detection rules...");
    let rules: Vec<Vec<u8>> = fs::read_to_string(rule_file)
        .unwrap_or_else(|e| panic!("Failed to read rule file '{}': {}", rule_file, e))
        .lines()
        .map(|line| line.trim().as_bytes().to_vec())
        .filter(|r| !r.is_empty())
        .collect();

    println!("  Loaded {} rule(s)", rules.len());
    for (i, r) in rules.iter().enumerate() {
        println!(
            "  Rule {:>2}: {:?}  ({} bytes)",
            i,
            std::str::from_utf8(r).unwrap_or("<binary>"),
            r.len()
        );
    }

    // --------------------------------------------------------
    // Stage 2b — Derive window length
    //
    // Window length = length of the longest rule.
    // All rules are padded to this length in rules.rs.
    // All sliding windows in payload_processor use this size.
    // --------------------------------------------------------
    let window_len = rules
        .iter()
        .map(|r| r.len())
        .max()
        .expect("Rule file is empty — at least one rule required");

    println!("  Window length: {} bytes", window_len);

    // --------------------------------------------------------
    // Stage 2c — Encrypt rules
    //
    // Each rule byte is encrypted as 8 Boolean ciphertexts.
    // Rules shorter than window_len are zero-padded.
    // Encrypted rules are reused across all packets.
    // --------------------------------------------------------
    println!("\nEncrypting rules...");
    let enc_start = Instant::now();
    let enc_rules = EncryptedRules::new(&client_key, &rules, window_len);
    println!("  Rule encryption: {:.3?}", enc_start.elapsed());

    // --------------------------------------------------------
    // Stage 3 — Build Bloom filter
    //
    // Inserts every rule-length n-gram from each rule.
    // Used to prune sliding windows before FHE evaluation.
    // Windows that fail the Bloom check are skipped entirely.
    //
    // fp_rate tunes the false positive rate:
    //   lower  → fewer windows reach FHE (faster, larger filter)
    //   higher → more windows reach FHE  (slower, smaller filter)
    // --------------------------------------------------------
    println!("\nBuilding Bloom filter...");
    let bloom = BloomFilter::build_from_rules(&rules, window_len, fp_rate);
    let (m, k, bits_set) = bloom.stats();
    println!(
        "  m={} bits  k={} hashes  {}/{} bits set  fp_rate={}",
        m, k, bits_set, m, fp_rate
    );

    // --------------------------------------------------------
    // Stage 4 — Load payload dataset
    //
    // Each line in the payload file is one payload (packet).
    // Payloads are stored as raw byte vectors.
    // No filtering is applied — all payloads are inspected.
    // --------------------------------------------------------
    println!("\nLoading payload dataset...");
    let payloads = load_payloads(payload_file);
    println!("  Loaded {} payload(s)", payloads.len());

    // --------------------------------------------------------
    // Stage 5 — Run ODPI
    //
    // process_payloads runs all packets in parallel using
    // Rayon. Each packet is independently inspected.
    // Results are printed per-packet as they complete.
    // --------------------------------------------------------
    println!("\nRunning ODPI...");
    process_payloads(
        &server_key,
        &client_key,
        &enc_rules,
        &bloom,
        &payloads,
        window_len,
    );
}
