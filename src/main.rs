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
//   2. Load and encrypt detection rules per group
//   3. Build Bloom filter per group
//   4. Load payload dataset
//   5. Run encrypted ODPI inspection (multi-group)
//
// Security Model
// --------------
// • ClientKey stays on the client (this process)
// • ServerKey is passed to server-side FHE evaluation
// • No plaintext payload ever reaches the FHE layer
// • No key material is logged or persisted
//
// Multi-group rule design
// -----------------------
// Rules are grouped by byte length to enable mixed-length
// inspection. Each group uses a window size equal to its
// rule length, its own Bloom filter, and its own encrypted
// rule set. Results are OR-accumulated across groups before
// a single decrypt per packet.
//
// Group A — 5-byte rules (credential + upload commands):
//   "USER "  "PASS "  "STOR "
//   Trailing space disambiguates from HTTP User-Agent header
//
// Group B — 6-byte rules (file retrieval commands with path):
//   "RETR /"  "SIZE /"  "MDTM /"
//   Path prefix disambiguates from substring collisions
//
// Configuration
// -------------
// payload_file    : path to plaintext payload dataset
// group_a_file    : path to Group A rule file (5-byte rules)
// group_b_file    : path to Group B rule file (6-byte rules)
// fp_rate         : Bloom filter false positive target rate
//
// ============================================================

use tfhe_odpi::keys::generate_keys;
use tfhe_odpi::data_loader::load_payloads;
use tfhe_odpi::payload_processor::{process_payloads_multigroup, RuleGroup};
use tfhe_odpi::bloom::BloomFilter;
use tfhe_odpi::rules::EncryptedRules;
use tfhe_odpi::normalizer::normalize_payloads;

use std::fs;
use std::time::Instant;

// ============================================================
// Helper — load and display rules from a file
// ============================================================

fn load_rules(path: &str) -> Vec<Vec<u8>> {
    let rules: Vec<Vec<u8>> = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Failed to read rule file '{}': {}", path, e))
        .lines()
        .map(|line| line.trim_end_matches('\n').as_bytes().to_vec())
        .filter(|r| !r.is_empty())
        .collect();
    rules
}

// ============================================================
// Helper — build a RuleGroup from a rule file
// ============================================================

fn build_rule_group(
    name:       &str,
    rule_file:  &str,
    fp_rate:    f64,
    client_key: &tfhe::boolean::prelude::ClientKey,
) -> RuleGroup {
    println!("\nBuilding group: [{}]", name);

    // Load rules
    let rules = load_rules(rule_file);
    println!("  Loaded {} rule(s) from {}", rules.len(), rule_file);

    for (i, r) in rules.iter().enumerate() {
        println!(
            "  Rule {:>2}: {:?}  ({} bytes)",
            i,
            std::str::from_utf8(r).unwrap_or("<binary>"),
            r.len()
        );
    }

    // Derive window length — all rules in a group must be same length
    let window_len = rules
        .iter()
        .map(|r| r.len())
        .max()
        .expect("Rule group is empty");

    // Validate all rules are same length
    for r in &rules {
        assert_eq!(
            r.len(),
            window_len,
            "All rules in a group must be the same length. \
             Group [{}] has mixed lengths.",
            name
        );
    }

    println!("  Window length: {} bytes", window_len);

    // Encrypt rules
    let enc_start = Instant::now();
    let enc_rules = EncryptedRules::new(client_key, &rules, window_len);
    println!("  Rule encryption: {:.3?}", enc_start.elapsed());

    // Build Bloom filter
    let bloom = BloomFilter::build_from_rules(&rules, window_len, fp_rate);
    let (m, k, bits_set) = bloom.stats();
    println!(
        "  Bloom: m={} bits  k={} hashes  {}/{} bits set  fp_rate={}",
        m, k, bits_set, m, fp_rate
    );

    RuleGroup {
        name:       name.to_string(),
        rules:      enc_rules,
        bloom,
        window_len,
    }
}

// ============================================================
// main
// ============================================================

fn main() {
    // --------------------------------------------------------
    // Configuration
    // --------------------------------------------------------
    let payload_file = "data/cicids_dataset_shuffled.txt";
    let group_a_file = "data/group_a_rules.txt";
    let group_b_file = "data/group_b_rules.txt";
    let fp_rate      = 0.1;

    // --------------------------------------------------------
    // Stage 1 — Generate TFHE keys
    // --------------------------------------------------------
    println!("Initializing TFHE keys...");
    let keygen_start = Instant::now();
    let (client_key, server_key) = generate_keys();
    println!("  Key generation: {:.3?}", keygen_start.elapsed());

    // --------------------------------------------------------
    // Stage 2 — Build rule groups
    //
    // Each group is self-contained:
    //   - its own rules (same length within group)
    //   - its own Bloom filter (tuned to its window size)
    //   - its own encrypted rule tokens
    // --------------------------------------------------------
    let group_a = build_rule_group("Group-A-5byte", group_a_file, fp_rate, &client_key);
    let group_b = build_rule_group("Group-B-6byte", group_b_file, fp_rate, &client_key);

    let groups = vec![group_a, group_b];

    // --------------------------------------------------------
    // Stage 3 — Load payload dataset
    // --------------------------------------------------------
    println!("\nLoading payload dataset...");
    let payloads = load_payloads(payload_file);
    println!("  Loaded {} payload(s)", payloads.len());

    // Normalise payloads to lowercase before encryption
    let payloads = normalize_payloads(payloads);
    println!("  Normalization complete");

    // --------------------------------------------------------
    // Stage 4 — Run multi-group ODPI
    // --------------------------------------------------------
    println!("\nRunning ODPI...");
    process_payloads_multigroup(
        &server_key,
        &client_key,
        &groups,
        &payloads,
    );
}
