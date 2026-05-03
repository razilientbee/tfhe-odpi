// ============================================================
// main.rs
// ============================================================
// Entry Point for TFHE-ODPI
//
// Pipeline stages:
//   1. Generate TFHE keys
//   2. Build rule groups (encrypt rules + build Bloom filters)
//   3. Load and normalise payload dataset
//   4. Run encrypted ODPI inspection (multi-group)
//   5. Compute and report evaluation metrics
//   6. Export CSV + LaTeX results
//
// ============================================================

use tfhe_odpi::keys::generate_keys;
use tfhe_odpi::data_loader::load_payloads;
use tfhe_odpi::normalizer::normalize_payloads;
use tfhe_odpi::payload_processor::{process_payloads_multigroup, RuleGroup};
use tfhe_odpi::bloom::BloomFilter;
use tfhe_odpi::rules::EncryptedRules;
use tfhe_odpi::metrics;

use std::fs;
use std::time::Instant;

// ============================================================
// Configuration
// ============================================================

const PAYLOAD_FILE: &str = "data/cicids_dataset_shuffled2.txt";
const LABEL_FILE:   &str = "data/cicids_labels_shuffled2.txt";
const GROUP_A_FILE: &str = "data/group_a_rules.txt";
const GROUP_B_FILE: &str = "data/group_b_rules.txt";
const FP_RATE:      f64  = 0.1;
const RUN_NAME:     &str = "Run6-reshuffled";

// ============================================================
// Helper — load rules from file
// ===========================================================Run6-reshuffle=

fn load_rules(path: &str) -> Vec<Vec<u8>> {
    fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("Failed to read rule file '{}': {}", path, e))
        .lines()
        .map(|line| line.trim_end_matches('\n').as_bytes().to_vec())
        .filter(|r| !r.is_empty())
        .collect()
}

// ============================================================
// Helper — build a RuleGroup
// ============================================================

fn build_rule_group(
    name:       &str,
    rule_file:  &str,
    fp_rate:    f64,
    client_key: &tfhe::boolean::prelude::ClientKey,
) -> RuleGroup {
    println!("\nBuilding group: [{}]", name);

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

    let window_len = rules.iter().map(|r| r.len()).max()
        .expect("Rule group is empty");

    for r in &rules {
        assert_eq!(
            r.len(), window_len,
            "All rules in group [{}] must be the same length", name
        );
    }

    println!("  Window length: {} bytes", window_len);

    let enc_start = Instant::now();
    let enc_rules = EncryptedRules::new(client_key, &rules, window_len);
    println!("  Rule encryption: {:.3?}", enc_start.elapsed());

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
    // Stage 1 — Generate TFHE keys
    // --------------------------------------------------------
    println!("Initializing TFHE keys...");
    let keygen_start = Instant::now();
    let (client_key, server_key) = generate_keys();
    println!("  Key generation: {:.3?}", keygen_start.elapsed());

    // --------------------------------------------------------
    // Stage 2 — Build rule groups
    // --------------------------------------------------------
    let group_a = build_rule_group("Group-A-5byte", GROUP_A_FILE, FP_RATE, &client_key);
    let group_b = build_rule_group("Group-B-6byte", GROUP_B_FILE, FP_RATE, &client_key);
    let groups  = vec![group_a, group_b];

    // --------------------------------------------------------
    // Stage 3 — Load and normalise payload dataset
    // --------------------------------------------------------
    println!("\nLoading payload dataset...");
    let payloads = load_payloads(PAYLOAD_FILE);
    println!("  Loaded {} payload(s)", payloads.len());
    let payloads = normalize_payloads(payloads);
    println!("  Normalization complete");

    // Load ground truth labels for metrics
    let labels: Vec<String> = fs::read_to_string(LABEL_FILE)
        .unwrap_or_else(|e| panic!("Failed to read label file '{}': {}", LABEL_FILE, e))
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    println!("  Loaded {} label(s)", labels.len());

    // --------------------------------------------------------
    // Stage 4 — Run ODPI
    // --------------------------------------------------------
    println!("\nRunning ODPI...");
    let odpi_start = Instant::now();
    let results = process_payloads_multigroup(
        &server_key,
        &client_key,
        &groups,
        &payloads,
    );
    let wall_time = odpi_start.elapsed().as_secs_f64();

    // --------------------------------------------------------
    // Stage 5 — Compute and display metrics
    // --------------------------------------------------------
    println!("\nComputing evaluation metrics...");
    let eval = metrics::compute(RUN_NAME, &results, &labels, wall_time);
    metrics::print_table(&eval);

    // --------------------------------------------------------
    // Stage 6 — Export results
    // --------------------------------------------------------
    metrics::write_csv(&eval, &results, &labels);
    metrics::write_latex(&eval);
    metrics::finalise_latex();

    println!("\nAll outputs written to results/");
}
