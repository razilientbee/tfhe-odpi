// ============================================================
// lib.rs
// ============================================================
// TFHE-ODPI Crate Module Registry
//
// Purpose
// -------
// Declares all public modules that make up the TFHE-ODPI
// crate. This is the single authoritative list of what
// exists in the pipeline.
//
// Module Execution Order
// ----------------------
//
// Stage 0 — shared infrastructure (imported everywhere)
//   types        type aliases for all encrypted structures
//   keys         TFHE key generation wrapper
//
// Stage 1 — startup, runs once
//   rules        encrypt detection rules → EncryptedRules
//   bloom        build Bloom filter from rule n-grams
//
// Stage 2 — data loading, runs once
//   data_loader  load payload dataset from disk
//
// Stage 3 — per-packet inspection loop (Rayon parallel)
//   payload_processor  sliding window → bloom → FHE → alert
//
// Stage 4 — homomorphic compute (called from payload_processor)
//   substring_matcher  iterate rules, collect match results
//   matcher            byte-level XNOR+MUX equality circuit
//   tree_reduce        balanced OR/AND reduction O(log n)
//
// Removed Modules
// ---------------
// payload_detect — REMOVED
//   Reason: applied a 70% ASCII readability heuristic that
//   silently dropped valid payloads before inspection,
//   causing missed detections (false negatives). DPI must
//   inspect all payloads regardless of content type.
//
// Planned Modules
// ---------------
// normalizer — to be added in Phase 1
//   Will handle payload byte normalisation (e.g. lowercase
//   conversion) before encryption to support case-insensitive
//   rule matching.
//
// ============================================================

// Stage 0 — shared infrastructure
pub mod types;
pub mod keys;

// Stage 1 — startup
pub mod rules;
pub mod bloom;

// Stage 2 — data loading
pub mod data_loader;
pub mod normalizer;
pub mod metrics;

// Stage 3 — pipeline
pub mod payload_processor;

// Stage 4 — homomorphic compute
pub mod substring_matcher;
pub mod matcher;
pub mod tree_reduce;
