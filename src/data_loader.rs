// ============================================================
// data_loader.rs
// ============================================================
// Payload Loading and Encryption Utilities for TFHE-ODPI
//
// Purpose
// -------
// This module handles:
//
// 1. Loading payload datasets from disk
// 2. Representing payloads as raw byte arrays (Vec<u8>)
// 3. Converting plaintext bytes into encrypted TFHE bit vectors
//
// Design Principles
// -----------------
// • Payloads remain plaintext during preprocessing
// • Encryption occurs only when required for FHE matching
// • Each byte is encoded as 8 encrypted bits
//
// Byte Encoding Model
// -------------------
//
// Plaintext byte:
//
//      u8
//
// Binary representation:
//
//      b7 b6 b5 b4 b3 b2 b1 b0
//
// Encrypted representation:
//
//      Vec<Ciphertext> (length = 8)
//
// Full payload representation:
//
//      Vec<byte>
//          Vec<encrypted bit>
//
// This encoding allows exact byte equality checks during
// homomorphic substring matching.
//
// Pipeline Position
// -----------------
//
// data_loader (this module)
//        ↓
// payload_processor
//        ↓
// bloom filter pruning
//        ↓
// encrypted substring matching
//
// ============================================================

use std::fs::File;
use std::io::{BufRead, BufReader};

use tfhe::boolean::ciphertext::Ciphertext;
use tfhe::boolean::client_key::ClientKey;

/// ------------------------------------------------------------
/// load_payloads
///
/// Load payloads from a text file.
///
/// Each non-empty line is interpreted as a payload and
/// converted into a byte vector.
///
/// Parameters
/// ----------
/// path : &str
///     Path to the payload dataset file.
///
/// Returns
/// -------
/// Vec<Vec<u8>>
///     Collection of payload byte arrays.
///
/// Notes
/// -----
/// • Empty lines are ignored
/// • Leading and trailing whitespace is removed
/// • No payload filtering occurs here
/// ------------------------------------------------------------
pub fn load_payloads(path: &str) -> Vec<Vec<u8>> {

    let file = File::open(path)
        .unwrap_or_else(|e| panic!("Failed to open payload file '{}': {}", path, e));

    let reader = BufReader::new(file);

    reader
        .lines()
        .filter_map(Result::ok)
        .map(|line| line.trim().to_string())  // trim() handles \r\n on both platforms
        .map(|line| line.into_bytes())
        .filter(|payload| !payload.is_empty())
        .collect()
}

/// ------------------------------------------------------------
/// encrypt_byte
///
/// Convert a plaintext byte into 8 encrypted TFHE bits.
///
/// Parameters
/// ----------
/// client_key : &ClientKey
///     TFHE client key used for encryption
///
/// byte : u8
///     Plaintext byte
///
/// Returns
/// -------
/// Vec<Ciphertext>
///     Encrypted bit vector (length = 8)
///
/// Bit Ordering
/// ------------
/// Least Significant Bit first (LSB → MSB)
///
/// This matches the encoding used for encrypted rules.
/// ------------------------------------------------------------
pub fn encrypt_byte(
    client_key: &ClientKey,
    byte: u8,
) -> Vec<Ciphertext> {

    (0..8)
        .map(|bit_index| {

            let bit = (byte >> bit_index) & 1;

            client_key.encrypt(bit == 1)

        })
        .collect()
}

/// ------------------------------------------------------------
/// encrypt_window
///
/// Encrypt an entire payload window.
///
/// Parameters
/// ----------
/// client_key : &ClientKey
///     TFHE client key
///
/// window : &[u8]
///     Payload window bytes
///
/// Returns
/// -------
/// Vec<Vec<Ciphertext>>
///
/// Structure
/// ---------
///
/// Vec<byte>
///     Vec<encrypted bit>
/// ------------------------------------------------------------
pub fn encrypt_window(
    client_key: &ClientKey,
    window: &[u8],
) -> Vec<Vec<Ciphertext>> {

    window
        .iter()
        .map(|byte| encrypt_byte(client_key, *byte))
        .collect()
}
