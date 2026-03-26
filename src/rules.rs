// ============================================================
// rules.rs
// ============================================================
// Detection Rule Representation and Encryption
//
// Changes from previous version
// ------------------------------
// 1. Rules are padded to window_len before encryption.
//    The matcher performs byte-by-byte equality over a fixed
//    window. If a rule is shorter than window_len, the token
//    comparison would fail on the padding bytes. Explicit
//    zero-padding makes the mismatch intentional and visible.
//
//    For the current ruleset (USER, PASS, HTTP — all 4 bytes)
//    this has no effect, but it makes the module correct for
//    mixed-length rulesets.
//
// 2. window_len is now stored on the struct so downstream
//    modules can read it without recomputing.
//
// 3. rule_bytes stores the original unpadded bytes for Bloom
//    filter construction (Bloom uses raw rule bytes, not
//    padded encrypted form).
// ============================================================

use tfhe::boolean::prelude::*;

/// ============================================================
/// EncryptedRules
///
/// tokens
///     Encrypted bit representation of each rule, padded to
///     window_len bytes. Shape: [rule][byte][bit]
///
/// rule_bytes
///     Original plaintext rule bytes (unpadded).
///     Used by BloomFilter::build_from_rules.
///
/// window_len
///     The uniform length all tokens are padded to.
///     Must match the window_len used in payload_processor.
/// ============================================================
pub struct EncryptedRules {
    pub tokens:     Vec<Vec<Vec<Ciphertext>>>,
    pub rule_bytes: Vec<Vec<u8>>,
    pub window_len: usize,
}

impl EncryptedRules {
    /// --------------------------------------------------------
    /// new
    ///
    /// Encrypt plaintext rules, padding each to window_len.
    ///
    /// Parameters
    /// ----------
    /// client_key : TFHE client key
    /// rules      : raw rule byte sequences
    /// window_len : target token length (= max rule length)
    /// --------------------------------------------------------
    pub fn new(
        client_key: &ClientKey,
        rules: &[Vec<u8>],
        window_len: usize,
    ) -> Self {
        let tokens = rules
            .iter()
            .map(|rule| {
                // Pad rule to window_len with zero bytes
                let mut padded = rule.clone();
                padded.resize(window_len, 0u8);

                padded
                    .iter()
                    .map(|byte| encrypt_byte(client_key, *byte))
                    .collect()
            })
            .collect();

        Self {
            tokens,
            rule_bytes: rules.to_vec(),
            window_len,
        }
    }
}

/// ------------------------------------------------------------
/// encrypt_byte
///
/// Encode a u8 as 8 encrypted TFHE Boolean ciphertexts.
///
/// Bit ordering: LSB first (bit 0 = least significant)
/// This matches the encoding used in data_loader::encrypt_byte.
/// ------------------------------------------------------------
fn encrypt_byte(client_key: &ClientKey, byte: u8) -> Vec<Ciphertext> {
    (0..8)
        .map(|bit_index| {
            let bit = (byte >> bit_index) & 1;
            client_key.encrypt(bit == 1)
        })
        .collect()
}
