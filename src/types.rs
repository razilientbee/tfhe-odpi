// ============================================================
// types.rs
// ============================================================
// Shared Type Aliases for TFHE-ODPI
//
// Purpose
// -------
// Defines canonical type aliases for all encrypted data
// structures used across the pipeline. Every module that
// handles ciphertext imports from here, ensuring a single
// source of truth for the encrypted type hierarchy.
//
// Type Hierarchy
// --------------
//
//   EncryptedBit
//       └── one TFHE Boolean ciphertext
//           encrypts a single bit (true/false)
//
//   EncryptedByte
//       └── Vec<EncryptedBit>  (length = 8)
//           encrypts one u8 as 8 individual bits
//           bit ordering: LSB first (index 0 = bit 0)
//
//   EncryptedWindow
//       └── Vec<EncryptedByte>  (length = window_len)
//           encrypts a payload window of window_len bytes
//           used as input to the FHE matcher
//
//   EncryptedRule
//       └── Vec<EncryptedByte>  (length = window_len)
//           encrypts a detection rule token
//           same shape as EncryptedWindow for direct comparison
//
// Why type aliases and not newtypes?
// -----------------------------------
// TFHE operations (xnor, mux, or, and) consume and return
// raw Ciphertext values. Wrapping them in newtypes would
// require unwrapping on every gate call. Aliases give
// readability without runtime cost or API friction.
//
// Pipeline usage
// --------------
//
//   data_loader.rs  → produces EncryptedByte, EncryptedWindow
//   rules.rs        → produces EncryptedRule
//   matcher.rs      → consumes EncryptedWindow + EncryptedRule
//                     returns EncryptedBit (match result)
//   tree_reduce.rs  → consumes Vec<EncryptedBit>
//                     returns EncryptedBit
//
// ============================================================

use tfhe::boolean::prelude::*;

/// A single encrypted Boolean bit.
/// Wraps one TFHE Boolean ciphertext.
/// Encrypts: true (1) or false (0).
pub type EncryptedBit = Ciphertext;

/// An encrypted byte represented as 8 encrypted bits.
/// Length is always exactly 8.
/// Bit ordering: index 0 = LSB (least significant bit).
///
/// Example: byte 0b00000101 (decimal 5) encodes as:
///   [enc(1), enc(0), enc(1), enc(0), enc(0), enc(0), enc(0), enc(0)]
pub type EncryptedByte = Vec<EncryptedBit>;

/// An encrypted payload window of window_len bytes.
/// Each element is one EncryptedByte (8 bits).
/// Length equals window_len set at runtime from rule length.
/// Passed to encrypted_match_token for FHE comparison.
pub type EncryptedWindow = Vec<EncryptedByte>;

/// An encrypted rule token of window_len bytes.
/// Structurally identical to EncryptedWindow.
/// Stored in EncryptedRules.tokens for reuse across packets.
pub type EncryptedRule = Vec<EncryptedByte>;
