// ============================================================
// matcher.rs
// ============================================================
// Homomorphic Equality Circuits for TFHE-ODPI
//
// Purpose
// -------
// This module implements encrypted equality circuits used by
// the ODPI matcher. These circuits compare encrypted payload
// bytes against encrypted rule bytes.
//
// The implementation uses a MUX-based propagation circuit
// inspired by homomorphic YARA rule evaluation work.
//
// Why MUX?
// --------
// Instead of a long chain of AND gates:
//
//     eq0 AND eq1 AND eq2 AND ... eq7
//
// we propagate equality using:
//
//     result = MUX(bit_eq, result, false)
//
// This keeps the circuit structure constant while reducing
// dependency depth, which improves TFHE performance.
//
// Security Properties
// -------------------
// • Constant circuit structure
// • No early exits
// • No rule leakage
// • No payload leakage
//
// ============================================================

use tfhe::boolean::ciphertext::Ciphertext;
use tfhe::boolean::prelude::*;



// ============================================================
// encrypted_eq_8bit_mux
// ------------------------------------------------------------
// Compare two encrypted bytes using a MUX propagation circuit.
//
// Parameters
// ----------
// server_key : TFHE server key
// a          : encrypted byte (Vec<Ciphertext>, length = 8)
// b          : encrypted byte (Vec<Ciphertext>, length = 8)
//
// Returns
// -------
// Ciphertext
//
// TRUE  -> bytes are equal
// FALSE -> bytes differ
//
// ============================================================

pub fn encrypted_eq_8bit_mux(
    server_key: &ServerKey,
    a: &[Ciphertext],
    b: &[Ciphertext],
) -> Ciphertext {

    debug_assert!(a.len() == 8, "Left operand must be 8 bits");
    debug_assert!(b.len() == 8, "Right operand must be 8 bits");

    // Start with equality assumed true
    let mut result = server_key.trivial_encrypt(true);

    // Constant false ciphertext
    let false_ct = server_key.trivial_encrypt(false);

    // Evaluate each bit
    for i in 0..8 {

        // Compare encrypted bits
        let bit_eq = server_key.xnor(&a[i], &b[i]);

        // Propagate equality using MUX
        result = server_key.mux(&bit_eq, &result, &false_ct);
    }

    result
}



// ============================================================
// encrypted_match_token
// ------------------------------------------------------------
// Compare encrypted byte sequences for exact equality.
//
// This function compares a payload window against an encrypted
// rule token.
//
// Parameters
// ----------
// server_key : TFHE server key
// data       : encrypted payload window
// token      : encrypted rule token
//
// Returns
// -------
// Ciphertext
//
// TRUE  -> sequences match exactly
// FALSE -> sequences differ
//
// ============================================================

pub fn encrypted_match_token(
    server_key: &ServerKey,
    data: &[Vec<Ciphertext>],
    token: &[Vec<Ciphertext>],
) -> Ciphertext {

    debug_assert!(
        data.len() == token.len(),
        "Token and data length mismatch"
    );

    // Start with equality assumed true
    let mut result = server_key.trivial_encrypt(true);

    // Constant false ciphertext
    let false_ct = server_key.trivial_encrypt(false);

    for i in 0..token.len() {

        // Compare each byte using the MUX equality circuit
        let byte_eq =
            encrypted_eq_8bit_mux(server_key, &data[i], &token[i]);

        // Propagate equality
        result = server_key.mux(&byte_eq, &result, &false_ct);
    }

    result
}
