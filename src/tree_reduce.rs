// ============================================================
// tree_reduce.rs
// ============================================================
// Balanced Reduction Circuit for TFHE
//
// Purpose
// -------
// Provides balanced aggregation circuit:
//
// • tree_or
//
// Reduces circuit depth from O(n) to O(log n).
//
// ============================================================

use tfhe::boolean::ciphertext::Ciphertext;
use tfhe::boolean::prelude::*;


/// ------------------------------------------------------------
/// tree_or
///
/// Balanced OR reduction
/// ------------------------------------------------------------
pub fn tree_or(
    server_key: &ServerKey,
    mut inputs: Vec<Ciphertext>,
) -> Ciphertext {

    if inputs.is_empty() {
        return server_key.trivial_encrypt(false);
    }

    while inputs.len() > 1 {

        inputs = inputs
            .chunks(2)
            .map(|pair| {

                if pair.len() == 2 {

                    server_key.or(&pair[0], &pair[1])

                } else {

                    pair[0].clone()
                }

            })
            .collect();
    }

    inputs.pop().unwrap()
}



