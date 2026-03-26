// ============================================================
// substring_matcher.rs
// ============================================================
// Homomorphic Substring Matching for ODPI
//
// Changes from previous version
// ------------------------------
// 1. RAYON FIX: Changed rules.tokens.par_iter() to .iter()
//
//    The previous version used par_iter() here while
//    payload_processor also uses par_iter() across packets.
//    This creates nested Rayon parallelism — both the outer
//    packet loop and the inner rule loop compete for the same
//    thread pool, causing thread contention and scheduler
//    overhead that dominates actual FHE compute time.
//
//    The correct strategy:
//    • Outer parallelism  → across packets (par_iter in
//      payload_processor) — high payoff, packets are fully
//      independent
//    • Inner parallelism  → sequential across rules — with
//      only 3 rules the thread spawn cost exceeds the savings
//
//    When your ruleset grows beyond ~20 rules, you can
//    reintroduce par_iter here and remove it from the packet
//    loop, or use a Rayon thread pool with explicit scope to
//    prevent nesting. For now sequential is correct.
//
// 2. Accepts enc_window as &[Vec<Ciphertext>] (a slice of the
//    pre-encrypted payload) rather than a freshly allocated
//    Vec, consistent with the batch-encrypt approach in
//    payload_processor.
// ============================================================

use crate::matcher::encrypted_match_token;
use crate::rules::EncryptedRules;
use crate::tree_reduce::tree_or;
use tfhe::boolean::prelude::*;

/// ------------------------------------------------------------
/// encrypted_substring_match
///
/// Compare an encrypted payload window against all encrypted
/// rules and return an encrypted boolean indicating whether
/// any rule matched.
///
/// Parameters
/// ----------
/// server_key : TFHE server key
/// payload    : encrypted window slice — &[Vec<Ciphertext>]
///              each inner Vec is one encrypted byte (8 bits)
/// rules      : encrypted rule tokens
///
/// Returns
/// -------
/// Ciphertext
///   TRUE  → at least one rule matched this window
///   FALSE → no rule matched
///
/// Circuit structure
/// -----------------
/// For R rules each of W bytes, this evaluates:
///
///   OR(
///     match_token(window, rule_0),
///     match_token(window, rule_1),
///     ...
///     match_token(window, rule_R)
///   )
///
/// match_token itself is:
///
///   AND(eq_8bit(w[0], r[0]), eq_8bit(w[1], r[1]), ...)
///
/// eq_8bit uses XNOR + MUX propagation (see matcher.rs).
///
/// Total gate depth per window:
///   log2(8) MUX levels per byte   (matcher)
/// + log2(W) AND levels per token  (matcher)
/// + log2(R) OR  levels            (tree_reduce)
/// ------------------------------------------------------------
pub fn encrypted_substring_match(
    server_key: &ServerKey,
    payload: &[Vec<Ciphertext>],
    rules: &EncryptedRules,
) -> Ciphertext {
    // Sequential rule evaluation — no nested Rayon
    let rule_results: Vec<Ciphertext> = rules
        .tokens
        .iter()                    // was par_iter() — see change note above
        .map(|rule| {
            encrypted_match_token(server_key, payload, rule)
        })
        .collect();

    // Balanced OR reduction across rule results — O(log R) depth
    tree_or(server_key, rule_results)
}
