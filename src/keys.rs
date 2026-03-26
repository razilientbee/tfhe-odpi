// ============================================================
// keys.rs
// ============================================================
// TFHE Key Generation for TFHE-ODPI
//
// Purpose
// -------
// Centralised wrapper for TFHE Boolean key generation.
// Provides a single named function that main.rs calls,
// making the key generation step explicit and auditable.
//
// Security Model
// --------------
// • ClientKey  — held only by the client (trusted party)
//               used for: encrypting payloads, encrypting rules,
//               decrypting the final alert result
//               MUST NEVER be sent to or accessed by the server
//
// • ServerKey  — given to the server (honest-but-curious)
//               used for: all homomorphic gate operations
//               (xnor, mux, or, and, trivial_encrypt)
//               contains no information about plaintext values
//               safe to share with the server
//
// Key Generation Notes
// --------------------
// • gen_keys() uses TFHE default Boolean parameters
//   (tfhe::boolean::parameters::DEFAULT_PARAMETERS)
// • Key generation is probabilistic and uses OS entropy
// • Keys are generated fresh on every run — no persistence
// • Key generation takes ~100ms in release mode
// • Keys are large (~10MB for ServerKey) — pass by reference
//   everywhere, never clone
//
// Future Extensions
// -----------------
// • Key serialisation: use tfhe's built-in bincode support
//   to save/load keys for long-running server deployments
// • Custom parameters: replace gen_keys() with
//   gen_keys_with_parameters() for tuned security/perf tradeoff
//
// Pipeline Position
// -----------------
//
//   main.rs
//      ↓
//   keys::generate_keys()
//      ↓
//   (ClientKey, ServerKey)
//      ↓
//   ClientKey → rules.rs, data_loader.rs, payload_processor.rs
//   ServerKey → payload_processor.rs, substring_matcher.rs,
//               matcher.rs, tree_reduce.rs
//
// ============================================================

use tfhe::boolean::prelude::*;

/// Generate a fresh TFHE Boolean (ClientKey, ServerKey) pair.
///
/// This is the only function in the pipeline that produces
/// key material. Both keys are generated atomically from the
/// same internal RNG state, ensuring they are cryptographically
/// paired.
///
/// Returns
/// -------
/// (ClientKey, ServerKey)
///
/// ClientKey : kept on the trusted client side only
/// ServerKey : passed to the server-side evaluation functions
///
/// Notes
/// -----
/// • Call once at startup — never regenerate mid-pipeline
/// • Pass ServerKey as &ServerKey everywhere (it is large)
/// • Pass ClientKey as &ClientKey everywhere
pub fn generate_keys() -> (ClientKey, ServerKey) {
    gen_keys()
}
