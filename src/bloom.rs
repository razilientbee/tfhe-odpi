// ============================================================
// bloom.rs
// ============================================================
// Bloom Filter Implementation for ODPI Candidate Pruning
//
// Purpose
// -------
// This module implements a Bloom filter used to quickly discard
// payload windows that cannot match any detection rule.
//
// Bloom filtering occurs entirely in plaintext before the system
// performs expensive TFHE encrypted evaluation.
//
// Changes from previous version
// ------------------------------
// 1. Formula-based parameter sizing (m and k derived from n and p)
// 2. N-gram insertion: every rule-length window from each rule
//    is inserted, not just the full rule bytes
// 3. Double hashing replaced DefaultHasher seeding with a proper
//    Kirsch-Mitzenmacher two-hash scheme using FNV + DJB2
//    for determinism and independence
//
// Design Principles
// -----------------
// • Operates on raw byte slices
// • Deterministic hashing (no std randomness)
// • Multiple independent hash functions via double hashing
// • No cryptographic operations
//
// Pipeline Position
// -----------------
//
// payload_processor
//       ↓
// sliding windows
//       ↓
// bloom.might_contain(window)
//       ↓
// if TRUE  → encrypt + evaluate
// if FALSE → skip (definitely not a match)
//
// ============================================================

/// Bloom filter structure
pub struct BloomFilter {
    bit_vec: Vec<bool>,
    m: usize,
    k: usize,
}

impl BloomFilter {
    // --------------------------------------------------------
    // new
    //
    // Create a Bloom filter with explicit parameters.
    //
    // Parameters
    // ----------
    // m : number of bits in the filter
    // k : number of hash functions
    // --------------------------------------------------------
    pub fn new(m: usize, k: usize) -> Self {
        Self {
            bit_vec: vec![false; m],
            m,
            k,
        }
    }

    // --------------------------------------------------------
    // with_params
    //
    // Create a Bloom filter sized for n items and target false
    // positive rate p using the standard formulae:
    //
    //   m = ceil(-n * ln(p) / (ln 2)^2)
    //   k = round((m / n) * ln 2)
    //
    // Parameters
    // ----------
    // n : expected number of items to insert
    // p : desired false positive probability (e.g. 0.01 = 1%)
    //
    // Why this matters
    // ----------------
    // The previous hardcoded m=10_000 with k=3 was massively
    // over-provisioned for 3 rules and left hash coverage too
    // sparse. This causes near-zero FP rate but also means
    // legitimate candidate windows get pruned incorrectly when
    // the hash positions do not align. Formula-derived params
    // give the correct trade-off.
    // --------------------------------------------------------
   pub fn with_params(n: usize, p: f64) -> Self {
    let ln2 = std::f64::consts::LN_2;
    let m = (-(n as f64) * p.ln() / (ln2 * ln2)).ceil() as usize;
    let m = m.max(64);
    let k = ((m as f64 / n as f64) * ln2).round() as usize;
    let k = k.clamp(1, 7);  // ← add this, was just .max(1)
    Self::new(m, k)
}

    // --------------------------------------------------------
    // hash_pair
    //
    // Compute two independent 64-bit hashes of data using:
    //   h1 : FNV-1a
    //   h2 : DJB2
    //
    // These form the basis of Kirsch-Mitzenmacher double
    // hashing:
    //
    //   g_i(x) = h1(x) + i * h2(x)   mod m
    //
    // This gives k near-independent hash functions from two
    // base hashes, with no collision between seeds and no
    // reliance on DefaultHasher (which is not guaranteed to
    // be deterministic across Rust versions).
    // --------------------------------------------------------
    fn hash_pair(data: &[u8]) -> (u64, u64) {
        // FNV-1a
        let mut h1: u64 = 14_695_981_039_346_656_037;
        for &byte in data {
            h1 ^= byte as u64;
            h1 = h1.wrapping_mul(1_099_511_628_211);
        }

        // DJB2
        let mut h2: u64 = 5381;
        for &byte in data {
            h2 = h2.wrapping_shl(5).wrapping_add(h2).wrapping_add(byte as u64);
        }

        (h1, h2)
    }

    // --------------------------------------------------------
    // bit_index
    //
    // Compute the i-th hash position using double hashing.
    //
    // g_i(x) = (h1 + i * h2) mod m
    //
    // The h2 | 1 ensures h2 is always odd, which guarantees
    // it is coprime with m (if m is a power of 2) and avoids
    // degenerate cycles where multiple i values map to the
    // same index.
    // --------------------------------------------------------
    fn bit_index(&self, h1: u64, h2: u64, i: usize) -> usize {
        let h2_odd = h2 | 1;
        h1.wrapping_add((i as u64).wrapping_mul(h2_odd)) as usize % self.m
    }

    // --------------------------------------------------------
    // insert
    //
    // Insert an item into the Bloom filter.
    // --------------------------------------------------------
    pub fn insert(&mut self, item: &[u8]) {
        let (h1, h2) = Self::hash_pair(item);
        for i in 0..self.k {
            let idx = self.bit_index(h1, h2, i);
            self.bit_vec[idx] = true;
        }
    }

    // --------------------------------------------------------
    // might_contain
    //
    // Query Bloom filter membership.
    //
    // Returns
    // -------
    // true  → possible match (may be a false positive)
    // false → definitely not present
    // --------------------------------------------------------
    pub fn might_contain(&self, item: &[u8]) -> bool {
        let (h1, h2) = Self::hash_pair(item);
        for i in 0..self.k {
            let idx = self.bit_index(h1, h2, i);
            if !self.bit_vec[idx] {
                return false;
            }
        }
        true
    }

    // --------------------------------------------------------
    // build_from_rules
    //
    // Construct a Bloom filter from detection rules.
    //
    // Key fix from previous version
    // ------------------------------
    // The old version inserted entire rule byte sequences.
    // The sliding window in payload_processor slices windows
    // of length == rule_len. For might_contain(window) to
    // correctly pass a candidate, the filter must have been
    // populated with those same-length n-grams.
    //
    // This version inserts every rule-length n-gram that
    // appears anywhere within each rule, ensuring that any
    // window which overlaps a rule token will pass the filter.
    //
    // For rules shorter than window_len (unusual), the rule
    // itself is inserted directly.
    //
    // Parameters
    // ----------
    // rules      : raw byte sequences of detection rules
    // window_len : length of sliding window (= max rule length)
    // fp_rate    : target false positive probability
    // --------------------------------------------------------
    pub fn build_from_rules(
        rules: &[Vec<u8>],
        window_len: usize,
        fp_rate: f64,
    ) -> Self {
        // Count total n-grams to size the filter correctly
        let total_ngrams: usize = rules
            .iter()
            .map(|r| {
                if r.len() >= window_len {
                    r.len() - window_len + 1
                } else {
                    1
                }
            })
            .sum();

        let n = total_ngrams.max(1);
        let mut bloom = BloomFilter::with_params(n, fp_rate);

        for rule in rules {
            if rule.len() >= window_len {
                // Insert every window-length n-gram from the rule.
                // This ensures that a sliding window of length
                // window_len that aligns with any part of the rule
                // will pass might_contain().
                for ngram in rule.windows(window_len) {
                    bloom.insert(ngram);
                }
            } else {
                // Rule is shorter than the window — insert as-is.
                bloom.insert(rule);
            }
        }

        bloom
    }

    // --------------------------------------------------------
    // stats
    //
    // Return (m, k, bits_set) for benchmarking / reporting.
    // --------------------------------------------------------
    pub fn stats(&self) -> (usize, usize, usize) {
        let bits_set = self.bit_vec.iter().filter(|&&b| b).count();
        (self.m, self.k, bits_set)
    }
}
