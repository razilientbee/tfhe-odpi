// ============================================================
// normalizer.rs
// ============================================================
// Payload Normalisation for TFHE-ODPI
//
// Purpose
// -------
// Converts raw payload bytes to a canonical form before
// encryption and FHE matching. Normalisation ensures that
// rule matching is case-insensitive — the rule "user" will
// match payloads containing "USER", "User", or "user".
//
// Why normalisation matters
// -------------------------
// FTP commands and HTTP keywords can appear in any case
// depending on the client implementation:
//
//   "USER admin"  → standard FTP client
//   "user admin"  → some FTP implementations
//   "User admin"  → rare but valid
//
// Without normalisation, a rule "user" only matches the
// exact byte sequence 0x75 0x73 0x65 0x72. With
// normalisation, all three variants map to the same bytes
// before encryption, so a single lowercase rule covers all.
//
// Design principles
// -----------------
// • Operates on plaintext bytes only — before encryption
// • Non-destructive to non-alphabetic bytes
// • ASCII-only lowercasing (bytes 0x41-0x5A → 0x61-0x7A)
// • Binary bytes (>0x7F) are passed through unchanged
// • Zero allocation for already-lowercase payloads is NOT
//   guaranteed — simplicity is preferred over micro-optimisation
//
// Security note
// -------------
// Normalisation happens on the CLIENT side before encryption.
// The server never sees normalised or unnormalised plaintext.
// This does not affect the privacy guarantee.
//
// Pipeline position
// -----------------
//
//   data_loader::load_payloads()
//          ↓
//   normalizer::normalize_payloads()   ← this module
//          ↓
//   payload_processor::process_payloads()
//          ↓
//   bloom filter + FHE matching
//
// ============================================================

/// ------------------------------------------------------------
/// normalize_byte
///
/// Convert a single byte to its ASCII lowercase equivalent.
///
/// Parameters
/// ----------
/// b : u8 — input byte
///
/// Returns
/// -------
/// u8 — lowercase byte if ASCII uppercase (A-Z), else unchanged
///
/// Examples
/// --------
/// normalize_byte(b'U') → b'u'
/// normalize_byte(b'u') → b'u'   (already lowercase)
/// normalize_byte(b'1') → b'1'   (digit, unchanged)
/// normalize_byte(0xFF) → 0xFF   (binary, unchanged)
/// ------------------------------------------------------------
#[inline]
pub fn normalize_byte(b: u8) -> u8 {
    // ASCII uppercase range: 0x41 ('A') to 0x5A ('Z')
    // OR with 0x20 sets bit 5, converting to lowercase
    // This is equivalent to b + 32 for uppercase letters only
    if b.is_ascii_uppercase() {
        b | 0x20
    } else {
        b
    }
}

/// ------------------------------------------------------------
/// normalize_payload
///
/// Convert all bytes in a payload to ASCII lowercase.
///
/// Parameters
/// ----------
/// payload : &[u8] — raw payload bytes
///
/// Returns
/// -------
/// Vec<u8> — normalised payload bytes
///
/// Notes
/// -----
/// • Non-ASCII bytes (>0x7F) are passed through unchanged
/// • Digits, punctuation, whitespace are unchanged
/// • Only A-Z (0x41-0x5A) are converted to a-z (0x61-0x7A)
/// ------------------------------------------------------------
pub fn normalize_payload(payload: &[u8]) -> Vec<u8> {
    payload.iter().map(|&b| normalize_byte(b)).collect()
}

/// ------------------------------------------------------------
/// normalize_payloads
///
/// Apply normalisation to an entire dataset of payloads.
///
/// Parameters
/// ----------
/// payloads : Vec<Vec<u8>> — raw payload dataset
///
/// Returns
/// -------
/// Vec<Vec<u8>> — normalised payload dataset
///
/// Notes
/// -----
/// Consumes the input vector. Each payload is normalised
/// independently. Empty payloads are preserved (not filtered).
/// ------------------------------------------------------------
pub fn normalize_payloads(payloads: Vec<Vec<u8>>) -> Vec<Vec<u8>> {
    payloads
        .into_iter()
        .map(|p| normalize_payload(&p))
        .collect()
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uppercase_converted() {
        let input = b"USER admin".to_vec();
        let result = normalize_payload(&input);
        assert_eq!(result, b"user admin".to_vec());
    }

    #[test]
    fn test_already_lowercase_unchanged() {
        let input = b"user admin".to_vec();
        let result = normalize_payload(&input);
        assert_eq!(result, b"user admin".to_vec());
    }

    #[test]
    fn test_mixed_case() {
        let input = b"PASS Password123".to_vec();
        let result = normalize_payload(&input);
        assert_eq!(result, b"pass password123".to_vec());
    }

    #[test]
    fn test_digits_unchanged() {
        let input = b"STOR 1234abcd".to_vec();
        let result = normalize_payload(&input);
        assert_eq!(result, b"stor 1234abcd".to_vec());
    }

    #[test]
    fn test_binary_bytes_unchanged() {
        let input = vec![0x55, 0x53, 0x45, 0x52, 0xFF, 0x80];
        let result = normalize_payload(&input);
        // USER → user, 0xFF and 0x80 unchanged
        assert_eq!(result, vec![0x75, 0x73, 0x65, 0x72, 0xFF, 0x80]);
    }

    #[test]
    fn test_ftp_commands() {
        let cases = vec![
            (b"STOR file.txt".to_vec(), b"stor file.txt".to_vec()),
            (b"RETR file.txt".to_vec(), b"retr file.txt".to_vec()),
            (b"SIZE /path".to_vec(),    b"size /path".to_vec()),
            (b"MDTM /path".to_vec(),    b"mdtm /path".to_vec()),
            (b"TYPE I".to_vec(),        b"type i".to_vec()),
            (b"PASV".to_vec(),          b"pasv".to_vec()),
            (b"QUIT".to_vec(),          b"quit".to_vec()),
        ];
        for (input, expected) in cases {
            assert_eq!(normalize_payload(&input), expected);
        }
    }

    #[test]
    fn test_http_payload_preserved() {
        let input = b"GET /index.html HTTP/1.1\r\nHost: example.com".to_vec();
        let result = normalize_payload(&input);
        assert_eq!(result, b"get /index.html http/1.1\r\nhost: example.com".to_vec());
    }

    #[test]
    fn test_normalize_payloads_batch() {
        let payloads = vec![
            b"USER admin".to_vec(),
            b"PASS 1234".to_vec(),
            b"already lower".to_vec(),
        ];
        let result = normalize_payloads(payloads);
        assert_eq!(result[0], b"user admin".to_vec());
        assert_eq!(result[1], b"pass 1234".to_vec());
        assert_eq!(result[2], b"already lower".to_vec());
    }
}
