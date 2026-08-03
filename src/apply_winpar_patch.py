#!/usr/bin/env python3
import sys

path = "payload_processor.rs"   # adjust if you run this from elsewhere

with open(path, "r") as f:
    content = f.read()

old = '''                let total_windows        = payload.len() - window_len + 1;
                total_windows_all       += total_windows;
                let mut group_accumulated = server_key.trivial_encrypt(false);

                for i in 0..total_windows {
                    let window = &payload[i..i + window_len];
                    if !group.bloom.might_contain(window) { continue; }
                    total_candidates_all += 1;
                    let enc_window = &enc_payload[i..i + window_len];
                    let enc_result = encrypted_substring_match(
                        server_key, enc_window, &group.rules,
                    );
                    group_accumulated = server_key.or(&group_accumulated, &enc_result);
                }'''

new = '''                let total_windows  = payload.len() - window_len + 1;
                total_windows_all += total_windows;

                // Sequential prefilter: cheap, plaintext-only.
                let candidate_indices: Vec<usize> = (0..total_windows)
                    .filter(|&i| group.bloom.might_contain(&payload[i..i + window_len]))
                    .collect();
                total_candidates_all += candidate_indices.len();

                // Parallel FHE evaluation + OR-reduction over candidates.
                let group_accumulated = candidate_indices
                    .par_iter()
                    .map(|&i| {
                        let enc_window = &enc_payload[i..i + window_len];
                        encrypted_substring_match(server_key, enc_window, &group.rules)
                    })
                    .reduce(
                        || server_key.trivial_encrypt(false),
                        |a, b| server_key.or(&a, &b),
                    );'''

count = content.count(old)
if count != 1:
    print(f"ERROR: expected exactly 1 match of the target block, found {count}.")
    print("File NOT modified.")
    sys.exit(1)

content = content.replace(old, new)

with open(path, "w") as f:
    f.write(content)

print("Patched successfully: payload_processor.rs updated in place.")
