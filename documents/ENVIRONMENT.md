# Benchmarking Environment

Recorded for reproducibility of the two-phase parallelization
benchmarking runs (cap50-185 and isolated-category batches).

## Hardware
- vCPUs: 8
- RAM: 7.1 GiB (VirtualBox VM)
- CPU: AMD Ryzen 5 5600H with Radeon Graphics

## Software
- OS: Ubuntu 26.04 LTS (resolute)
- Rust: rustc 1.97.1, cargo 1.97.1
- tfhe-rs: 0.4.4 (Boolean API, `seeder_unix` feature; confirmed as
  the sole resolved version via `cargo tree`)
- rayon: 1.11.0

## How this was captured
    nproc
    free -h
    lscpu | grep "Model name"
    lsb_release -a
    rustc --version && cargo --version
    cargo tree | grep tfhe
    grep -A2 'name = "rayon"' Cargo.lock
