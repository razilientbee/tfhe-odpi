//src/bin/benchmark.rs

use std::time::{Duration, Instant};

use rayon::ThreadPoolBuilder;
use tfhe::boolean::prelude::*;
use tfhe_odpi::rule_engine::LogicOp;

//Project modules
use tfhe_odpi::payload_processor::process_payloads;
use tfhe_odpi::rules::EncryptedRules;

#[derive(Clone)]

struct BenchmarkConfig {
	warmup_runs: usize,
	measured_runs: usize,
	max_packets: Option<usize>,
	rayon_threads: usize,
}

impl Default for BenchmarkConfig {
	fn default() -> Self {
		Self {
			warmup_runs: 1,
			measured_runs: 3,
			max_packets: None, //Use all packets in payloads.txt
			rayon_threads: std::thread::available_parallelism()
				.map(|n| n.get())
				.unwrap_or(1),
		}
	}
}



//Next function
fn setup_tfhe() -> (ClientKey, ServerKey) {
	let params = tfhe::boolean::parameters::DEFAULT_PARAMETERS;
	let (ck, sk) = gen_keys();
	(ck, sk)
}


fn warmup(
	ck: &ClientKey,
	sk: &ServerKey,
	encrypted_rules: &EncryptedRules,
	cfg: &BenchmarkConfig,
) {
	let payload_path = "data/payloads3.txt";

	for _ in 0..cfg.warmup_runs {
		let _ =process_payloads(
			ck,
			sk,
			payload_path,
			encrypted_rules,
			LogicOp::Or,
		
		);
	}
}

fn measured_run(
	ck: &ClientKey,
	sk: &ServerKey,
	encrypted_rules: &EncryptedRules,
	cfg: &BenchmarkConfig,
) -> Duration {
	let payload_path = "data/payload3.txt";
	let start = Instant::now();

	let _ =process_payloads(
		ck,
		sk,
		payload_path,
		encrypted_rules,
		LogicOp::Or,
	
	);

	start.elapsed()
}



fn report(cfg: &BenchmarkConfig, times: &[Duration]) {
	let ms: Vec<f64> = times
		.iter()
		.map(|t| t.as_secs_f64() * 1e3)
		.collect();

	let mean = ms.iter().sum::<f64>() / ms.len() as f64;
	let min = ms.iter().cloned().fold(f64::INFINITY, f64::min);
	let max = ms.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

	
	println!();
	println!("-------------------------------------");
	println!(" ODPI (TFHE-rs Boolean) Benchmark");
	println!("-------------------------------------");
	println!("Rayon threads       : {}", cfg.rayon_threads);
	println!("Packet limit        : {:?}", cfg.max_packets);
	println!("Warmup runs         : {}", cfg.measured_runs);
	println!("-------------------------------------");
	println!("Mean time (ms)      : {:.2}", mean);
	println!("Min time (ms)       : {:.2}", min);
	println!("Max time (ms)       : {:.2}", max);
	println!("-------------------------------------");
	println!();
}

fn run_benchmark(cfg: BenchmarkConfig) {
	ThreadPoolBuilder::new()
		.num_threads(cfg.rayon_threads)
		.build_global()
		.expect("Failed to initialize Rayon thread pool");

	let (ck,sk) = setup_tfhe();

	//Encrypt rule once
	let encrypted_rules = EncryptedRules::new(&ck);

	//Warmup phase

	warmup(&ck, &sk, &encrypted_rules, &cfg);

	let mut times = Vec::new();
	for _ in 0..cfg.measured_runs {
		let t = measured_run(&ck, &sk, &encrypted_rules, &cfg);
		times.push(t);
	}
	
	report(&cfg, &times);

}


fn main() {
	println!("Current working directly: {:?}", std::env::current_dir().unwrap());

	let cfg = BenchmarkConfig::default();
	run_benchmark(cfg);
}

