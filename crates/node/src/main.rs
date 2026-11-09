//! bitcoin-spec-node: a Bitcoin full node built from the specification package.
//!
//! Subcommands:
//! - `harness`: the conformance protocol on standard input and output (conformance/PROTOCOL.md);
//! - `run`: a persistent full node that synchronizes from the peers given with `--connect`.

mod downloads;
mod harness;
mod net;
mod node;
mod store;

use consensus::params::Network;
use consensus::util::hash_from_display;
use std::io::Write;
use std::sync::Mutex;

static STDOUT_LOCK: Mutex<()> = Mutex::new(());

/// Writes one line to standard output (event lines; nothing else goes there).
pub fn emit(line: &str) {
    let _guard = STDOUT_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let _ = out.write_all(line.as_bytes());
    let _ = out.write_all(b"\n");
    let _ = out.flush();
}

fn usage() -> ! {
    eprintln!("usage: bitcoin-spec-node harness");
    eprintln!(
        "       bitcoin-spec-node run --network <main|testnet3|testnet4|signet|regtest> --datadir <dir> [--connect <host:port> ...] [--max-peers <n>]\n\
         \x20                          [--stop-at <hash>] [--utxo-hash-at <h1,h2,...>] [--options <json>] [--dbcache <MiB>]\n\
         \x20                          [--max-in-flight <n>] [--prune-depth <n>] [--idle-timeout <seconds>]"
    );
    std::process::exit(2);
}

fn raise_file_limit() {
    unsafe {
        let mut limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) == 0 {
            let wanted = 10_240.min(limit.rlim_max);
            if limit.rlim_cur < wanted {
                limit.rlim_cur = wanted;
                libc::setrlimit(libc::RLIMIT_NOFILE, &limit);
            }
        }
    }
}

fn parse_run(args: &[String]) -> node::NodeConfig {
    let mut network = None;
    let mut datadir = None;
    let mut connect = Vec::new();
    let mut stop_at = None;
    let mut utxo_hash_at = Vec::new();
    let mut dbcache_mb = None;
    let mut max_in_flight = 16;
    let mut prune_depth = 2100;
    let mut options = consensus::params::NetworkOptions::default();
    let mut idle_timeout = 300u64;
    let mut max_peers = 8usize;
    let mut i = 0;
    let value = |i: usize| -> String { args.get(i + 1).cloned().unwrap_or_else(|| usage()) };
    while i < args.len() {
        match args[i].as_str() {
            "--network" => network = Some(Network::from_name(&value(i)).unwrap_or_else(|| usage())),
            "--datadir" => datadir = Some(std::path::PathBuf::from(value(i))),
            "--connect" => connect.push(value(i)),
            "--stop-at" => stop_at = Some(hash_from_display(&value(i)).unwrap_or_else(|| usage())),
            "--utxo-hash-at" => {
                for part in value(i).split(',').filter(|p| !p.is_empty()) {
                    utxo_hash_at.push(part.trim().parse::<i32>().unwrap_or_else(|_| usage()));
                }
            }
            "--dbcache" => dbcache_mb = Some(value(i).parse::<usize>().unwrap_or_else(|_| usage())),
            "--max-in-flight" => max_in_flight = value(i).parse::<usize>().unwrap_or_else(|_| usage()).max(1),
            "--prune-depth" => prune_depth = value(i).parse::<i32>().unwrap_or_else(|_| usage()).max(2016),
            "--options" => {
                options = harness::parse_options_json(&value(i)).unwrap_or_else(|e| {
                    eprintln!("invalid --options: {e}");
                    std::process::exit(2);
                })
            }
            "--idle-timeout" => idle_timeout = value(i).parse::<u64>().unwrap_or_else(|_| usage()),
            "--max-peers" => max_peers = value(i).parse::<usize>().unwrap_or_else(|_| usage()).max(1),
            _ => usage(),
        }
        i += 2;
    }
    let network = network.unwrap_or_else(|| usage());
    let datadir = datadir.unwrap_or_else(|| usage());
    if connect.is_empty() && network == Network::Regtest {
        eprintln!("regtest has no DNS seeds: give the peer with --connect");
        std::process::exit(2);
    }
    let default_cache = if network == Network::Main { 12_000 } else { 1_000 };
    node::NodeConfig {
        network,
        datadir,
        connect,
        stop_at,
        utxo_hash_at,
        dbcache_mb: dbcache_mb.unwrap_or(default_cache),
        max_in_flight,
        prune_depth,
        options,
        idle_timeout: std::time::Duration::from_secs(idle_timeout),
        max_peers,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(|s| s.as_str()) {
        Some("harness") => {
            if let Err(e) = harness::run() {
                eprintln!("harness: {e}");
                std::process::exit(1);
            }
        }
        Some("run") => {
            raise_file_limit();
            let config = parse_run(&args[1..]);
            let _ = ctrlc::set_handler(|| node::SHUTDOWN.store(true, std::sync::atomic::Ordering::SeqCst));
            let result = node::Node::new(config).and_then(|n| n.run());
            if let Err(error) = result {
                eprintln!("error: {error}");
                std::process::exit(1);
            }
        }
        Some("bench-flush") => {
            // Diagnostics: bitcoin-spec-node bench-flush <dir> <millions of coins>
            let dir = std::path::PathBuf::from(args.get(1).cloned().unwrap_or_else(|| usage()));
            let millions: usize = args.get(2).and_then(|v| v.parse().ok()).unwrap_or_else(|| usage());
            if let Err(error) = store::bench_flush(&dir, millions) {
                eprintln!("bench-flush: {error}");
                std::process::exit(1);
            }
        }
        _ => usage(),
    }
}
