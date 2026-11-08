//! bitcoin-spec-node: a Bitcoin full node built from the specification package.
//!
//! Subcommands:
//! - `harness`: the conformance protocol on standard input and output (conformance/PROTOCOL.md);
//! - `run`: a persistent full node that synchronizes from the peers given with `--connect`.

mod harness;

fn usage() -> ! {
    eprintln!("usage: bitcoin-spec-node harness");
    eprintln!("       bitcoin-spec-node run --network <main|testnet3|testnet4|signet|regtest> --datadir <dir> --connect <host:port> [--connect ...] [--stop-at <hash>] [--utxo-hash-at <h1,h2,...>]");
    std::process::exit(2);
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
        _ => usage(),
    }
}
