//! bsn-txgen: builds regtest blocks full of signed transactions (P2PKH, P2WPKH, P2SH-P2WPKH,
//! P2WSH and P2TR key path spends, chains of spends inside a block, OP_RETURN and zero-value
//! outputs) and submits them to a Bitcoin Core node with `submitblock`. Bitcoin Core validates
//! every block, so a chain built this way is a valid chain by Core's own rules, which the node
//! under test must then follow.
//!
//! Usage: bsn-txgen --rpc 127.0.0.1:PORT --blocks N --txs M [--seed S] [--user u --password p]

use consensus::block_rules::compute_merkle_root;
use consensus::hashes::{hash160, sha256, sha256d, tagged_hash};
use consensus::interpreter::SigVersion;
use consensus::pow::check_proof_of_work;
use consensus::script::*;
use consensus::sighash::{signature_hash, signature_hash_schnorr, PrecomputedTx};
use consensus::tx::{Block, BlockHeader, OutPoint, Transaction, TxIn, TxOut};
use consensus::uint::U256;
use consensus::util::{hash_from_display, hash_to_display, hex_encode, Hash256};
use secp256k1::{Keypair, Message, PublicKey, Scalar, SecretKey, SECP256K1};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::net::TcpStream;

struct Rpc {
    address: String,
    auth: String,
}

impl Rpc {
    fn call(&self, method: &str, params: Value) -> Result<Value, String> {
        let body = json!({"jsonrpc": "1.0", "id": 1, "method": method, "params": params}).to_string();
        let mut stream = TcpStream::connect(&self.address).map_err(|e| e.to_string())?;
        let request = format!(
            "POST / HTTP/1.1\r\nHost: {}\r\nAuthorization: Basic {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            self.address,
            self.auth,
            body.len(),
            body
        );
        stream.write_all(request.as_bytes()).map_err(|e| e.to_string())?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).map_err(|e| e.to_string())?;
        let text = String::from_utf8_lossy(&response);
        let json_start = text.find("\r\n\r\n").map(|i| i + 4).ok_or("bad HTTP response")?;
        let reply: Value = serde_json::from_str(&text[json_start..]).map_err(|e| format!("bad JSON: {e}"))?;
        if !reply["error"].is_null() {
            return Err(format!("{method}: {}", reply["error"]));
        }
        Ok(reply["result"].clone())
    }
}

fn base64(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(TABLE[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// xorshift64* generator (deterministic test data).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    P2pkh,
    P2wpkh,
    P2shP2wpkh,
    P2wsh,
    P2tr,
}

const KINDS: [Kind; 5] = [Kind::P2pkh, Kind::P2wpkh, Kind::P2shP2wpkh, Kind::P2wsh, Kind::P2tr];

struct Key {
    secret: SecretKey,
    public: [u8; 33],
    /// Taproot output key (BIP341 key path without a script tree) and its signing key pair.
    tweaked: Keypair,
    output_key: [u8; 32],
}

impl Key {
    fn new(seed: u64, index: u64) -> Key {
        let mut material = seed.to_le_bytes().to_vec();
        material.extend_from_slice(&index.to_le_bytes());
        let secret = SecretKey::from_byte_array(sha256(&material)).expect("valid key");
        let public = PublicKey::from_secret_key(SECP256K1, &secret).serialize();
        let keypair = Keypair::from_secret_key(SECP256K1, &secret);
        let (internal, _) = keypair.x_only_public_key();
        let tweak = Scalar::from_be_bytes(tagged_hash("TapTweak", &internal.serialize())).expect("tweak in range");
        let tweaked = keypair.add_xonly_tweak(SECP256K1, &tweak).expect("tweak");
        let output_key = tweaked.x_only_public_key().0.serialize();
        Key { secret, public, tweaked, output_key }
    }

    fn witness_script(&self) -> Vec<u8> {
        let mut script = push_data(&self.public);
        script.push(OP_CHECKSIG);
        script
    }

    fn script_pubkey(&self, kind: Kind) -> Vec<u8> {
        let hash = hash160(&self.public);
        match kind {
            Kind::P2pkh => {
                let mut s = vec![OP_DUP, OP_HASH160, 20];
                s.extend_from_slice(&hash);
                s.extend_from_slice(&[OP_EQUALVERIFY, OP_CHECKSIG]);
                s
            }
            Kind::P2wpkh => {
                let mut s = vec![OP_0, 20];
                s.extend_from_slice(&hash);
                s
            }
            Kind::P2shP2wpkh => {
                let redeem = self.script_pubkey(Kind::P2wpkh);
                let mut s = vec![OP_HASH160, 20];
                s.extend_from_slice(&hash160(&redeem));
                s.push(OP_EQUAL);
                s
            }
            Kind::P2wsh => {
                let mut s = vec![OP_0, 32];
                s.extend_from_slice(&sha256(&self.witness_script()));
                s
            }
            Kind::P2tr => {
                let mut s = vec![OP_1, 32];
                s.extend_from_slice(&self.output_key);
                s
            }
        }
    }
}

#[derive(Clone)]
struct Utxo {
    outpoint: OutPoint,
    output: TxOut,
    kind: Kind,
    key: usize,
    height: i32,
    coinbase: bool,
}

fn ecdsa_sig(key: &Key, sighash: Hash256) -> Vec<u8> {
    let sig = SECP256K1.sign_ecdsa(Message::from_digest(sighash), &key.secret);
    let mut der = sig.serialize_der().to_vec();
    der.push(1); // SIGHASH_ALL
    der
}

/// Signs every input of `tx`, which spends `spent` (in input order).
fn sign(tx: &mut Transaction, spent: &[Utxo], keys: &[Key]) {
    let spent_outputs: Vec<TxOut> = spent.iter().map(|u| u.output.clone()).collect();
    // Script sigs that do not depend on signatures first (they are part of the txid, not of the
    // segwit signature hashes).
    for (input, utxo) in tx.inputs.iter_mut().zip(spent) {
        if utxo.kind == Kind::P2shP2wpkh {
            input.script_sig = push_data(&keys[utxo.key].script_pubkey(Kind::P2wpkh));
        }
    }
    let precomputed = PrecomputedTx::new(tx, &spent_outputs);
    let mut witnesses = Vec::new();
    let mut script_sigs = Vec::new();
    for (index, utxo) in spent.iter().enumerate() {
        let key = &keys[utxo.key];
        match utxo.kind {
            Kind::P2pkh => {
                let hash = signature_hash(&utxo.output.script_pubkey, tx, index, 1, utxo.output.value, SigVersion::Base, &precomputed);
                let mut script_sig = push_data(&ecdsa_sig(key, hash));
                script_sig.extend_from_slice(&push_data(&key.public));
                script_sigs.push((index, script_sig));
                witnesses.push(Vec::new());
            }
            Kind::P2wpkh | Kind::P2shP2wpkh => {
                let code = key.script_pubkey(Kind::P2pkh);
                let hash = signature_hash(&code, tx, index, 1, utxo.output.value, SigVersion::WitnessV0, &precomputed);
                witnesses.push(vec![ecdsa_sig(key, hash), key.public.to_vec()]);
            }
            Kind::P2wsh => {
                let script = key.witness_script();
                let hash = signature_hash(&script, tx, index, 1, utxo.output.value, SigVersion::WitnessV0, &precomputed);
                witnesses.push(vec![ecdsa_sig(key, hash), script]);
            }
            Kind::P2tr => {
                let execdata = consensus::interpreter::ExecData { codeseparator_pos: 0xffff_ffff, ..Default::default() };
                let hash = signature_hash_schnorr(&execdata, tx, index, 0, SigVersion::Taproot, &spent_outputs, &precomputed).expect("sighash");
                let sig = SECP256K1.sign_schnorr_no_aux_rand(&hash, &key.tweaked);
                witnesses.push(vec![sig.to_byte_array().to_vec()]);
            }
        }
    }
    for (index, script_sig) in script_sigs {
        tx.inputs[index].script_sig = script_sig;
    }
    for (input, witness) in tx.inputs.iter_mut().zip(witnesses) {
        input.witness = witness;
    }
}

struct Generator {
    rpc: Rpc,
    rng: Rng,
    keys: Vec<Key>,
    pool: Vec<Utxo>,
    tip: Hash256,
    height: i32,
    times: Vec<i64>,
    submitted: u64,
    txs: u64,
}

impl Generator {
    fn median_time_past(&self) -> i64 {
        let mut window: Vec<i64> = self.times.iter().rev().take(11).copied().collect();
        window.sort();
        window[window.len() / 2]
    }

    fn subsidy(height: i32) -> i64 {
        let halvings = height / 150;
        if halvings >= 64 {
            0
        } else {
            (50 * 100_000_000i64) >> halvings
        }
    }

    /// Builds, mines and submits a block with up to `tx_count` transactions.
    fn block(&mut self, tx_count: usize) -> Result<(), String> {
        let height = self.height + 1;
        let mut transactions: Vec<Transaction> = Vec::new();
        let mut created: Vec<Utxo> = Vec::new();
        let mut fees = 0i64;
        for _ in 0..tx_count {
            // Pick 1 to 3 spendable coins, sometimes one created earlier in this block.
            let mut spent: Vec<Utxo> = Vec::new();
            let inputs = 1 + self.rng.below(3) as usize;
            for _ in 0..inputs {
                if !created.is_empty() && self.rng.below(4) == 0 {
                    let i = self.rng.below(created.len() as u64) as usize;
                    spent.push(created.swap_remove(i));
                    continue;
                }
                let mut found = None;
                for _ in 0..20 {
                    if self.pool.is_empty() {
                        break;
                    }
                    let i = self.rng.below(self.pool.len() as u64) as usize;
                    let candidate = &self.pool[i];
                    if !candidate.coinbase || height - candidate.height >= 100 {
                        found = Some(self.pool.swap_remove(i));
                        break;
                    }
                }
                if let Some(utxo) = found {
                    spent.push(utxo);
                }
            }
            if spent.is_empty() {
                break;
            }
            let total: i64 = spent.iter().map(|u| u.output.value).sum();
            let fee = 1000.min(total);
            let mut remaining = total - fee;
            let output_count = 1 + self.rng.below(4) as usize;
            let mut outputs = Vec::new();
            let mut kinds = Vec::new();
            for o in 0..output_count {
                let value = if o + 1 == output_count { remaining } else { (remaining as u64 / 2 * (1 + self.rng.below(100)) / 100) as i64 };
                remaining -= value;
                let kind = KINDS[self.rng.below(KINDS.len() as u64) as usize];
                let key = self.rng.below(self.keys.len() as u64) as usize;
                outputs.push(TxOut { value, script_pubkey: self.keys[key].script_pubkey(kind) });
                kinds.push((kind, key));
            }
            if self.rng.below(10) == 0 {
                outputs.push(TxOut { value: 0, script_pubkey: vec![OP_RETURN, 4, 0xde, 0xad, 0xbe, 0xef] });
                kinds.push((Kind::P2pkh, usize::MAX));
            }
            let mut tx = Transaction {
                version: if self.rng.below(2) == 0 { 1 } else { 2 },
                inputs: spent.iter().map(|u| TxIn { prevout: u.outpoint, script_sig: Vec::new(), sequence: 0xffff_fffe, witness: Vec::new() }).collect(),
                outputs,
                lock_time: self.height as u32,
            };
            sign(&mut tx, &spent, &self.keys);
            let txid = tx.txid();
            for (vout, (output, (kind, key))) in tx.outputs.iter().zip(kinds).enumerate() {
                if key == usize::MAX {
                    continue;
                }
                created.push(Utxo { outpoint: OutPoint { txid, vout: vout as u32 }, output: output.clone(), kind, key, height, coinbase: false });
            }
            fees += fee;
            transactions.push(tx);
        }
        // Coinbase with the witness commitment.
        let reward_kind = KINDS[self.rng.below(KINDS.len() as u64) as usize];
        let reward_key = self.rng.below(self.keys.len() as u64) as usize;
        let mut script_sig = push_int(height as i64);
        script_sig.extend_from_slice(&push_data(b"bsn-txgen"));
        let mut coinbase = Transaction {
            version: 1,
            inputs: vec![TxIn { prevout: OutPoint::null(), script_sig, sequence: 0xffff_ffff, witness: vec![vec![0u8; 32]] }],
            outputs: vec![TxOut { value: Self::subsidy(height) + fees, script_pubkey: self.keys[reward_key].script_pubkey(reward_kind) }],
            lock_time: 0,
        };
        let mut wtxids = vec![[0u8; 32]];
        wtxids.extend(transactions.iter().map(|tx| tx.wtxid()));
        let witness_root = compute_merkle_root(wtxids).0;
        let mut data = witness_root.to_vec();
        data.extend_from_slice(&[0u8; 32]);
        let mut commitment = vec![OP_RETURN, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        commitment.extend_from_slice(&sha256d(&data));
        coinbase.outputs.push(TxOut { value: 0, script_pubkey: commitment });
        let coinbase_txid = coinbase.txid();
        let mut txids = vec![coinbase_txid];
        txids.extend(transactions.iter().map(|tx| tx.txid()));
        let merkle_root = compute_merkle_root(txids).0;
        let time = (self.median_time_past() + 1).max(*self.times.last().unwrap());
        let mut header = BlockHeader { version: 0x2000_0000, prev_block: self.tip, merkle_root, time: time as u32, bits: 0x207f_ffff, nonce: 0 };
        let limit = U256::from_be_bytes(&consensus::util::hex_decode("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap());
        while !check_proof_of_work(&header.hash(), header.bits, limit) {
            header.nonce += 1;
        }
        let mut all = vec![coinbase];
        all.extend(transactions);
        let block = Block { header, transactions: all };
        let result = self.rpc.call("submitblock", json!([hex_encode(&block.serialize(true))]))?;
        if !result.is_null() {
            return Err(format!("block {height} rejected by Bitcoin Core: {result}"));
        }
        self.tip = header.hash();
        self.height = height;
        self.times.push(time);
        self.submitted += 1;
        self.txs += block.transactions.len() as u64 - 1;
        self.pool.extend(created);
        self.pool.push(Utxo {
            outpoint: OutPoint { txid: coinbase_txid, vout: 0 },
            output: block.transactions[0].outputs[0].clone(),
            kind: reward_kind,
            key: reward_key,
            height,
            coinbase: true,
        });
        Ok(())
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(|s| s.as_str()) == Some("--bench-sigs") {
        bench_signatures();
        return;
    }
    if args.first().map(|s| s.as_str()) == Some("--bench-download") {
        bench_download(&args[1], args[2].parse().expect("in flight"));
        return;
    }
    let mut rpc_address = String::from("127.0.0.1:30702");
    let mut user = String::from("u");
    let mut password = String::from("p");
    let mut blocks = 100usize;
    let mut txs = 100usize;
    let mut seed = 1u64;
    let mut i = 0;
    while i + 1 < args.len() {
        match args[i].as_str() {
            "--rpc" => rpc_address = args[i + 1].clone(),
            "--user" => user = args[i + 1].clone(),
            "--password" => password = args[i + 1].clone(),
            "--blocks" => blocks = args[i + 1].parse().expect("--blocks"),
            "--txs" => txs = args[i + 1].parse().expect("--txs"),
            "--seed" => seed = args[i + 1].parse().expect("--seed"),
            other => panic!("unknown option {other}"),
        }
        i += 2;
    }
    let rpc = Rpc { address: rpc_address, auth: base64(format!("{user}:{password}").as_bytes()) };
    let info = rpc.call("getblockchaininfo", json!([])).expect("getblockchaininfo");
    let tip_display = info["bestblockhash"].as_str().unwrap().to_string();
    let height = info["blocks"].as_i64().unwrap() as i32;
    // Times of the last 11 blocks, for the median time past.
    let mut times = Vec::new();
    let mut cursor = tip_display.clone();
    for _ in 0..11 {
        let header = rpc.call("getblockheader", json!([cursor])).expect("getblockheader");
        times.push(header["time"].as_i64().unwrap());
        match header["previousblockhash"].as_str() {
            Some(previous) => cursor = previous.to_string(),
            None => break,
        }
    }
    times.reverse();
    let keys: Vec<Key> = (0..64).map(|i| Key::new(seed, i)).collect();
    let mut generator = Generator {
        rpc,
        rng: Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1),
        keys,
        pool: Vec::new(),
        tip: hash_from_display(&tip_display).unwrap(),
        height,
        times,
        submitted: 0,
        txs: 0,
    };
    let started = std::time::Instant::now();
    // Coins to spend: 101 blocks paying to our keys (coinbase maturity is 100).
    for _ in 0..101 {
        generator.block(0).unwrap_or_else(|e| panic!("{e}"));
    }
    for n in 0..blocks {
        generator.block(txs).unwrap_or_else(|e| panic!("{e}"));
        if (n + 1) % 50 == 0 {
            eprintln!("txgen: {} blocks, {} transactions, height {}, {:.0}s", generator.submitted, generator.txs, generator.height, started.elapsed().as_secs_f64());
        }
    }
    println!("{} {}", hash_to_display(&generator.tip), generator.height);
}

/// `bsn-txgen --bench-sigs`: raw libsecp256k1 verification throughput, one thread and all threads.
#[allow(dead_code)]
pub fn bench_signatures() {
    use rayon::prelude::*;
    let keys: Vec<Key> = (0..64).map(|i| Key::new(99, i)).collect();
    let items: Vec<(usize, Hash256, Vec<u8>, Vec<u8>)> = (0..20_000u64)
        .map(|i| {
            let key = (i % 64) as usize;
            let msg = sha256(&i.to_le_bytes());
            let ecdsa = ecdsa_sig(&keys[key], msg);
            let schnorr = SECP256K1.sign_schnorr_no_aux_rand(&msg, &keys[key].tweaked).to_byte_array().to_vec();
            (key, msg, ecdsa, schnorr)
        })
        .collect();
    let started = std::time::Instant::now();
    let ok = items.iter().all(|(key, msg, sig, _)| consensus::crypto::ecdsa_verify(&keys[*key].public, &sig[..sig.len() - 1], msg));
    let one = started.elapsed().as_secs_f64();
    let started = std::time::Instant::now();
    let ok2 = items.par_iter().all(|(key, msg, sig, _)| consensus::crypto::ecdsa_verify(&keys[*key].public, &sig[..sig.len() - 1], msg));
    let all = started.elapsed().as_secs_f64();
    println!("ecdsa: {:.1} us/verify on one thread, {:.0} verifies/s on {} threads ({ok} {ok2})", one * 1e6 / items.len() as f64, items.len() as f64 / all, rayon::current_num_threads());
    let started = std::time::Instant::now();
    let ok = items.iter().all(|(key, msg, _, sig)| consensus::crypto::schnorr_verify(&keys[*key].output_key, msg, sig));
    let one = started.elapsed().as_secs_f64();
    let started = std::time::Instant::now();
    let ok2 = items.par_iter().all(|(key, msg, _, sig)| consensus::crypto::schnorr_verify(&keys[*key].output_key, msg, sig));
    let all = started.elapsed().as_secs_f64();
    println!("schnorr: {:.1} us/verify on one thread, {:.0} verifies/s on {} threads ({ok} {ok2})", one * 1e6 / items.len() as f64, items.len() as f64 / all, rayon::current_num_threads());
}

/// `bsn-txgen --bench-download HOST:PORT IN_FLIGHT`: how fast a node serves its blocks over P2P
/// (headers first, then every block with `in_flight` requests outstanding; nothing is validated).
pub fn bench_download(address: &str, in_flight: usize) {
    use consensus::p2p::*;
    use std::io::{BufReader, Read, Write};
    let magic = [0xfa, 0xbf, 0xb5, 0xda];
    let stream = TcpStream::connect(address).expect("connect");
    stream.set_nodelay(true).unwrap();
    let mut writer = stream.try_clone().unwrap();
    let mut reader = BufReader::with_capacity(4 << 20, stream);
    let mut send = |command: &str, payload: &[u8]| writer.write_all(&encode_message(magic, command, payload)).unwrap();
    let version = VersionMessage { version: PROTOCOL_VERSION, services: NODE_WITNESS, timestamp: 0, nonce: 7, user_agent: b"/bench/".to_vec(), start_height: 0, relay: false };
    send("version", &encode_version(&version));
    let mut read = || -> (String, Vec<u8>) {
        let mut header = [0u8; 24];
        reader.read_exact(&mut header).unwrap();
        let parsed = decode_message_header(&header, magic).unwrap();
        let mut payload = vec![0u8; parsed.length];
        reader.read_exact(&mut payload).unwrap();
        (parsed.command, payload)
    };
    let genesis = consensus::params::network_params(consensus::params::Network::Regtest, &Default::default()).consensus.genesis_hash;
    let mut hashes: Vec<Hash256> = Vec::new();
    let mut last = genesis;
    let started = std::time::Instant::now();
    let mut requested = 0usize;
    let mut received = 0usize;
    let mut bytes = 0usize;
    let mut asked_headers = false;
    loop {
        let (command, payload) = read();
        match command.as_str() {
            "version" => send("verack", &[]),
            "verack" if !asked_headers => {
                asked_headers = true;
                send("getheaders", &encode_getheaders(&[last], &[0u8; 32]));
            }
            "ping" => send("pong", &payload),
            "headers" => {
                let headers = decode_headers(&payload).unwrap();
                for h in &headers {
                    last = h.hash();
                    hashes.push(last);
                }
                if headers.len() == MAX_HEADERS_RESULTS {
                    send("getheaders", &encode_getheaders(&[last], &[0u8; 32]));
                } else {
                    println!("{} headers in {:.2}s", hashes.len(), started.elapsed().as_secs_f64());
                    let items: Vec<(u32, Hash256)> = hashes.iter().take(in_flight).map(|h| (MSG_WITNESS_BLOCK, *h)).collect();
                    requested = items.len();
                    send("getdata", &encode_inv(&items));
                }
            }
            "block" => {
                received += 1;
                bytes += payload.len();
                if requested < hashes.len() {
                    send("getdata", &encode_inv(&[(MSG_WITNESS_BLOCK, hashes[requested])]));
                    requested += 1;
                }
                if received == hashes.len() {
                    let seconds = started.elapsed().as_secs_f64();
                    println!("{received} blocks, {:.0} MB in {seconds:.2}s: {:.0} blocks/s, {:.0} MB/s", bytes as f64 / 1e6, received as f64 / seconds, bytes as f64 / 1e6 / seconds);
                    return;
                }
            }
            _ => {}
        }
    }
}
