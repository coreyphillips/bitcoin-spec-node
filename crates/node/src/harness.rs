//! `bitcoin-spec-node harness`: the JSON-lines conformance protocol (conformance/PROTOCOL.md).
//!
//! Chain operations use the same `ChainState` code as the node, with an in-memory store.

use consensus::block_rules::{block_merkle_root, check_witness_malleation, is_block_mutated};
use consensus::chain::{headers_message_acceptable, BlockOutcome, ChainState, HeaderError, MemoryStore};
use consensus::crypto::schnorr_verify;
use consensus::hashes::sha256;
use consensus::interpreter::{ExecData, ScriptFlags, SigVersion, TxChecker, FLAG_NAMES};
use consensus::params::{try_network_params, Network, NetworkOptions};
use consensus::serialize::write_var_bytes;
use consensus::sighash::{signature_hash, signature_hash_schnorr, PrecomputedTx};
use consensus::tx::{deserialize_block_data, deserialize_transaction, deserialize_transaction_info, BlockHeader, Transaction, TxOut};
use consensus::tx_rules::check_transaction_sized;
use consensus::util::{hash_from_display, hash_to_display, hex_decode, hex_encode, FailureKind, Hash256};
use consensus::verify::{control_block_size_valid, tapleaf_hash, verify_script, verify_taproot_commitment, TAPROOT_LEAF_MASK};
use serde_json::{json, Map, Value};
use std::io::{BufRead, Write};
use std::sync::Arc;

const OPS: [&str; 14] = [
    "info",
    "script_verify",
    "tx_check",
    "sighash_legacy",
    "sighash_taproot",
    "taproot_commitment_verify",
    "schnorr_verify",
    "chain_reset",
    "chain_process_block",
    "chain_process_headers",
    "chain_invalidate",
    "chain_tip",
    "chain_tips",
    "utxo_hash",
];

/// A protocol-level failure (`ok: false`).
pub(crate) struct OpError {
    code: &'static str,
    message: String,
}

fn bad_request(message: impl Into<String>) -> OpError {
    OpError { code: "bad_request", message: message.into() }
}

type OpResult = Result<Map<String, Value>, OpError>;

fn field<'a>(request: &'a Map<String, Value>, name: &str) -> Result<&'a Value, OpError> {
    request.get(name).ok_or_else(|| bad_request(format!("missing field {name}")))
}

fn hex_field(request: &Map<String, Value>, name: &str) -> Result<Vec<u8>, OpError> {
    let text = field(request, name)?.as_str().ok_or_else(|| bad_request(format!("{name} is not a string")))?;
    hex_decode(text).ok_or_else(|| bad_request(format!("{name} is not hex")))
}

fn int_field(request: &Map<String, Value>, name: &str) -> Result<i64, OpError> {
    field(request, name)?.as_i64().ok_or_else(|| bad_request(format!("{name} is not an integer")))
}

fn hash_field(request: &Map<String, Value>, name: &str) -> Result<Hash256, OpError> {
    let text = field(request, name)?.as_str().ok_or_else(|| bad_request(format!("{name} is not a string")))?;
    hash_from_display(text).ok_or_else(|| bad_request(format!("{name} is not a 32-byte hash")))
}

fn parse_tx(request: &Map<String, Value>) -> Result<Transaction, OpError> {
    let bytes = hex_field(request, "tx")?;
    deserialize_transaction(&bytes).map_err(|e| bad_request(format!("tx does not decode: {}", e.0)))
}

fn parse_spent_outputs(request: &Map<String, Value>) -> Result<Vec<TxOut>, OpError> {
    let list = field(request, "spent_outputs")?.as_array().ok_or_else(|| bad_request("spent_outputs is not an array"))?;
    let mut outputs = Vec::with_capacity(list.len());
    for item in list {
        let object = item.as_object().ok_or_else(|| bad_request("spent output is not an object"))?;
        outputs.push(TxOut { value: int_field(object, "amount")?, script_pubkey: hex_field(object, "script_pubkey")? });
    }
    Ok(outputs)
}

fn parse_flags(request: &Map<String, Value>) -> Result<ScriptFlags, OpError> {
    let list = field(request, "flags")?.as_array().ok_or_else(|| bad_request("flags is not an array"))?;
    let mut flags = 0;
    for item in list {
        let name = item.as_str().ok_or_else(|| bad_request("flag is not a string"))?;
        let (_, bit) = FLAG_NAMES.iter().find(|(n, _)| *n == name).ok_or_else(|| bad_request(format!("unknown flag {name}")))?;
        flags |= bit;
    }
    Ok(flags)
}

fn result(pairs: Vec<(&str, Value)>) -> OpResult {
    let mut map = Map::new();
    for (key, value) in pairs {
        map.insert(key.to_string(), value);
    }
    Ok(map)
}

pub struct Harness {
    chain: Option<ChainState<MemoryStore>>,
}

impl Harness {
    pub fn new() -> Harness {
        Harness { chain: None }
    }

    fn chain(&mut self) -> Result<&mut ChainState<MemoryStore>, OpError> {
        if self.chain.is_none() {
            self.reset(Network::Regtest, NetworkOptions::default())?;
        }
        Ok(self.chain.as_mut().unwrap())
    }

    fn reset(&mut self, network: Network, options: NetworkOptions) -> Result<(), OpError> {
        let params = try_network_params(network, &options).map_err(bad_request)?;
        let genesis = params.consensus.genesis_hash;
        self.chain = Some(ChainState::new(params, MemoryStore::new(genesis)));
        Ok(())
    }

    fn tip_fields(&mut self) -> Result<Vec<(&'static str, Value)>, OpError> {
        let chain = self.chain()?;
        let tip = chain.tip();
        Ok(vec![("tip", json!(hash_to_display(&tip.hash))), ("height", json!(tip.height))])
    }

    pub fn handle(&mut self, op: &str, request: &Map<String, Value>) -> OpResult {
        match op {
            "info" => result(vec![
                ("name", json!("bitcoin-spec-node")),
                ("version", json!(env!("CARGO_PKG_VERSION"))),
                ("spec_version", json!(consensus::SPEC_VERSION)),
                ("ops", json!(OPS.to_vec())),
            ]),
            "script_verify" => {
                let tx = parse_tx(request)?;
                let index = int_field(request, "index")?;
                let spent_outputs = parse_spent_outputs(request)?;
                let flags = parse_flags(request)?;
                if index < 0 || index as usize >= tx.inputs.len() {
                    return Err(bad_request("index out of range"));
                }
                if spent_outputs.len() != tx.inputs.len() {
                    return Err(bad_request("spent_outputs must have one entry per input"));
                }
                let index = index as usize;
                let precomputed = PrecomputedTx::new(&tx, &spent_outputs);
                let checker = TxChecker { tx: &tx, input_index: index, amount: spent_outputs[index].value, spent_outputs: &spent_outputs, precomputed: &precomputed };
                let input = &tx.inputs[index];
                match verify_script(&input.script_sig, &spent_outputs[index].script_pubkey, &input.witness, flags, &checker) {
                    Ok(()) => result(vec![("valid", json!(true)), ("script_error", json!("OK"))]),
                    Err(error) => result(vec![("valid", json!(false)), ("script_error", json!(error.name()))]),
                }
            }
            "tx_check" => {
                let bytes = hex_field(request, "tx")?;
                match deserialize_transaction_info(&bytes) {
                    Err(_) => result(vec![("valid", json!(false)), ("reason", json!("tx-decode"))]),
                    Ok((tx, info)) => match check_transaction_sized(&tx, info.stripped_size) {
                        Ok(()) => result(vec![("valid", json!(true))]),
                        Err(reason) => result(vec![("valid", json!(false)), ("reason", json!(reason))]),
                    },
                }
            }
            "sighash_legacy" => {
                let tx = parse_tx(request)?;
                let script_code = hex_field(request, "script_code")?;
                let index = int_field(request, "index")?;
                let hash_type = int_field(request, "hash_type")?;
                if index < 0 || index as usize >= tx.inputs.len() {
                    return Err(bad_request("index out of range"));
                }
                if hash_type < i32::MIN as i64 || hash_type > u32::MAX as i64 {
                    return Err(bad_request("hash_type out of range"));
                }
                let precomputed = PrecomputedTx::new(&tx, &[]);
                let hash = signature_hash(&script_code, &tx, index as usize, hash_type as i32, 0, SigVersion::Base, &precomputed);
                result(vec![("sighash", json!(hex_encode(&hash)))])
            }
            "sighash_taproot" => {
                let tx = parse_tx(request)?;
                let index = int_field(request, "index")?;
                let spent_outputs = parse_spent_outputs(request)?;
                let hash_type = int_field(request, "hash_type")?;
                if index < 0 || index as usize >= tx.inputs.len() {
                    return Err(bad_request("index out of range"));
                }
                if spent_outputs.len() != tx.inputs.len() {
                    return Err(bad_request("spent_outputs must have one entry per input"));
                }
                if !(0..=255).contains(&hash_type) {
                    return Err(bad_request("hash_type out of range"));
                }
                let mut execdata = ExecData { codeseparator_pos: 0xffff_ffff, ..ExecData::default() };
                if request.contains_key("annex") && !request["annex"].is_null() {
                    let annex = hex_field(request, "annex")?;
                    let mut serialized = Vec::new();
                    write_var_bytes(&mut serialized, &annex);
                    execdata.annex_hash = Some(sha256(&serialized));
                }
                let mut sigversion = SigVersion::Taproot;
                if request.contains_key("leaf_hash") && !request["leaf_hash"].is_null() {
                    let leaf = hex_field(request, "leaf_hash")?;
                    let leaf: Hash256 = leaf.try_into().map_err(|_| bad_request("leaf_hash must be 32 bytes"))?;
                    execdata.tapleaf_hash = Some(leaf);
                    sigversion = SigVersion::Tapscript;
                }
                if request.contains_key("codesep_pos") && !request["codesep_pos"].is_null() {
                    let position = int_field(request, "codesep_pos")?;
                    if !(0..=u32::MAX as i64).contains(&position) {
                        return Err(bad_request("codesep_pos out of range"));
                    }
                    execdata.codeseparator_pos = position as u32;
                }
                let precomputed = PrecomputedTx::new(&tx, &spent_outputs);
                match signature_hash_schnorr(&execdata, &tx, index as usize, hash_type as u8, sigversion, &spent_outputs, &precomputed) {
                    Some(hash) => result(vec![("valid", json!(true)), ("sighash", json!(hex_encode(&hash)))]),
                    None => result(vec![("valid", json!(false))]),
                }
            }
            "taproot_commitment_verify" => {
                let control = hex_field(request, "control_block")?;
                let script = hex_field(request, "script")?;
                let output_key = hex_field(request, "output_key")?;
                if !control_block_size_valid(&control) || output_key.len() != 32 {
                    return result(vec![("valid", json!(false))]);
                }
                let leaf_hash = tapleaf_hash(control[0] & TAPROOT_LEAF_MASK, &script);
                result(vec![("valid", json!(verify_taproot_commitment(&control, &output_key, &leaf_hash)))])
            }
            "schnorr_verify" => {
                let pubkey = hex_field(request, "pubkey")?;
                let msg = hex_field(request, "msg")?;
                let sig = hex_field(request, "sig")?;
                result(vec![("valid", json!(schnorr_verify(&pubkey, &msg, &sig)))])
            }
            "chain_reset" => {
                let name = field(request, "network")?.as_str().ok_or_else(|| bad_request("network is not a string"))?;
                let network = Network::from_name(name).ok_or_else(|| bad_request(format!("unknown network {name}")))?;
                let options = parse_options(request.get("options"))?;
                self.reset(network, options)?;
                let genesis = self.chain()?.params.consensus.genesis_hash;
                result(vec![("genesis", json!(hash_to_display(&genesis)))])
            }
            "chain_process_block" => self.process_block(request),
            "chain_process_headers" => self.process_headers(request),
            "chain_invalidate" => {
                let hash = hash_field(request, "hash")?;
                let chain = self.chain()?;
                if chain.tree.lookup(&hash).is_none() {
                    return Err(bad_request("unknown block"));
                }
                chain.invalidate_block(&hash);
                result(self.tip_fields()?)
            }
            "chain_tip" => {
                let chain = self.chain()?;
                let tip = chain.tip();
                result(vec![
                    ("tip", json!(hash_to_display(&tip.hash))),
                    ("height", json!(tip.height)),
                    ("chainwork", json!(hex_encode(&tip.chain_work.to_be_bytes()))),
                ])
            }
            "chain_tips" => {
                let chain = self.chain()?;
                let tips: Vec<Value> = chain
                    .chain_tips()
                    .into_iter()
                    .map(|(hash, height, status)| json!({"hash": hash_to_display(&hash), "height": height, "status": status}))
                    .collect();
                result(vec![("tips", Value::Array(tips))])
            }
            "utxo_hash" => {
                let chain = self.chain()?;
                let (hash, count) = chain.utxo_hash().map_err(|e| OpError { code: "internal", message: e.to_string() })?;
                result(vec![("hash_serialized_3", json!(hash_to_display(&hash))), ("txouts", json!(count))])
            }
            other => Err(OpError { code: "unsupported_op", message: format!("unknown op {other}") }),
        }
    }

    fn process_block(&mut self, request: &Map<String, Value>) -> OpResult {
        let bytes = hex_field(request, "block")?;
        let now = int_field(request, "now")?;
        let via = request.get("via").and_then(|v| v.as_str()).unwrap_or("p2p").to_string();
        let requested = request.get("requested").and_then(|v| v.as_bool()).unwrap_or(true);
        let data = match deserialize_block_data(&bytes) {
            Ok(data) => data,
            Err(_) => {
                let mut fields = vec![("result", json!("mutated")), ("reason", json!("block-decode"))];
                fields.extend(self.tip_fields()?);
                return result(fields);
            }
        };
        let chain = self.chain()?;
        if via == "p2p" {
            // Chapter 11 section 11.11: a mutated block from a peer is dropped, recording nothing.
            if let Some(parent) = chain.tree.lookup(&data.block.header.prev_block) {
                let segwit_active = chain.tree.get(parent).height + 1 >= chain.params.consensus.segwit_height;
                if is_block_mutated(&data, segwit_active) {
                    let reason = mutation_reason(&data, segwit_active);
                    let mut fields = vec![("result", json!("mutated")), ("reason", json!(reason))];
                    fields.extend(self.tip_fields()?);
                    return result(fields);
                }
            }
        }
        let requested = via != "p2p" || requested;
        let outcome = chain.process_block(Arc::new(data), now, requested);
        let mut fields = match outcome {
            BlockOutcome::Accepted => vec![("result", json!("accepted"))],
            BlockOutcome::AcceptedHeaderOnly => vec![("result", json!("accepted")), ("reason", json!("unrequested-header-only"))],
            BlockOutcome::Duplicate => vec![("result", json!("duplicate"))],
            BlockOutcome::Orphan => vec![("result", json!("orphan"))],
            BlockOutcome::Rejected(failure) => vec![("result", json!(kind_name(failure.kind))), ("reason", json!(failure.reason))],
        };
        fields.extend(self.tip_fields()?);
        result(fields)
    }

    fn process_headers(&mut self, request: &Map<String, Value>) -> OpResult {
        let list = field(request, "headers")?.as_array().ok_or_else(|| bad_request("headers is not an array"))?;
        let now = int_field(request, "now")?;
        let via = request.get("via").and_then(|v| v.as_str()).unwrap_or("p2p").to_string();
        let mut headers = Vec::with_capacity(list.len());
        for item in list {
            let bytes = hex_decode(item.as_str().ok_or_else(|| bad_request("header is not a string"))?).ok_or_else(|| bad_request("header is not hex"))?;
            let bytes: [u8; 80] = bytes.try_into().map_err(|_| bad_request("header is not 80 bytes"))?;
            headers.push(BlockHeader::deserialize(&bytes));
        }
        let chain = self.chain()?;
        let mut fields: Vec<(&str, Value)> = Vec::new();
        let acceptable = if via == "p2p" { headers_message_acceptable(chain, &headers) } else { Ok(()) };
        match acceptable {
            Err((index, reason)) => {
                if reason == "prev-blk-not-found" {
                    fields.push(("result", json!("orphan")));
                } else {
                    fields.push(("result", json!("invalid")));
                }
                fields.push(("reason", json!(reason)));
                fields.push(("index", json!(index)));
            }
            Ok(()) => match chain.process_headers(&headers, now) {
                Ok(()) => fields.push(("result", json!("accepted"))),
                Err((index, HeaderError::Orphan)) => {
                    fields.push(("result", json!("orphan")));
                    fields.push(("reason", json!("prev-blk-not-found")));
                    fields.push(("index", json!(index)));
                }
                Err((index, HeaderError::Failed(failure))) => {
                    fields.push(("result", json!(kind_name(failure.kind))));
                    fields.push(("reason", json!(failure.reason)));
                    fields.push(("index", json!(index)));
                }
            },
        }
        fields.push(("best_header", json!(hash_to_display(&chain.best_header().hash))));
        result(fields)
    }
}

fn kind_name(kind: FailureKind) -> &'static str {
    match kind {
        FailureKind::Invalid => "invalid",
        FailureKind::Mutated => "mutated",
        FailureKind::Temporary => "temporary",
    }
}

/// A diagnostic reason for a block that `is_block_mutated` rejects.
fn mutation_reason(data: &consensus::tx::BlockData, segwit_active: bool) -> String {
    let (root, tree_mutated) = block_merkle_root(data);
    if root != data.block.header.merkle_root {
        return "bad-txnmrklroot".into();
    }
    if tree_mutated {
        return "bad-txns-duplicate".into();
    }
    let txs = &data.block.transactions;
    if txs.is_empty() || !txs[0].is_coinbase() {
        return "bad-txns-64byte".into();
    }
    match check_witness_malleation(data, segwit_active) {
        Err(failure) => failure.reason,
        Ok(()) => "mutated".into(),
    }
}

fn parse_options(value: Option<&Value>) -> Result<NetworkOptions, OpError> {
    let mut options = NetworkOptions::default();
    let object = match value {
        None | Some(Value::Null) => return Ok(options),
        Some(Value::Object(object)) => object,
        Some(_) => return Err(bad_request("options is not an object")),
    };
    if let Some(heights) = object.get("testactivationheight") {
        let heights = heights.as_object().ok_or_else(|| bad_request("testactivationheight is not an object"))?;
        for (name, height) in heights {
            let height = height.as_i64().ok_or_else(|| bad_request("activation height is not an integer"))?;
            options.activation_heights.push((name.clone(), height as i32));
        }
    }
    if let Some(tests) = object.get("test") {
        let tests = tests.as_array().ok_or_else(|| bad_request("test is not an array"))?;
        for test in tests {
            match test.as_str() {
                Some("bip94") => options.enforce_bip94 = true,
                Some(other) => return Err(bad_request(format!("unknown test option {other}"))),
                None => return Err(bad_request("test option is not a string")),
            }
        }
    }
    if let Some(challenge) = object.get("signetchallenge") {
        let text = challenge.as_str().ok_or_else(|| bad_request("signetchallenge is not a string"))?;
        options.signet_challenge = Some(hex_decode(text).ok_or_else(|| bad_request("signetchallenge is not hex"))?);
    }
    Ok(options)
}

/// Runs the harness on standard input and output until end of file.
pub fn run() -> std::io::Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());
    let mut harness = Harness::new();
    let mut line = String::new();
    let mut input = stdin.lock();
    loop {
        line.clear();
        if input.read_line(&mut line)? == 0 {
            break;
        }
        let text = line.trim();
        if text.is_empty() {
            continue;
        }
        let response = respond(&mut harness, text);
        out.write_all(response.as_bytes())?;
        out.write_all(b"\n")?;
        out.flush()?;
    }
    Ok(())
}

fn respond(harness: &mut Harness, text: &str) -> String {
    let parsed: Value = match serde_json::from_str(text) {
        Ok(value) => value,
        Err(e) => return json!({"id": null, "ok": false, "error": "bad_request", "message": format!("not JSON: {e}")}).to_string(),
    };
    let request = match parsed {
        Value::Object(map) => map,
        _ => return json!({"id": null, "ok": false, "error": "bad_request", "message": "not a JSON object"}).to_string(),
    };
    let id = request.get("id").cloned().unwrap_or(Value::Null);
    let op = match request.get("op").and_then(|v| v.as_str()) {
        Some(op) => op.to_string(),
        None => return json!({"id": id, "ok": false, "error": "bad_request", "message": "missing op"}).to_string(),
    };
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| harness.handle(&op, &request)));
    let mut response = Map::new();
    response.insert("id".into(), id);
    match outcome {
        Ok(Ok(fields)) => {
            response.insert("ok".into(), json!(true));
            response.extend(fields);
        }
        Ok(Err(error)) => {
            response.insert("ok".into(), json!(false));
            response.insert("error".into(), json!(error.code));
            response.insert("message".into(), json!(error.message));
        }
        Err(panic) => {
            let message = panic.downcast_ref::<String>().cloned().or_else(|| panic.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default();
            // A panic may leave chain state half-updated; start over on the next chain_reset.
            if op.starts_with("chain_") || op == "utxo_hash" {
                harness.chain = None;
            }
            response.insert("ok".into(), json!(false));
            response.insert("error".into(), json!("internal"));
            response.insert("message".into(), json!(format!("panic: {message}")));
        }
    }
    Value::Object(response).to_string()
}
