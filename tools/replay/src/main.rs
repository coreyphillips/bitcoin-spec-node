//! bsn-replay: replays block corpus scenarios (conformance/CORPUS.md, format version 1) through
//! any harness that speaks conformance/PROTOCOL.md, following CORPUS.md section 4 exactly.
//!
//! It does not use the node's consensus code: it only maps events to requests and compares the
//! harness's answers with the recorded checkpoints.
//!
//! Usage: bsn-replay --impl "<harness command>" [--no-shortcut] [--verbose] FILE.jsonl.gz...

use serde_json::{json, Map, Value};
use sha2::Digest;
use std::collections::BTreeSet;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::time::Instant;

struct Harness {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
}

impl Harness {
    fn start(command: &str) -> Harness {
        let mut child = Command::new("sh").arg("-c").arg(command).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().expect("start harness");
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Harness { child, stdin, stdout, next_id: 1 }
    }

    fn request(&mut self, mut request: Map<String, Value>) -> Map<String, Value> {
        let id = self.next_id;
        self.next_id += 1;
        request.insert("id".into(), json!(id));
        let line = Value::Object(request).to_string();
        self.stdin.write_all(line.as_bytes()).expect("write request");
        self.stdin.write_all(b"\n").expect("write request");
        self.stdin.flush().expect("flush request");
        let mut response = String::new();
        if self.stdout.read_line(&mut response).expect("read response") == 0 {
            panic!("harness closed its output");
        }
        match serde_json::from_str::<Value>(&response) {
            Ok(Value::Object(map)) => {
                if map.get("id") != Some(&json!(id)) {
                    panic!("response id mismatch: {response}");
                }
                map
            }
            _ => panic!("malformed response: {response}"),
        }
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn obj(pairs: Vec<(&str, Value)>) -> Map<String, Value> {
    let mut map = Map::new();
    for (key, value) in pairs {
        map.insert(key.to_string(), value);
    }
    map
}

#[derive(Default)]
struct Report {
    events: usize,
    blocks: usize,
    normative: usize,
    normative_failed: usize,
    non_normative: usize,
    non_normative_differ: usize,
    tips_checked: usize,
    tips_failed: usize,
    utxo_checked: usize,
    utxo_failed: usize,
    harness_errors: usize,
    restarts_replayed: usize,
    restarts_skipped: usize,
    failures: Vec<String>,
    results: std::collections::BTreeMap<String, usize>,
}

fn load_block_hex(event: &Map<String, Value>, dir: &Path) -> String {
    if let Some(hex) = event.get("hex").and_then(|v| v.as_str()) {
        return hex.to_string();
    }
    let blob = event.get("blob").and_then(|v| v.as_str()).expect("block event without hex or blob");
    let path = dir.join(blob);
    let file = std::fs::File::open(&path).unwrap_or_else(|e| panic!("open blob {}: {e}", path.display()));
    let mut raw = Vec::new();
    flate2::read::GzDecoder::new(file).read_to_end(&mut raw).expect("decompress blob");
    if let Some(expected) = event.get("sha256").and_then(|v| v.as_str()) {
        let digest = sha2::Sha256::digest(&raw);
        let actual: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(actual, expected, "blob sha256 mismatch for {}", path.display());
    }
    raw.iter().map(|b| format!("{b:02x}")).collect()
}

fn tip_set(value: &Value) -> BTreeSet<(String, i64, String)> {
    value
        .as_array()
        .map(|list| {
            list.iter()
                .map(|t| (t["hash"].as_str().unwrap_or("").to_string(), t["height"].as_i64().unwrap_or(-1), t["status"].as_str().unwrap_or("").to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn replay(path: &Path, command: &str, shortcut: bool, verbose: bool) -> Report {
    let file = std::fs::File::open(path).unwrap_or_else(|e| panic!("open {}: {e}", path.display()));
    let reader = BufReader::new(flate2::read::GzDecoder::new(file));
    let dir = path.parent().unwrap_or(Path::new(".")).to_path_buf();
    let mut harness = Harness::start(command);
    let mut report = Report::default();
    let mut network = String::from("regtest");
    let mut current_options = json!({});
    // Every block, headers and invalidate request sent since the last reset, for restarts.
    let mut delivered: Vec<Map<String, Value>> = Vec::new();

    for (line_number, line) in reader.lines().enumerate() {
        let line = line.expect("read corpus line");
        if line.trim().is_empty() {
            continue;
        }
        let event: Map<String, Value> = match serde_json::from_str(&line) {
            Ok(Value::Object(map)) => map,
            _ => panic!("{}: line {} is not a JSON object", path.display(), line_number + 1),
        };
        report.events += 1;
        let kind = event.get("type").and_then(|v| v.as_str()).unwrap_or("meta");
        match kind {
            "meta" => {
                assert_eq!(event.get("format").and_then(|v| v.as_str()), Some("bcs-block-corpus"));
                assert_eq!(event.get("format_version").and_then(|v| v.as_i64()), Some(1));
            }
            "reset" => {
                network = event["network"].as_str().unwrap().to_string();
                current_options = event.get("options").cloned().unwrap_or(json!({}));
                delivered.clear();
                let response = harness.request(obj(vec![("op", json!("chain_reset")), ("network", json!(network)), ("options", current_options.clone())]));
                if response.get("ok") != Some(&json!(true)) {
                    report.harness_errors += 1;
                    report.failures.push(format!("reset failed: {}", Value::Object(response)));
                } else if response.get("genesis") != event.get("genesis") {
                    report.failures.push(format!("genesis mismatch: {:?} vs {:?}", response.get("genesis"), event.get("genesis")));
                }
            }
            "block" => {
                report.blocks += 1;
                let mut request = obj(vec![("op", json!("chain_process_block")), ("block", json!(load_block_hex(&event, &dir))), ("now", event["now"].clone())]);
                if let Some(via) = event.get("via") {
                    request.insert("via".into(), via.clone());
                }
                if let Some(requested) = event.get("requested") {
                    request.insert("requested".into(), requested.clone());
                }
                let response = harness.request(request.clone());
                if response.get("ok") != Some(&json!(true)) {
                    report.harness_errors += 1;
                    report.failures.push(format!("block {} error: {}", event.get("hash").and_then(|v| v.as_str()).unwrap_or("?"), Value::Object(response.clone())));
                }
                let key = format!("block:{}{}", response.get("result").and_then(|v| v.as_str()).unwrap_or("error"), response.get("reason").and_then(|v| v.as_str()).map(|r| format!(":{r}")).unwrap_or_default());
                *report.results.entry(key).or_default() += 1;
                delivered.push(request);
            }
            "headers" => {
                let mut request = obj(vec![("op", json!("chain_process_headers")), ("headers", event["headers"].clone()), ("now", event["now"].clone())]);
                if let Some(via) = event.get("via") {
                    request.insert("via".into(), via.clone());
                }
                let response = harness.request(request.clone());
                if response.get("ok") != Some(&json!(true)) {
                    report.harness_errors += 1;
                    report.failures.push(format!("headers error: {}", Value::Object(response.clone())));
                }
                let key = format!("headers:{}{}", response.get("result").and_then(|v| v.as_str()).unwrap_or("error"), response.get("reason").and_then(|v| v.as_str()).map(|r| format!(":{r}")).unwrap_or_default());
                *report.results.entry(key).or_default() += 1;
                delivered.push(request);
            }
            "invalidate" => {
                let mut request = obj(vec![("op", json!("chain_invalidate")), ("hash", event["hash"].clone())]);
                if let Some(now) = event.get("now") {
                    request.insert("now".into(), now.clone());
                }
                let response = harness.request(request.clone());
                if response.get("ok") != Some(&json!(true)) {
                    report.harness_errors += 1;
                    report.failures.push(format!("invalidate error: {}", Value::Object(response.clone())));
                }
                delivered.push(request);
            }
            "restart" => {
                let options = event.get("options").cloned().unwrap_or(json!({}));
                if shortcut && options == current_options {
                    report.restarts_skipped += 1;
                    continue;
                }
                report.restarts_replayed += 1;
                current_options = options;
                let response = harness.request(obj(vec![("op", json!("chain_reset")), ("network", json!(network)), ("options", current_options.clone())]));
                if response.get("ok") != Some(&json!(true)) {
                    report.harness_errors += 1;
                    report.failures.push(format!("restart reset failed: {}", Value::Object(response)));
                }
                for request in delivered.clone() {
                    let response = harness.request(request);
                    if response.get("ok") != Some(&json!(true)) {
                        report.harness_errors += 1;
                    }
                }
            }
            "check" => {
                let n = event.get("n").and_then(|v| v.as_i64()).unwrap_or(0);
                let label = event.get("label").and_then(|v| v.as_str()).unwrap_or("");
                let normative = event.get("normative").and_then(|v| v.as_bool()).unwrap_or(true);
                let response = harness.request(obj(vec![("op", json!("chain_tip"))]));
                let tip_ok = response.get("tip") == event.get("tip") && response.get("height") == event.get("height");
                if normative {
                    report.normative += 1;
                    if !tip_ok {
                        report.normative_failed += 1;
                        report.failures.push(format!(
                            "check n={n} [{label}] level 0: expected {} @{}, got {} @{}",
                            event["tip"], event["height"], response.get("tip").unwrap_or(&Value::Null), response.get("height").unwrap_or(&Value::Null)
                        ));
                    }
                } else {
                    report.non_normative += 1;
                    if !tip_ok {
                        report.non_normative_differ += 1;
                    }
                }
                if let Some(expected_tips) = event.get("tips") {
                    report.tips_checked += 1;
                    let response = harness.request(obj(vec![("op", json!("chain_tips"))]));
                    let expected = tip_set(expected_tips);
                    let got = tip_set(response.get("tips").unwrap_or(&Value::Null));
                    if expected != got {
                        report.tips_failed += 1;
                        if verbose {
                            let missing: Vec<_> = expected.difference(&got).collect();
                            let extra: Vec<_> = got.difference(&expected).collect();
                            report.failures.push(format!("check n={n} [{label}] level 1 tips: missing {missing:?} extra {extra:?}"));
                        }
                    }
                }
                if let Some(expected_utxo) = event.get("utxo") {
                    report.utxo_checked += 1;
                    let response = harness.request(obj(vec![("op", json!("utxo_hash"))]));
                    if response.get("hash_serialized_3") != expected_utxo.get("hash_serialized_3") || response.get("txouts") != expected_utxo.get("txouts") {
                        report.utxo_failed += 1;
                        report.failures.push(format!(
                            "check n={n} [{label}] level 2 utxo: expected {} / {}, got {} / {}",
                            expected_utxo["hash_serialized_3"],
                            expected_utxo["txouts"],
                            response.get("hash_serialized_3").unwrap_or(&Value::Null),
                            response.get("txouts").unwrap_or(&Value::Null)
                        ));
                    }
                }
            }
            other => panic!("{}: unknown event type {other}", path.display()),
        }
    }
    report
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut command = None;
    let mut shortcut = true;
    let mut verbose = false;
    let mut files: Vec<PathBuf> = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--impl" => {
                i += 1;
                command = Some(args[i].clone());
            }
            "--no-shortcut" => shortcut = false,
            "--verbose" => verbose = true,
            other => files.push(PathBuf::from(other)),
        }
        i += 1;
    }
    let command = command.unwrap_or_else(|| {
        eprintln!("usage: bsn-replay --impl \"<harness command>\" [--no-shortcut] [--verbose] FILE.jsonl.gz...");
        std::process::exit(2);
    });
    println!(
        "{:<36} {:>7} {:>6} {:>9} {:>6} {:>9} {:>11} {:>11} {:>7} {:>7}",
        "scenario", "events", "blocks", "level0", "failed", "non-norm", "level1", "level2", "errors", "time"
    );
    let mut total_failed = 0;
    let mut totals = (0usize, 0usize, 0usize, 0usize, 0usize, 0usize);
    let mut all_failures = Vec::new();
    for file in &files {
        let started = Instant::now();
        let report = replay(file, &command, shortcut, verbose);
        let name = file.file_name().unwrap().to_string_lossy().trim_end_matches(".jsonl.gz").to_string();
        println!(
            "{:<36} {:>7} {:>6} {:>9} {:>6} {:>9} {:>11} {:>11} {:>7} {:>6.1}s",
            name,
            report.events,
            report.blocks,
            format!("{}/{}", report.normative - report.normative_failed, report.normative),
            report.normative_failed,
            format!("{}/{}", report.non_normative - report.non_normative_differ, report.non_normative),
            format!("{}/{}", report.tips_checked - report.tips_failed, report.tips_checked),
            format!("{}/{}", report.utxo_checked - report.utxo_failed, report.utxo_checked),
            report.harness_errors,
            started.elapsed().as_secs_f64()
        );
        total_failed += report.normative_failed + report.harness_errors;
        totals.0 += report.normative;
        totals.1 += report.normative_failed;
        totals.2 += report.tips_checked;
        totals.3 += report.tips_failed;
        totals.4 += report.utxo_checked;
        totals.5 += report.utxo_failed;
        if verbose {
            println!("    restarts replayed {}, skipped {}; outcomes {:?}", report.restarts_replayed, report.restarts_skipped, report.results);
        }
        for failure in report.failures.iter().take(if verbose { usize::MAX } else { 5 }) {
            all_failures.push(format!("{name}: {failure}"));
        }
    }
    println!(
        "TOTAL level 0: {}/{} normative checks pass; level 1: {}/{}; level 2: {}/{}",
        totals.0 - totals.1,
        totals.0,
        totals.2 - totals.3,
        totals.2,
        totals.4 - totals.5,
        totals.4
    );
    for failure in &all_failures {
        println!("  {failure}");
    }
    println!("RESULT: {}", if total_failed == 0 { "PASS (level 0)" } else { "FAIL" });
    std::process::exit(if total_failed == 0 { 0 } else { 1 });
}
