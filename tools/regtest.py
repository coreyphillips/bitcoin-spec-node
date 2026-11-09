#!/usr/bin/env python3
"""Regtest interoperability tests: bitcoin-spec-node against Bitcoin Core v32.1 (black box).

Bitcoin Core runs from ~/bcs-data/bin/bitcoin-32.1/bin with its own datadir under test-data/,
on ports 30000-30999 only. Every scenario compares the node's tip and UTXO set fingerprint with
Core's (`gettxoutsetinfo` hash_serialized_3).

Usage: regtest.py <scenario> [options]   (scenarios: sync, follow, reorg, restart, all)
"""
import base64
import json
import os
import random
import shutil
import signal
import subprocess
import sys
import threading
import time
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORE_BIN = os.path.expanduser("~/bcs-data/bin/bitcoin-32.1/bin")
NODE_BIN = os.path.join(ROOT, "target", "release", "bitcoin-spec-node")
TXGEN_BIN = os.path.join(ROOT, "target", "release", "bsn-txgen")
TEST_DATA = os.path.join(ROOT, "test-data", "regtest")


def log(message):
    print(f"[{time.strftime('%H:%M:%S')}] {message}", flush=True)


class Core:
    def __init__(self, name, p2p_port, rpc_port, extra_args=()):
        self.datadir = os.path.join(TEST_DATA, name)
        self.p2p_port = p2p_port
        self.rpc_port = rpc_port
        self.extra_args = list(extra_args)
        self.process = None

    def start(self, fresh=True):
        if fresh and os.path.exists(self.datadir):
            shutil.rmtree(self.datadir)
        os.makedirs(self.datadir, exist_ok=True)
        args = [
            os.path.join(CORE_BIN, "bitcoind"),
            "-regtest",
            f"-datadir={self.datadir}",
            f"-port={self.p2p_port}",
            f"-rpcport={self.rpc_port}",
            "-bind=127.0.0.1",
            "-rpcbind=127.0.0.1",
            "-rpcallowip=127.0.0.1",
            "-rpcuser=u",
            "-rpcpassword=p",
            "-listen=1",
            "-server=1",
            "-fallbackfee=0.0002",
            "-dnsseed=0",
            "-fixedseeds=0",
            "-listenonion=0",
            "-printtoconsole=0",
        ] + self.extra_args
        self.process = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.time() + 60
        while time.time() < deadline:
            try:
                self.rpc("getblockcount")
                return
            except Exception:
                time.sleep(0.2)
        raise RuntimeError("bitcoind did not start")

    def stop(self):
        if self.process is None:
            return
        try:
            self.rpc("stop")
        except Exception:
            pass
        try:
            self.process.wait(timeout=60)
        except subprocess.TimeoutExpired:
            self.process.kill()
        self.process = None

    def rpc(self, method, *params, wallet=None):
        url = f"http://127.0.0.1:{self.rpc_port}/"
        if wallet:
            url += f"wallet/{wallet}"
        body = json.dumps({"jsonrpc": "1.0", "id": 1, "method": method, "params": list(params)}).encode()
        request = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
        request.add_header("Authorization", "Basic " + base64.b64encode(b"u:p").decode())
        try:
            with urllib.request.urlopen(request, timeout=600) as response:
                reply = json.loads(response.read())
        except urllib.error.HTTPError as error:
            reply = json.loads(error.read())
        if reply.get("error"):
            raise RuntimeError(f"{method}: {reply['error']}")
        return reply["result"]

    def utxo(self):
        info = self.rpc("gettxoutsetinfo", "hash_serialized_3")
        return info["bestblock"], info["height"], info["hash_serialized_3"], info["txouts"]

    def tip(self):
        return self.rpc("getbestblockhash"), self.rpc("getblockcount")


class Node:
    """bitcoin-spec-node run, with its stdout events collected by a thread."""

    def __init__(self, name):
        self.datadir = os.path.join(TEST_DATA, name)
        self.process = None
        self.events = []
        self.lock = threading.Lock()
        self.stderr_path = self.datadir + ".log"

    def reset(self):
        if os.path.exists(self.datadir):
            shutil.rmtree(self.datadir)

    def start(self, peer_port, stop_at=None, extra=()):
        args = [NODE_BIN, "run", "--network", "regtest", "--datadir", self.datadir, "--connect", f"127.0.0.1:{peer_port}"]
        if stop_at:
            args += ["--stop-at", stop_at]
        args += list(extra)
        self.stderr = open(self.stderr_path, "a")
        self.process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=self.stderr, text=True)
        self.events = []
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        for line in self.process.stdout:
            line = line.strip()
            if line.startswith("{"):
                event = json.loads(line)
                with self.lock:
                    self.events.append(event)

    def last_tip(self):
        with self.lock:
            tips = [e for e in self.events if e.get("event") in ("tip", "stopped")]
        return tips[-1] if tips else None

    def wait_for(self, predicate, timeout):
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self.lock:
                for event in self.events:
                    if predicate(event):
                        return event
            if self.process.poll() is not None:
                time.sleep(0.2)
                with self.lock:
                    for event in self.events:
                        if predicate(event):
                            return event
                raise RuntimeError(f"node exited with status {self.process.returncode}")
            time.sleep(0.05)
        raise RuntimeError("timeout waiting for node event")

    def wait_exit(self, timeout=120):
        code = self.process.wait(timeout=timeout)
        self.reader.join(timeout=5)
        return code

    def terminate(self):
        if self.process and self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            self.process.wait(timeout=600)

    def kill(self):
        if self.process and self.process.poll() is None:
            self.process.kill()
            self.process.wait()


def make_activity(core, rounds, txs_per_round, seed=1):
    """Mines blocks full of wallet transactions of every address type."""
    rng = random.Random(seed)
    wallets = core.rpc("listwallets")
    if "w" not in wallets:
        core.rpc("createwallet", "w")
    types = ["legacy", "p2sh-segwit", "bech32", "bech32m"]
    addresses = [core.rpc("getnewaddress", "", t, wallet="w") for t in types for _ in range(4)]
    miner = core.rpc("getnewaddress", "", "bech32m", wallet="w")
    if core.rpc("getblockcount") < 110:
        core.rpc("generatetoaddress", 110 - core.rpc("getblockcount"), miner)
    for round_number in range(rounds):
        for _ in range(txs_per_round):
            outputs = {rng.choice(addresses): round(rng.uniform(0.001, 0.05), 8) for _ in range(rng.randint(1, 4))}
            try:
                core.rpc("sendmany", "", outputs, wallet="w")
            except RuntimeError:
                break
        core.rpc("generatetoaddress", 1, rng.choice(addresses))


def make_chain(core, blocks, txs, seed=1, wallet_rounds=0):
    """A chain of `blocks` blocks with `txs` transactions each, built by bsn-txgen (signed by our
    own keys and validated by Core through submitblock), optionally preceded by wallet activity."""
    core.rpc("generatetodescriptor", 1, "raw(51)")
    if wallet_rounds:
        make_activity(core, rounds=wallet_rounds, txs_per_round=10, seed=seed)
    started = time.time()
    result = subprocess.run(
        [TXGEN_BIN, "--rpc", f"127.0.0.1:{core.rpc_port}", "--blocks", str(blocks), "--txs", str(txs), "--seed", str(seed)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"bsn-txgen failed: {result.stderr[-2000:]}")
    tip, height = core.tip()
    log(f"built a chain of {height} blocks (txgen: {blocks} blocks x {txs} txs in {time.time() - started:.0f}s)")


def compare(core, event, label):
    best, height, utxo_hash, txouts = core.utxo()
    ok = event["tip"] == best and event["height"] == height and event["hash_serialized_3"] == utxo_hash
    log(f"{label}: core tip {best} @{height} hash {utxo_hash} ({txouts} txouts); node tip {event['tip']} @{event['height']} hash {event['hash_serialized_3']} -> {'MATCH' if ok else 'MISMATCH'}")
    return ok


def check_contract(node, exit_code, stop_hash):
    """PROTOCOL.md section 5 output rules for a run that reached `stop_hash`: one `stopped` line,
    last, exit status 0; tip lines name each connected block at most once (no reorganization
    here); `utxo_hash` lines come before `stopped`; nothing else."""
    with node.lock:
        events = list(node.events)
    problems = []
    stopped = [e for e in events if e.get("event") == "stopped"]
    if len(stopped) != 1 or events[-1].get("event") != "stopped" or stopped[0]["tip"] != stop_hash:
        problems.append(f"{len(stopped)} stopped lines; last line {events[-1] if events else None}")
    tips = [e["tip"] for e in events if e.get("event") == "tip"]
    if len(tips) != len(set(tips)):
        problems.append(f"{len(tips) - len(set(tips))} repeated tip lines")
    others = [e for e in events if e.get("event") not in ("tip", "stopped", "utxo_hash")]
    if others:
        problems.append(f"unexpected lines: {others[:3]}")
    hashes = {e["height"]: e["hash_serialized_3"] for e in events if e.get("event") == "utxo_hash"}
    if stopped and stopped[0]["height"] in hashes and hashes[stopped[0]["height"]] != stopped[0]["hash_serialized_3"]:
        problems.append("utxo_hash at the stop height differs from the stopped line")
    if exit_code != 0:
        problems.append(f"exit status {exit_code}")
    log(f"output contract: {len(events)} lines, {len(hashes)} utxo_hash lines -> {'; '.join(problems) if problems else 'OK'}")
    return not problems


def scenario_sync(args):
    core = Core("core-sync", 30701, 30702)
    node = Node("node-sync")
    try:
        core.start()
        make_chain(core, blocks=args.get("blocks", 300), txs=args.get("txs", 200), seed=1, wallet_rounds=args.get("rounds", 3))
        tip, height = core.tip()
        log(f"core has {height} blocks; syncing the node to {tip}")
        node.reset()
        started = time.time()
        # Fingerprints at a middle height and at the stop block itself (both reported, the
        # stop block's before the stopped line).
        node.start(30701, stop_at=tip, extra=["--utxo-hash-at", f"{height // 2},{height}"])
        event = node.wait_for(lambda e: e.get("event") == "stopped", 600)
        log(f"synced {height} blocks in {time.time() - started:.1f}s")
        code = node.wait_exit()
        contract = check_contract(node, code, tip)
        return compare(core, event, "sync") and contract
    finally:
        node.kill()
        core.stop()


def scenario_follow_and_reorg(args):
    core = Core("core-reorg", 30711, 30712)
    node = Node("node-reorg")
    ok = True
    try:
        core.start()
        make_chain(core, blocks=args.get("blocks", 200), txs=args.get("txs", 100), seed=2, wallet_rounds=3)
        node.reset()
        node.start(30711)
        tip, height = core.tip()
        node.wait_for(lambda e: e.get("event") == "tip" and e["tip"] == tip, 300)
        log(f"node reached {height}; mining 5 more blocks on Core")
        miner = core.rpc("getnewaddress", "", "bech32", wallet="w")
        core.rpc("generatetoaddress", 5, miner)
        tip, height = core.tip()
        node.wait_for(lambda e: e.get("event") == "tip" and e["tip"] == tip, 120)
        log(f"node followed to {height}")
        # Reorganization: invalidate 6 blocks back on Core and build a longer fork with new transactions.
        fork_point = core.rpc("getblockhash", height - 5)
        core.rpc("invalidateblock", fork_point)
        make_activity(core, rounds=8, txs_per_round=10, seed=3)
        tip, height = core.tip()
        log(f"core reorganized to {tip} @{height}")
        node.wait_for(lambda e: e.get("event") == "tip" and e["tip"] == tip, 120)
        log("node followed the reorganization")
        node.terminate()
        node.start(30711, stop_at=tip)
        event = node.wait_for(lambda e: e.get("event") == "stopped", 120)
        node.wait_exit()
        ok &= compare(core, event, "reorg")
        # A second, deeper reorganization while the node runs, back onto a branch with more work.
        node.start(30711)
        core.rpc("reconsiderblock", fork_point)
        tip_a, height_a = core.tip()
        if tip_a == tip:
            core.rpc("invalidateblock", core.rpc("getblockhash", height - 7))
            make_activity(core, rounds=12, txs_per_round=5, seed=4)
        tip, height = core.tip()
        log(f"core switched to {tip} @{height}")
        node.wait_for(lambda e: e.get("event") == "tip" and e["tip"] == tip, 120)
        node.terminate()
        node.start(30711, stop_at=tip)
        event = node.wait_for(lambda e: e.get("event") == "stopped", 120)
        node.wait_exit()
        ok &= compare(core, event, "reorg-2")
        return ok
    finally:
        node.kill()
        core.stop()


def scenario_restart(args):
    """Kills the node (SIGKILL) at random moments during a sync, restarting it each time."""
    core = Core("core-restart", 30721, 30722)
    node = Node("node-restart")
    rng = random.Random(args.get("seed", 7))
    try:
        core.start()
        make_chain(core, blocks=args.get("blocks", 1500), txs=args.get("txs", 100), seed=5)
        tip, height = core.tip()
        log(f"core has {height} blocks; syncing with {args.get('kills', 8)} kills")
        node.reset()
        for kill in range(args.get("kills", 8)):
            node.start(30721, extra=["--dbcache", "4"])
            time.sleep(rng.uniform(0.3, 2.5))
            last = node.last_tip()
            node.kill()
            log(f"kill {kill + 1}: node was at {last['height'] if last else '?'}")
        node.start(30721, stop_at=tip, extra=["--dbcache", "4"])
        event = node.wait_for(lambda e: e.get("event") == "stopped", 900)
        node.wait_exit()
        return compare(core, event, "restart")
    finally:
        node.kill()
        core.stop()


def scenario_storm(args):
    """The node follows Core through many reorganizations of random depth (Core invalidates a
    recent block and mines a longer fork, which picks up the disconnected transactions from its
    mempool; sometimes the old branch is reconsidered), then restarts and compares its UTXO set."""
    core = Core("core-storm", 30741, 30742)
    node = Node("node-storm")
    rng = random.Random(args.get("seed", 13))
    try:
        core.start()
        make_chain(core, blocks=args.get("blocks", 150), txs=args.get("txs", 60), seed=21, wallet_rounds=2)
        node.reset()
        node.start(30741)

        def wait_node_at(tip, timeout):
            # The node reports every tip change on regtest, so its last tip event is its tip.
            deadline = time.time() + timeout
            while time.time() < deadline:
                last = node.last_tip()
                if last and last["tip"] == tip:
                    return
                if node.process.poll() is not None:
                    raise RuntimeError(f"node exited with status {node.process.returncode}")
                time.sleep(0.05)
            raise RuntimeError(f"node did not reach {tip}")

        tip, height = core.tip()
        wait_node_at(tip, 300)
        invalidated = []
        for step in range(args.get("steps", 25)):
            tip, height = core.tip()
            if invalidated and rng.random() < 0.25:
                block = invalidated.pop(rng.randrange(len(invalidated)))
                core.rpc("reconsiderblock", block)
                action = "reconsider"
            else:
                depth = rng.randint(1, 8)
                block = core.rpc("getblockhash", height - depth + 1)
                core.rpc("invalidateblock", block)
                invalidated.append(block)
                # Spend some coins so the new branch differs, then outgrow the old branch.
                try:
                    for _ in range(rng.randint(0, 6)):
                        address = core.rpc("getnewaddress", "", rng.choice(["bech32", "bech32m", "legacy"]), wallet="w")
                        core.rpc("sendtoaddress", address, round(rng.uniform(0.01, 0.3), 8), wallet="w")
                except RuntimeError:
                    pass
                # A coinbase script of its own per step: a block identical to the invalidated
                # one would be refused by Core as known invalid. Each new tip is higher than every
                # earlier block, so the node must follow it (regtest blocks have equal work).
                core.rpc("generatetodescriptor", depth + rng.randint(1, 3), f"raw(01{step % 256:02x}7551)")
                action = f"invalidate depth {depth}"
            tip, height = core.tip()
            wait_node_at(tip, 120)
            log(f"storm step {step + 1}: {action}; core and node at {height}")
        node.terminate()
        tip, height = core.tip()
        node.start(30741, stop_at=tip)
        event = node.wait_for(lambda e: e.get("event") == "stopped", 120)
        node.wait_exit()
        return compare(core, event, "storm")
    finally:
        node.kill()
        core.stop()


def scenario_bench(args):
    """Builds (once) a large chain on Core and measures how fast the node synchronizes it."""
    core = Core("core-bench", 30731, 30732)
    node = Node("node-bench")
    try:
        built = os.path.exists(os.path.join(core.datadir, "regtest", "blocks")) and args.get("rebuild", 0) == 0
        core.start(fresh=not built)
        if not built:
            make_chain(core, blocks=args.get("blocks", 600), txs=args.get("txs", 2500), seed=11)
        tip, height = core.tip()
        log(f"core has {height} blocks; benchmarking a sync to {tip}")
        node.reset()
        extra = []
        if "dbcache" in args:
            extra += ["--dbcache", str(args["dbcache"])]
        started = time.time()
        node.start(30731, stop_at=tip, extra=extra)
        event = node.wait_for(lambda e: e.get("event") == "stopped", 3600)
        elapsed = time.time() - started
        node.wait_exit()
        stats = core.rpc("getchaintxstats")
        log(f"synced {height} blocks ({stats['txcount']} transactions) in {elapsed:.1f}s: {height / elapsed:.1f} blocks/s, {stats['txcount'] / elapsed:.0f} tx/s")
        return compare(core, event, "bench")
    finally:
        node.kill()
        core.stop()


def main():
    scenario = sys.argv[1] if len(sys.argv) > 1 else "all"
    args = {}
    for item in sys.argv[2:]:
        key, value = item.split("=")
        args[key] = int(value)
    os.makedirs(TEST_DATA, exist_ok=True)
    results = {}
    if scenario in ("sync", "all"):
        results["sync"] = scenario_sync(args)
    if scenario in ("reorg", "all"):
        results["reorg"] = scenario_follow_and_reorg(args)
    if scenario in ("restart", "all"):
        results["restart"] = scenario_restart(args)
    if scenario == "bench":
        results["bench"] = scenario_bench(args)
    if scenario in ("storm", "all"):
        results["storm"] = scenario_storm(args)
    log(f"results: {results}")
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
