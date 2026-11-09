#!/usr/bin/env python3
"""Kills a syncing node, truncates its newest block files (a system crash can leave damaged files),
restarts it with --stop-at, and checks that it re-downloads what it cannot read and matches Core."""
import glob
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import regtest  # noqa: E402


def main():
    core = regtest.Core("core-restart", 30721, 30722)
    core.start(fresh=False)
    node = regtest.Node("node-corrupt")
    try:
        if core.rpc("getblockcount") < 300:
            regtest.make_chain(core, blocks=300, txs=150, seed=5)
        tip, height = core.tip()
        node.reset()
        node.start(30721, extra=["--dbcache", "4"])
        time.sleep(1.2)
        last = node.last_tip()
        node.kill()
        files = sorted(glob.glob(os.path.join(node.datadir, "blocks", "*.blk")), key=os.path.getmtime)
        victims = files[-40:]
        for path in victims:
            with open(path, "r+b") as handle:
                handle.truncate(100)
        print("killed at", last["height"] if last else None, "- truncated", len(victims), "newest block files of", len(files), flush=True)
        node.start(30721, stop_at=tip, extra=["--dbcache", "4", "--idle-timeout", "60"])
        event = node.wait_for(lambda e: e.get("event") == "stopped", 120)
        node.wait_exit()
        return 0 if regtest.compare(core, event, "corrupt") else 1
    finally:
        node.kill()
        core.stop()


if __name__ == "__main__":
    sys.exit(main())
