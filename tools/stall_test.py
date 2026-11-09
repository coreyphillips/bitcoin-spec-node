#!/usr/bin/env python3
"""Stalling-peer test: the node syncs from Bitcoin Core and from a fake peer that completes the
handshake and serves the same header chain but never answers block requests. The node must notice
that the fake peer holds up the next block, ask Core instead, finish well before its 64-second
block request timeout would, and match Core's UTXO set.

Usage: stall_test.py [blocks=300] [txs=100]
"""
import hashlib
import os
import socket
import struct
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import regtest  # noqa: E402

MAGIC = bytes.fromhex("fabfb5da")  # regtest
FAKE_PORT = 30751


def sha256d(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def varint(n):
    if n < 0xFD:
        return bytes([n])
    if n <= 0xFFFF:
        return b"\xfd" + struct.pack("<H", n)
    return b"\xfe" + struct.pack("<I", n)


def read_varint(data, pos):
    first = data[pos]
    if first < 0xFD:
        return first, pos + 1
    if first == 0xFD:
        return struct.unpack_from("<H", data, pos + 1)[0], pos + 3
    if first == 0xFE:
        return struct.unpack_from("<I", data, pos + 1)[0], pos + 5
    return struct.unpack_from("<Q", data, pos + 1)[0], pos + 9


def message(command, payload=b""):
    return MAGIC + command.encode().ljust(12, b"\0") + struct.pack("<I", len(payload)) + sha256d(payload)[:4] + payload


def read_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("closed")
        data += chunk
    return data


class FakePeer:
    """Serves `headers` (80-byte headers, genesis first) and ignores every block request."""

    def __init__(self, headers):
        self.headers = headers
        self.hashes = [sha256d(h) for h in headers]
        self.index = {h: i for i, h in enumerate(self.hashes)}
        self.getdata_items = 0
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", FAKE_PORT))
        self.server.listen(4)
        threading.Thread(target=self.accept, daemon=True).start()

    def accept(self):
        while True:
            try:
                sock, _ = self.server.accept()
            except OSError:
                return
            threading.Thread(target=self.serve, args=(sock,), daemon=True).start()

    def serve(self, sock):
        try:
            while True:
                header = read_exact(sock, 24)
                command = header[4:16].rstrip(b"\0").decode()
                length = struct.unpack_from("<I", header, 16)[0]
                payload = read_exact(sock, length)
                if command == "version":
                    address = struct.pack("<Q", 9) + bytes(10) + b"\xff\xff" + bytes([127, 0, 0, 1]) + struct.pack(">H", FAKE_PORT)
                    version = (
                        struct.pack("<iQq", 70016, 9, int(time.time()))
                        + address
                        + address
                        + struct.pack("<Q", 0x5EED)
                        + varint(len(b"/fake-staller/"))
                        + b"/fake-staller/"
                        + struct.pack("<i", len(self.headers) - 1)
                        + b"\x00"
                    )
                    sock.sendall(message("version", version) + message("verack"))
                elif command == "ping":
                    sock.sendall(message("pong", payload))
                elif command == "getheaders":
                    count, pos = read_varint(payload, 4)
                    start = 0
                    for i in range(count):
                        known = self.index.get(payload[pos + 32 * i : pos + 32 * (i + 1)])
                        if known is not None:
                            start = known + 1
                            break
                    chunk = self.headers[start : start + 2000]
                    sock.sendall(message("headers", varint(len(chunk)) + b"".join(h + b"\x00" for h in chunk)))
                elif command == "getdata":
                    count, _ = read_varint(payload, 0)
                    self.getdata_items += count
        except (ConnectionError, OSError):
            pass
        finally:
            sock.close()

    def close(self):
        self.server.close()


def main():
    args = {k: int(v) for k, v in (a.split("=") for a in sys.argv[1:])}
    core = regtest.Core("core-stall", 30761, 30762)
    node = regtest.Node("node-stall")
    fake = None
    try:
        core.start()
        regtest.make_chain(core, blocks=args.get("blocks", 300), txs=args.get("txs", 100), seed=31)
        tip, height = core.tip()
        headers = [bytes.fromhex(core.rpc("getblockheader", core.rpc("getblockhash", h), False)) for h in range(height + 1)]
        fake = FakePeer(headers)
        node.reset()
        started = time.time()
        # The fake peer is listed first, so it is connected (and asked for blocks) first.
        node.start(FAKE_PORT, stop_at=tip, extra=["--connect", f"127.0.0.1:{core.p2p_port}"])
        event = node.wait_for(lambda e: e.get("event") == "stopped", 300)
        elapsed = time.time() - started
        code = node.wait_exit()
        stalls = sum(1 for line in open(node.stderr_path) if "stalls block" in line)
        regtest.log(f"stall: synced {height} blocks in {elapsed:.1f}s; the fake peer was asked for {fake.getdata_items} blocks; {stalls} stall lines in the node log")
        ok = regtest.compare(core, event, "stall") and code == 0 and fake.getdata_items > 0 and elapsed < 60
        regtest.log(f"stall: {'PASS' if ok else 'FAIL'}")
        return 0 if ok else 1
    finally:
        node.kill()
        if fake:
            fake.close()
        core.stop()


if __name__ == "__main__":
    sys.exit(main())
