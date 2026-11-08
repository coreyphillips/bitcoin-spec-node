#!/usr/bin/env python3
"""Checks a PROTOCOL.md harness against conformance/vectors/custom/*.jsonl.

Usage: check_custom.py "<harness command>" <cases.jsonl> [--verbose]

Each case is {"name", "request", "expect"}; the request is sent with an id, and every field of
"expect" must equal the response's field. `valid` is level 1; `script_error` and `reason` are
level 2 (a valid answer without script_error counts as OK, as in conformance/README.md).
"""
import json
import subprocess
import sys


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        return 2
    command, path = sys.argv[1], sys.argv[2]
    verbose = "--verbose" in sys.argv[3:]
    harness = subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    cases = [json.loads(line) for line in open(path) if line.strip()]
    level1_fail = level2_fail = 0
    for number, case in enumerate(cases):
        request = dict(case["request"])
        request["id"] = number
        harness.stdin.write(json.dumps(request) + "\n")
        harness.stdin.flush()
        response = json.loads(harness.stdout.readline())
        expect = case["expect"]
        problems = []
        if not response.get("ok"):
            problems.append(("level1", "ok", True, response))
        for key, value in expect.items():
            got = response.get(key)
            if key == "script_error" and got is None and response.get("valid"):
                got = "OK"
            if got != value:
                problems.append(("level1" if key == "valid" else "level2", key, value, got))
        if any(p[0] == "level1" for p in problems):
            level1_fail += 1
        elif problems:
            level2_fail += 1
        status = "FAIL" if any(p[0] == "level1" for p in problems) else ("LEVEL2" if problems else "ok")
        if verbose or problems:
            print(f"{status:6} {case['name']}" + "".join(f"\n       {lvl} {key}: expected {exp!r}, got {got!r}" for lvl, key, exp, got in problems))
    harness.stdin.close()
    harness.wait()
    print(f"custom: {len(cases)} cases, {len(cases) - level1_fail} passed level 1, {level1_fail} failed, {level2_fail} level 2 mismatches")
    return 1 if level1_fail else 0


if __name__ == "__main__":
    sys.exit(main())
