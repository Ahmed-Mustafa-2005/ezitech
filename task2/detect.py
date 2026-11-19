#!/usr/bin/env python3
"""Flag IDOR and brute-force patterns in Brew & Bean Cafe API logs.

Rules:
  IDOR        - a user requests /api/orders/<id> where <id> was created by a DIFFERENT user.
                Ownership is learned from POST /api/orders ... 201 order_id=<id> lines.
  Brute Force - one user gets >= FAIL_THRESHOLD 401/403 responses within WINDOW_SECONDS.

Usage:
  python detect.py [api.log] [--verify ground_truth.json]
"""
import json
import re
from collections import defaultdict
from datetime import datetime

FAIL_THRESHOLD = 3
WINDOW_SECONDS = 10

LINE_RE = re.compile(
    r"^(?P<ts>\S+) (?P<ip>\S+) user=(?P<user>\S+) method=(?P<method>[A-Z]+) "
    r"path=(?P<path>\S+) status=(?P<status>\d{3})(?: bytes=\d+)?(?: order_id=(?P<oid>\d+))?"
)
ORDER_PATH_RE = re.compile(r"^/api/orders/(\d+)$")


def parse(path):
    rows = []
    with open(path) as f:
        for n, raw in enumerate(f, start=1):
            m = LINE_RE.match(raw.strip())
            if not m:
                continue
            d = m.groupdict()
            d["n"] = n
            d["raw"] = raw.rstrip("\n")
            d["time"] = datetime.fromisoformat(d["ts"])
            d["status"] = int(d["status"])
            rows.append(d)
    return rows


def detect(rows):
    flags = {}

    owners = {}
    for r in rows:
        if r["method"] == "POST" and r["path"] == "/api/orders" and r["status"] == 201 and r["oid"]:
            owners[r["oid"]] = r["user"]

    for r in rows:
        m = ORDER_PATH_RE.match(r["path"])
        if not m:
            continue
        oid = m.group(1)
        owner = owners.get(oid)
        if owner and owner != r["user"]:
            flags[r["n"]] = ("IDOR", f"User {r['user']} accessed order {oid} owned by {owner}", r["raw"])

    fails = defaultdict(list)
    for r in rows:
        if r["status"] in (401, 403):
            fails[r["user"]].append(r)
    for user, items in fails.items():
        for r in items:
            near = [x for x in items if abs((x["time"] - r["time"]).total_seconds()) <= WINDOW_SECONDS]
            if len(near) >= FAIL_THRESHOLD and r["n"] not in flags:
                flags[r["n"]] = ("Brute Force",
                                 f"User {user} got {len(near)} 401/403 responses within {WINDOW_SECONDS}s",
                                 r["raw"])
    return dict(sorted(flags.items()))


def main():
    import sys
    args = sys.argv[1:]
    verify = None
    if "--verify" in args:
        i = args.index("--verify")
        verify = args[i + 1]
        del args[i:i + 2]
    log = args[0] if args else "api.log"

    rows = parse(log)
    flags = detect(rows)

    print(f"Parsed {len(rows)} lines, flagged {len(flags)}\n")
    for n, (label, reason, raw) in flags.items():
        print(f"[{label}] line {n}: {reason}\n    {raw}")

    if verify:
        with open(verify) as f:
            truth = {t["line"]: t["label"] for t in json.load(f)}
        got = {n: v[0] for n, v in flags.items()}
        ok = got == truth
        print(f"\nVERIFY: expected {len(truth)} injected lines, flagged {len(got)} -> "
              f"{'PASS (exact match, no false positives)' if ok else 'FAIL'}")
        if not ok:
            print("  missed:", sorted(set(truth) - set(got)))
            print("  false positives:", sorted(set(got) - set(truth)))
            sys.exit(1)


if __name__ == "__main__":
    main()
