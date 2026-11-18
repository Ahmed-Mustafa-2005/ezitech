"""
Brew & Bean Cafe - Task 1: Baseline Normal API Traffic

Generates a synthetic sample.log (500 lines) of normal, authorized API
traffic and then reads it back to count requests per user and per endpoint.

All data is fake and generated locally. This is a lab exercise only.

Log line format (comma separated):
    timestamp, user_id, method, endpoint, status_code

Usage:
    python log_baseline.py
"""

import random
from collections import Counter
from datetime import datetime, timedelta

LOG_FILE = "sample.log"
OUTPUT_FILE = "baseline_output.txt"
NUM_LINES = 500
SEED = 42  # fixed seed so results are reproducible

USERS = ["user_101", "user_102", "user_103", "user_104", "user_105"]

# (method, endpoint) pairs that make up normal traffic, with weights.
# Normal behaviour: mostly listing orders (GET) and placing orders (POST).
REQUESTS = [("GET", "/orders"), ("POST", "/orders")]
REQUEST_WEIGHTS = [70, 30]

# Mostly 200 OK; a small number of 400s on POST (e.g. empty cart) is realistic.
STATUS_WEIGHTS_GET = ([200], [100])
STATUS_WEIGHTS_POST = ([200, 400], [97, 3])


def generate_log(path=LOG_FILE, num_lines=NUM_LINES, seed=SEED):
    """Write `num_lines` lines of fake normal traffic to `path`."""
    rng = random.Random(seed)
    current = datetime(2026, 11, 17, 8, 0, 0)  # cafe opens at 08:00
    lines = []

    for _ in range(num_lines):
        current += timedelta(seconds=rng.randint(5, 90))
        user = rng.choice(USERS)
        method, endpoint = rng.choices(REQUESTS, weights=REQUEST_WEIGHTS)[0]

        codes, weights = (
            STATUS_WEIGHTS_GET if method == "GET" else STATUS_WEIGHTS_POST
        )
        status = rng.choices(codes, weights=weights)[0]

        lines.append(
            f"{current.strftime('%Y-%m-%d %H:%M:%S')}, {user}, {method}, {endpoint}, {status}"
        )

    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    return path


def parse_log(path=LOG_FILE):
    """Read the log and return a list of dicts, one per valid line."""
    records = []
    with open(path) as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) != 5:
                print(f"Skipping malformed line {line_no}: {line}")
                continue
            ts, user, method, endpoint, status = parts
            records.append(
                {
                    "timestamp": ts,
                    "user": user,
                    "method": method,
                    "endpoint": endpoint,
                    "status": int(status),
                }
            )
    return records


def count_requests(records):
    """Count requests per user and per (method, endpoint)."""
    per_user = Counter(r["user"] for r in records)
    per_endpoint = Counter(f"{r['method']} {r['endpoint']}" for r in records)
    per_user_endpoint = Counter(
        (r["user"], f"{r['method']} {r['endpoint']}") for r in records
    )
    per_status = Counter(r["status"] for r in records)
    return per_user, per_endpoint, per_user_endpoint, per_status


def build_report(records):
    per_user, per_endpoint, per_user_endpoint, per_status = count_requests(records)
    total = len(records)
    out = []

    out.append("=== Brew & Bean Cafe - Baseline Traffic Summary ===")
    out.append(f"Total requests: {total}\n")

    out.append("Requests per user")
    out.append(f"{'User ID':<12}{'Requests':>10}{'Share':>9}")
    out.append("-" * 31)
    for user in sorted(per_user):
        out.append(f"{user:<12}{per_user[user]:>10}{per_user[user] / total:>8.1%}")
    out.append("")

    out.append("Requests per endpoint")
    out.append(f"{'Endpoint':<16}{'Requests':>10}{'Share':>9}")
    out.append("-" * 35)
    for ep, n in per_endpoint.most_common():
        out.append(f"{ep:<16}{n:>10}{n / total:>8.1%}")
    out.append("")

    endpoints = sorted(per_endpoint)
    out.append("Requests per user and endpoint")
    header = f"{'User ID':<12}" + "".join(f"{e:>14}" for e in endpoints)
    out.append(header)
    out.append("-" * len(header))
    for user in sorted(per_user):
        row = f"{user:<12}" + "".join(
            f"{per_user_endpoint[(user, e)]:>14}" for e in endpoints
        )
        out.append(row)
    out.append("")

    out.append("Status codes")
    for code, n in sorted(per_status.items()):
        out.append(f"  {code}: {n} ({n / total:.1%})")

    return "\n".join(out)


def main():
    generate_log()
    records = parse_log()
    report = build_report(records)
    print(report)
    with open(OUTPUT_FILE, "w") as f:
        f.write(report + "\n")
    print(f"\nLog written to {LOG_FILE}, summary saved to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
