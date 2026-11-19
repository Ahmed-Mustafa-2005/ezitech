#!/usr/bin/env python3
"""Generate sample Brew & Bean Cafe API logs with injected IDOR and brute-force events.

Output:
  api.log           - log analysed by the detector
  ground_truth.json - injected line numbers and labels for verification
"""
import json
import random
from datetime import datetime, timedelta

random.seed(42)

USERS = ["alice", "bob", "carol", "dave", "erin", "frank"]
IPS = {u: f"10.0.0.{10 + i}" for i, u in enumerate(USERS)}
IPS["mallory"] = "203.0.113.66"
START = datetime(2026, 11, 19, 8, 0, 0)


def fmt(ts, user, method, path, status, extra=""):
    size = random.randint(120, 900)
    line = (f"{ts.strftime('%Y-%m-%dT%H:%M:%S')} {IPS[user]} user={user} "
            f"method={method} path={path} status={status} bytes={size}")
    return line + (f" {extra}" if extra else "")


def main():
    events = []
    owners = {}
    order_id = 1000

    t = START
    for _ in range(250):
        t += timedelta(seconds=random.randint(10, 90))
        user = random.choice(USERS)
        order_id += 1
        owners[order_id] = (user, t)
        events.append((t, fmt(t, user, "POST", "/api/orders", 201, f"order_id={order_id}"), None))
        for _ in range(random.randint(1, 3)):
            t2 = t + timedelta(seconds=random.randint(5, 600))
            events.append((t2, fmt(t2, user, "GET", f"/api/orders/{order_id}", 200), None))
        if random.random() < 0.3:
            events.append((t, fmt(t + timedelta(seconds=1), user, "GET", "/api/menu", 200), None))

    for u, offset in [("bob", 1200), ("erin", 5000), ("alice", 9000)]:
        ts = START + timedelta(seconds=offset)
        events.append((ts, fmt(ts, u, "POST", "/api/login", 401), None))
    for offset in (2000, 7000):
        ts = START + timedelta(seconds=offset)
        events.append((ts, fmt(ts, "dave", "GET", "/api/orders/999999999", 404), None))

    attackers = ["alice", "bob", "carol", "dave", "erin"]
    for i, attacker in enumerate(attackers):
        victim_order = random.choice([o for o, (own, _) in owners.items() if own != attacker])
        created = owners[victim_order][1]
        ts = created + timedelta(minutes=30 + i * 40)
        events.append((ts, fmt(ts, attacker, "GET", f"/api/orders/{victim_order}", 200), "IDOR"))

    bf_start = START + timedelta(hours=2, minutes=13)
    bf = [("/api/login", 401), ("/api/login", 401), ("/api/login", 401),
          ("/api/admin/orders", 403), ("/api/admin/users", 403)]
    for i, (path, status) in enumerate(bf):
        ts = bf_start + timedelta(seconds=i * 2)
        events.append((ts, fmt(ts, "mallory", "POST" if status == 401 else "GET", path, status), "Brute Force"))

    events.sort(key=lambda e: e[0])

    truth = []
    with open("api.log", "w") as f:
        for n, (_, line, label) in enumerate(events, start=1):
            f.write(line + "\n")
            if label:
                truth.append({"line": n, "label": label})
    with open("ground_truth.json", "w") as f:
        json.dump(truth, f, indent=2)

    print(f"Wrote api.log ({len(events)} lines) with {len(truth)} injected events.")


if __name__ == "__main__":
    main()
