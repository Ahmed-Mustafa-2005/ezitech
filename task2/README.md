# Brew & Bean Cafe: IDOR and Brute Force Detection (Task 2)

Intern: Ahmed Mustafa | Client: Ezitech | Technology: Cyber Security

## What this does

- `gen_logs.py` generates a sample API log (`api.log`, approximately 850 lines) containing normal traffic and 10 injected suspicious events:
  - 5 IDOR events: user A reads an order owned by user B
  - 5 brute-force events: one user (`mallory`) receives 401/403 responses two seconds apart
- `detect.py` parses the log and labels suspicious lines as `IDOR` or `Brute Force`.
- `ground_truth.json` contains the injected line numbers and labels for verification.

## Run it

```bash
python3 gen_logs.py
python3 detect.py api.log --verify ground_truth.json
```

Expected: 10 flagged lines and `VERIFY: ... PASS (exact match, no false positives)`.

## Detection logic

| Rule | Logic | Why |
|---|---|---|
| IDOR | Learn order ownership from `POST /api/orders` 201 lines, then flag `GET /api/orders/<id>` by a different user | A normal user only reads their own orders |
| Brute Force | A user with at least 3 responses of 401/403 inside 10 seconds | Single typos or lone 404s are normal; rapid bursts are suspicious |

## Limitations

- Ownership comes from the same log file. In a SIEM, join against an orders table or session identity.
- Thresholds are tunable, and production systems would typically key on source IP as well.
- A 200 response on another user's order demonstrates successful IDOR; repeated 403/404 responses would indicate failed attempts worth alerting on.
