# ezitech SOC Log Triage Tasks

This repository contains the Ezitech SOC log triage lab tasks.

## Tasks

- [Task 1: Baseline Normal API Traffic](README-task1.md)
- [Task 2: IDOR and Brute Force Detection](task2/README.md)

## Repository layout

- `log_baseline.py`, `sample.log`, and `baseline_output.txt` — Task 1 files
- `task2/` — Task 2 detector, generator, ground truth, and instructions

## Task 1 summary

Task 1 generates a 500-line synthetic API baseline and summarizes traffic per user, endpoint, and status code.

```bash
python3 log_baseline.py
```

## Task 2 summary

Task 2 generates suspicious API log events and detects IDOR and brute-force patterns.

```bash
cd task2
python3 gen_logs.py
python3 detect.py api.log --verify ground_truth.json
```
