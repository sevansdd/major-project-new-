#!/usr/bin/env python3
"""
generate_threat_db.py
Generates a safe test threat database for the triage project.

Creates:
 - artifacts/files/*.exe  (harmless text files with .exe extension)
 - processed_data/final_scored.csv  (CSV used by remediation.py)
Optional:
 - spawn dummy processes that sleep (to get real PIDs) with --spawn
"""

import os
import csv
import argparse
import pathlib
import hashlib
import time
import random
import datetime
import subprocess
import sys

ROOT = pathlib.Path.cwd()
ARTIFACTS_DIR = ROOT / "artifacts" / "files"
PROCESSED_DIR = ROOT / "processed_data"
FINAL_CSV = PROCESSED_DIR / "final_scored.csv"

# IANA TEST-NET ranges (safe)
TEST_NET_IPS = [
    "203.0.113.",   # TEST-NET-3
    "198.51.100.",  # TEST-NET-2
    "192.0.2."      # TEST-NET-1
]

DEFAULT_COUNT = 10

def ensure_dirs():
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

def make_dummy_exe(index):
    """
    Create a harmless file with .exe extension containing readable text.
    Returns absolute path and sha256.
    """
    name = f"test_malware_like_{index}.exe"
    path = ARTIFACTS_DIR / name
    content = (f"Dummy executable placeholder\n"
               f"Index: {index}\n"
               f"Created: {datetime.datetime.utcnow().isoformat()} UTC\n"
               f"This is harmless test data — NOT MALWARE.\n")
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    # build SHA256
    import hashlib
    with open(path, "rb") as f:
        sha = hashlib.sha256(f.read()).hexdigest()
    return str(path.resolve()), sha, path.stat().st_size

def random_test_ip():
    base = random.choice(TEST_NET_IPS)
    last = random.randint(1, 254)
    return base + str(last)

def generate_rows(count, spawn_pids=False, num_procs=0):
    rows = []
    pids = []
    procs = []
    if spawn_pids and num_procs > 0:
        # Spawn num_procs dummy sleep processes and keep track of their PIDs.
        # They will run Python in background and sleep for some time.
        for i in range(num_procs):
            # cross-platform simple sleeper command
            if sys.platform.startswith("win"):
                # Use Python to sleep to get a PID of a python process
                cmd = [sys.executable, "-c", "import time; time.sleep(600)"]
                proc = subprocess.Popen(cmd, creationflags=0)
            else:
                cmd = [sys.executable, "-c", "import time; time.sleep(600)"]
                proc = subprocess.Popen(cmd)
            procs.append(proc)
            pids.append(proc.pid)
        print(f"Spawned {len(procs)} dummy processes: PIDs {pids}")

    for i in range(count):
        file_path, sha256, size = make_dummy_exe(i+1)
        # randomly assign some as malicious/high and others as benign
        risk = random.choices(
            ["clean", "suspicious", "malicious", "high"],
            weights=[40, 25, 25, 10],
            k=1
        )[0]
        # vt_score mimic: higher value = more engines detect
        vt_score = 0
        if risk == "malicious":
            vt_score = random.randint(20, 60)
        elif risk == "high":
            vt_score = random.randint(60, 95)
        elif risk == "suspicious":
            vt_score = random.randint(1, 19)
        else:
            vt_score = 0

        # abuseipdb score mimic
        abuse_score = 0
        remote_ip = random_test_ip()
        if risk in ("malicious", "high"):
            abuse_score = random.randint(80, 100)
        elif risk == "suspicious":
            abuse_score = random.randint(10, 60)
        else:
            abuse_score = random.randint(0, 5)

        # optionally assign a PID from spawned ones (round-robin) for some rows
        pid = ""
        if pids and random.random() < 0.3:  # 30% of entries use a spawned PID
            pid = str(random.choice(pids))

        row = {
            "file_name": os.path.basename(file_path),
            "file_path": file_path,
            "sha256": sha256,
            "size": size,
            "created_at": datetime.datetime.utcnow().isoformat(),
            "pid": pid,
            "remote_ip": remote_ip,
            "vt_score": vt_score,
            "abuse_score": abuse_score,
            "risk": risk
        }
        rows.append(row)
    return rows, procs

def write_csv(rows):
    fieldnames = ["file_name", "file_path", "sha256", "size", "created_at",
                  "pid", "remote_ip", "vt_score", "abuse_score", "risk"]
    with open(FINAL_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)
    print(f"Wrote {len(rows)} rows to {FINAL_CSV}")

def main():
    parser = argparse.ArgumentParser(description="Generate a safe threat DB for testing")
    parser.add_argument("--count", type=int, default=DEFAULT_COUNT, help="number of sample artifact rows")
    parser.add_argument("--spawn", action="store_true", help="spawn dummy sleeper processes so remediation can test PID termination")
    parser.add_argument("--num-procs", type=int, default=2, help="how many sleeper processes to spawn (only used with --spawn)")
    args = parser.parse_args()

    ensure_dirs()
    rows, procs = generate_rows(args.count, spawn_pids=args.spawn, num_procs=args.num_procs)
    write_csv(rows)

    print("Sample files created under:", ARTIFACTS_DIR)
    print("Final scored CSV created at:", FINAL_CSV)
    if args.spawn:
        print("Spawned dummy processes (they will run for ~10 minutes).")
        print("To clean them up manually, kill the listed PIDs or restart the test VM.")
    else:
        print("No dummy processes spawned. If you want PID tests, rerun with --spawn")

if __name__ == "__main__":
    main()
