#!/usr/bin/env python3
"""
live_monitor.py — fixed and hardened.

Fixes:
 - correct datetime usage to avoid AttributeError
 - ignore System Idle / PID 0 to prevent false positives
 - guard against unrealistic cpu% readings
 - call run_pipeline.py with --no-dashboard so dashboard isn't launched automatically
"""
import os
import time
import subprocess
import psutil
from datetime import datetime
from dotenv import load_dotenv

# Load .env from project root
ROOT = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(ROOT, ".env"))

# Import abuselpdb functions (ensure file defines them)
from abuselpdb_checker import extract_remote_ips, check_ip

# config
THREAT_CPU_THRESHOLD = 90               # per-process threshold (percentage)
THREAT_IP_SCORE_THRESHOLD = 70
CHECK_INTERVAL = 60
COOLDOWN_AFTER_TRIGGER = 300            # seconds
LOG_FILE = os.path.join(ROOT, "incident_logs.txt")
PIPELINE_SCRIPT = os.path.join(ROOT, "run_pipeline.py")
PIPELINE_PY = "python"  # or "python3" on some systems

# System process names to ignore (case-insensitive)
SYSTEM_NAME_BLACKLIST = {"system idle process", "idle", "system"}

def log_incident(details):
    entry = f"{datetime.now().isoformat()} - {details}\n"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(entry)
    print(entry.strip())

def warmup_cpu():
    # call once for psutil baseline
    psutil.cpu_percent(interval=None)

def check_high_cpu(threshold=THREAT_CPU_THRESHOLD, sample_interval=0.1):
    """
    Return string describing offending process if any process exceeds threshold.
    Ignores PID 0 and common system names to avoid false positives.
    """
    try:
        cpu_count = psutil.cpu_count(logical=True) or 1
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pid = getattr(proc, "pid", None)
                name = (proc.info.get('name') or "").strip()
                # sample shortly
                cpu = proc.cpu_percent(interval=sample_interval)
                # guard: if cpu reading absurdly large (> cpu_count*100 + 1) ignore it
                if cpu and cpu > (cpu_count * 100 + 1):
                    # suspicious reading - skip
                    continue
                # ignore pid 0 and blacklisted system process names
                if pid in (0, None):
                    continue
                if name.lower() in SYSTEM_NAME_BLACKLIST:
                    continue
                if cpu and cpu > threshold:
                    return f"High CPU usage detected: {name} (PID {pid}) -> {cpu:.1f}%"
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                print("Process cpu check error:", e)
                continue
    except Exception as e:
        print("Failed to iterate processes:", e)
    return None

def check_malicious_ips(threshold=THREAT_IP_SCORE_THRESHOLD):
    try:
        ips = extract_remote_ips() or []
    except Exception as e:
        print("Failed to extract remote IPs:", e)
        return None
    if not ips:
        return None
    print(f"Remote IPs found: {ips}")
    for ip in ips:
        try:
            resp = check_ip(ip)
            if not isinstance(resp, dict):
                continue
            # find abuseConfidenceScore inside response safely
            data = resp.get("data") or {}
            score = 0
            try:
                score = int(data.get("abuseConfidenceScore", 0))
            except Exception:
                score = 0
            print(f"IP {ip} abuse score -> {score}")
            if score >= threshold:
                return f"Malicious IP detected: {ip} (Abuse Score: {score})"
        except Exception as e:
            print(f"Error checking IP {ip}: {e}")
            continue
    return None

def run_pipeline_no_dashboard(script_path=PIPELINE_SCRIPT):
    if not os.path.exists(script_path):
        log_incident(f"Pipeline script not found: {script_path}")
        return -1
    # pass explicit flag to avoid dashboard launching
    try:
        cmd = [PIPELINE_PY, script_path, "--no-dashboard"]
        log_incident(f"Triggering pipeline: {' '.join(cmd)}")
        proc = subprocess.run(cmd, capture_output=True, text=True)
        log_incident(f"Pipeline finished with code {proc.returncode}")
        # write short stdout/stderr for debugging
        if proc.stdout:
            with open(os.path.join(ROOT, "pipeline_stdout.log"), "a", encoding="utf-8") as lf:
                lf.write(f"\n--- {datetime.now().isoformat()} STDOUT ---\n")
                lf.write(proc.stdout[:20000])
        if proc.stderr:
            with open(os.path.join(ROOT, "pipeline_stderr.log"), "a", encoding="utf-8") as lf:
                lf.write(f"\n--- {datetime.now().isoformat()} STDERR ---\n")
                lf.write(proc.stderr[:20000])
        return proc.returncode
    except Exception as e:
        log_incident(f"Failed to run pipeline: {e}")
        return -1

def main():
    print("🔍 Live Monitor starting — warming sensors...")
    warmup_cpu()
    last_trigger = 0
    try:
        while True:
            now = time.time()
            if now - last_trigger < COOLDOWN_AFTER_TRIGGER:
                remaining = int(COOLDOWN_AFTER_TRIGGER - (now - last_trigger))
                print(f"In cooldown ({remaining}s remaining). Sleeping {CHECK_INTERVAL}s.")
                time.sleep(CHECK_INTERVAL)
                continue

            cpu_alert = check_high_cpu()
            ip_alert = check_malicious_ips()
            threat = cpu_alert or ip_alert
            if threat:
                print(f"\n🚨 Threat detected: {threat}")
                log_incident(f"Threat detected -> {threat}")
                rc = run_pipeline_no_dashboard(PIPELINE_SCRIPT)
                log_incident(f"Pipeline run returned code {rc}")
                last_trigger = time.time()
            else:
                print(f"{datetime.now().isoformat()} – No threats detected. Next check in {CHECK_INTERVAL}s.")
            time.sleep(CHECK_INTERVAL)
    except KeyboardInterrupt:
        print("Live monitor stopped by user.")
    except Exception as e:
        print("Unexpected error in monitor main loop:", e)
        log_incident(f"Monitor crashed: {e}")

if __name__ == "__main__":
    main()
