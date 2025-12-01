#!/usr/bin/env python3
"""
run_pipeline.py — simple one-shot pipeline runner + dashboard launcher

Runs your triage pipeline once in this order:

    1. collect_artifacts.py
    2. preprocess.py
    3. anomaly_detector.py
    4. rank_artifacts.py
    5. virustotal_checker.py
    6. abuselpdb_checker.py
    7. sync_threat_db.py
    8. remediation.py
    9. email_alert.py

Features:
 - Uses current Python interpreter.
 - Logs stdout/stderr for each step into logs/.
 - Writes processed_data/pipeline_status.json with progress.
 - Exits non-zero if any step fails.
 - NO live monitoring.
 - AFTER all steps succeed, launches the Streamlit dashboard (dashboard.py).
"""

import sys
import os
import subprocess
import pathlib
import datetime
import json
import difflib
import time

ROOT = pathlib.Path(__file__).resolve().parent
LOG_DIR = ROOT / "logs"
LOG_DIR.mkdir(exist_ok=True)
PROCESSED = ROOT / "processed_data"
PROCESSED.mkdir(exist_ok=True)

PY = sys.executable

# scripts to run in order
scripts = [
    "collect_artifacts.py",
    "preprocess.py",
    "anomoly_detector.py",   # your file may be anomoly_detector.py; resolver will handle
    "rank_artifacts.py",
    "virustotal_checker.py",
    "abuselpdb_checker.py",
    "sync_threat_db.py",
    "remediation.py",
]

PIPELINE_STATUS = PROCESSED / "pipeline_status.json"


def now_iso():
    return datetime.datetime.now().isoformat(timespec="seconds")


def write_status(step=None, status="idle", extra=None):
    """Write a small JSON with current pipeline progress for external observers."""
    data = {
        "timestamp": now_iso(),
        "step": step,
        "status": status,  # running, success, failed, idle, starting, finished, aborted
        "extra": extra or {},
    }
    try:
        PIPELINE_STATUS.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception:
        # Don't break the pipeline just because status can't be written
        pass


def resolve_script(script_name: str):
    """
    Try to find the script on disk.

    - First try ROOT/script_name
    - Then fuzzy match by basename
    - Then substring match in any *.py under ROOT
    """
    candidate = ROOT / script_name
    if candidate.exists():
        return candidate

    py_files = [p for p in ROOT.rglob("*.py") if p.name != pathlib.Path(__file__).name]
    basenames = [p.name for p in py_files]

    # fuzzy by basename
    matches = difflib.get_close_matches(
        os.path.basename(script_name), basenames, n=3, cutoff=0.6
    )
    if matches:
        for m in matches:
            cand = ROOT / m
            if cand.exists():
                print(f"resolve_script: fuzzy matched {script_name} -> {m}")
                return cand

    # substring in name
    stem = os.path.splitext(os.path.basename(script_name))[0].lower()
    for p in py_files:
        if stem in p.name.lower():
            print(f"resolve_script: substring matched {script_name} -> {p.name}")
            return p

    return None


def run_single(script_path: pathlib.Path) -> int:
    """Run one script and log its output."""
    script_name = script_path.name
    print(f"[{now_iso()}] ▶ Running: {script_name} (resolved: {script_path})")

    stdout_log = LOG_DIR / f"{script_name}_stdout.log"
    stderr_log = LOG_DIR / f"{script_name}_stderr.log"

    write_status(step=script_name, status="running")

    with open(stdout_log, "a", encoding="utf-8", errors="replace") as out_f, \
         open(stderr_log, "a", encoding="utf-8", errors="replace") as err_f:

        out_f.write(f"\n--- START {now_iso()} ---\n")
        err_f.write(f"\n--- START {now_iso()} ---\n")

        try:
            proc = subprocess.run(
                [PY, str(script_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=os.environ.copy(),
            )

            out_f.write(proc.stdout or "")
            err_f.write(proc.stderr or "")
            out_f.write(f"\n--- END {now_iso()} returncode={proc.returncode} ---\n")
            err_f.write(f"\n--- END {now_iso()} returncode={proc.returncode} ---\n")

            if proc.returncode != 0:
                print(
                    f"❌ {script_name} failed (code {proc.returncode}). "
                    f"See logs: {stdout_log}, {stderr_log}"
                )
                write_status(
                    step=script_name,
                    status="failed",
                    extra={"returncode": proc.returncode},
                )
            else:
                print(f"✅ {script_name} completed successfully.")
                write_status(step=script_name, status="success")

            return proc.returncode

        except Exception as e:
            err_f.write(f"Exception running step: {e}\n")
            print(f"❌ Exception while running {script_name}: {e}")
            write_status(
                step=script_name,
                status="failed",
                extra={"exception": str(e)},
            )
            return 3


def launch_dashboard():
    """Launch the Streamlit dashboard (dashboard.py) once at the end of the pipeline."""
    dashboard_path = ROOT / "dashboard.py"
    if not dashboard_path.exists():
        print("⚠️ dashboard.py not found; skipping dashboard launch.")
        write_status(step="dashboard", status="failed", extra={"error": "dashboard_not_found"})
        return

    try:
        print("📊 Launching Streamlit dashboard (dashboard.py)...")
        proc = subprocess.Popen(
            [PY, "-m", "streamlit", "run", "dashboard.py"],
            cwd=str(ROOT),
            env=os.environ.copy(),
        )
        print(f"Dashboard launched (PID {proc.pid}).")
        write_status(step="dashboard", status="launched", extra={"pid": proc.pid})
    except Exception as e:
        print("❌ Failed to launch dashboard:", e)
        write_status(step="dashboard", status="failed", extra={"error": str(e)})


def main():
    print("🚀 Simple pipeline runner starting (one-shot, no live monitoring).")
    write_status(step=None, status="starting")

    for s in scripts:
        resolved = resolve_script(s)
        if not resolved:
            print(f"❌ Could not resolve script: {s}. Aborting pipeline.")
            write_status(step=s, status="failed", extra={"error": "script_not_found"})
            sys.exit(5)

        code = run_single(resolved)

        if code != 0:
            print(
                f"[ABORT] Pipeline aborted due to failure in: {resolved.name} "
                f"(code {code})"
            )
            write_status(
                step=resolved.name,
                status="aborted",
                extra={"returncode": code},
            )
            sys.exit(code)

        # tiny pause just so logs are readable (optional)
        time.sleep(0.2)

    write_status(step=None, status="finished")
    print("🎉 All pipeline steps completed successfully.")

    # FINAL STEP: launch dashboard
    launch_dashboard()


if __name__ == "__main__":
    main()
