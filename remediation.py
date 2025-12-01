#!/usr/bin/env python3
"""
remediation.py - robust remediation & matching (fixed logging bug)

Place at project root (overwrite existing remediation.py).
"""
import os
import csv
import json
import shutil
import hashlib
import time
from datetime import datetime
import pathlib
import psutil
import platform
import subprocess
import ctypes
from ctypes import wintypes
import concurrent.futures

ROOT = pathlib.Path.cwd()
PROCESSED = ROOT / "processed_data"
PROCESSED.mkdir(parents=True, exist_ok=True)
LOG_FILE = PROCESSED / "remediation_logs.txt"
DEBUG_CSV = PROCESSED / "remediation_debug.csv"
QUARANTINE_DIR = PROCESSED / "quarantine"
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
SCORED_CSV = PROCESSED / "final_scored.csv"
ART_FILES_DIR = ROOT / "artifacts" / "files"
ART_INDEX = ROOT / "artifacts" / "artifacts_index.json"

# Environment knobs (tune as needed)
DRY_RUN = os.getenv("DRY_RUN", "1") == "1"  # safe default: don't modify files
REM_VT_THRESH = int(os.getenv("REMEDIATION_VT_THRESHOLD", "1"))
REM_ABUSE_THRESH = int(os.getenv("REMEDIATION_ABUSE_THRESHOLD", "70"))
COMPUTE_SHA = os.getenv("COMPUTE_SHA_FOR_REMEDIATION", "0") == "1"
FILE_WORKERS = int(os.getenv("FILE_WORKERS", os.getenv("WORKERS", "6")))
FORCE_MATCH_ARTIFACT_FILENAMES = os.getenv("FORCE_MATCH_ARTIFACT_FILENAMES", "0") == "1"

MOVEFILE_DELAY_UNTIL_REBOOT = 0x00000004

# --- Logging helpers ---
def log(msg):
    ts = datetime.now().isoformat()
    line = f"{ts} - {msg}"
    try:
        with open(LOG_FILE, "a", encoding="utf-8", errors="replace") as f:
            f.write(line + "\n")
    except Exception:
        pass
    print(line)

# --- Utility helpers ---
def compute_sha(path, chunk=65536):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for b in iter(lambda: fh.read(chunk), b""):
                h.update(b)
        return h.hexdigest()
    except Exception as e:
        log(f"compute_sha error for {path}: {e}")
        return ""

def _schedule_delete_on_reboot_windows(path):
    try:
        if platform.system().lower().startswith("windows"):
            MoveFileEx = ctypes.windll.kernel32.MoveFileExW
            MoveFileEx.argtypes = [wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
            MoveFileEx.restype = wintypes.BOOL
            ok = MoveFileEx(str(path), None, MOVEFILE_DELAY_UNTIL_REBOOT)
            if ok:
                log(f"Scheduled {path} for deletion on next reboot.")
                return True
            else:
                log(f"MoveFileExW failed for {path}, code: {ctypes.GetLastError()}")
    except Exception as e:
        log(f"schedule_delete_on_reboot_windows error: {e}")
    return False

def terminate_pid(pid):
    try:
        p = psutil.Process(int(pid))
    except Exception as e:
        log(f"terminate_pid: no such pid {pid}: {e}")
        return False
    try:
        p.terminate()
        try:
            p.wait(timeout=5)
            log(f"PID {pid} terminated")
            return True
        except psutil.TimeoutExpired:
            log(f"PID {pid} did not terminate; killing")
            p.kill()
            try:
                p.wait(timeout=5)
                log(f"PID {pid} killed")
                return True
            except Exception as e:
                log(f"Failed killing PID {pid}: {e}")
                return False
    except Exception as e:
        log(f"terminate_pid error: {e}")
        return False

def quarantine_path(filepath, reason=None):
    """Attempt to quarantine file. Returns (True, info) or (False, err)."""
    if not filepath:
        return False, "no_path"
    if not os.path.exists(filepath):
        return False, "not_found"

    dest = QUARANTINE_DIR / f"{int(time.time())}_{os.path.basename(filepath)}"

    if DRY_RUN:
        log(f"[DRY_RUN] Would quarantine {filepath} -> {dest} (reason={reason})")
        return True, str(dest)

    # Attempt move
    try:
        shutil.move(filepath, str(dest))
        log(f"Quarantined {filepath} -> {dest} (move) reason={reason}")
        return True, str(dest)
    except Exception as e:
        log(f"Move failed for {filepath}: {e}")

    # Try to find owning processes and terminate them then retry
    try:
        for proc in psutil.process_iter(['pid','exe','open_files']):
            try:
                matched = False
                exe = proc.info.get('exe') or ""
                if exe and os.path.exists(exe) and os.path.samefile(exe, filepath):
                    matched = True
                if not matched:
                    try:
                        for of in proc.open_files() or []:
                            if os.path.samefile(of.path, filepath):
                                matched = True
                                break
                    except Exception:
                        pass
                if matched:
                    log(f"Found owning process PID {proc.pid} for {filepath}; terminating")
                    terminate_pid(proc.pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                log(f"Error while checking process: {e}")
    except Exception as e:
        log(f"Error iterating processes: {e}")

    # Try move again
    try:
        shutil.move(filepath, str(dest))
        log(f"Quarantined {filepath} -> {dest} after terminating owners")
        return True, str(dest)
    except Exception as e:
        log(f"Move retry failed for {filepath}: {e}")

    # Try copy + remove
    try:
        shutil.copy2(filepath, str(dest))
        log(f"Copied {filepath} -> {dest} (fallback); attempting remove original")
        try:
            os.remove(filepath)
            log(f"Removed original {filepath} after copy.")
            return True, str(dest)
        except Exception as e:
            log(f"Failed removing original after copy: {e}; leaving copy in quarantine")
            return True, str(dest) + " (copied; original not removed)"
    except Exception as e:
        log(f"Copy fallback failed for {filepath}: {e}")

    # Schedule delete on reboot (Windows)
    if platform.system().lower().startswith("windows"):
        if _schedule_delete_on_reboot_windows(filepath):
            placeholder = QUARANTINE_DIR / f"{int(time.time())}_{os.path.basename(filepath)}.scheduled_delete"
            try:
                with open(placeholder, "w", encoding="utf-8", errors="replace") as fh:
                    fh.write(f"Scheduled {filepath} for deletion on reboot at {datetime.now().isoformat()}\n")
            except Exception:
                pass
            return True, "scheduled_delete_on_reboot"

    log(f"Failed to quarantine {filepath} after all attempts.")
    return False, "locked_or_error"

# --- Build artifacts index ---
def build_artifacts_index(compute_sha_flag=False):
    """
    Build:
      - name_map: filename.lower() -> [abs_paths]
      - sha_map: sha -> abs_path (if compute_sha_flag True)
    """
    name_map = {}
    sha_map = {}

    # include artifacts_index.json if present
    if ART_INDEX.exists():
        try:
            j = json.loads(ART_INDEX.read_text(encoding="utf-8"))
            for e in j:
                fp = e.get("file_path") or ""
                fn = e.get("file_name") or (os.path.basename(fp) if fp else "")
                if fp and os.path.exists(fp):
                    p = str(pathlib.Path(fp).resolve())
                    name_map.setdefault(fn.lower(), []).append(p)
                    if compute_sha_flag and e.get("sha256"):
                        sha_map[e.get("sha256")] = p
        except Exception as e:
            log(f"Warning: failed to parse artifacts_index.json: {e}")

    # scan ART_FILES_DIR recursively
    if ART_FILES_DIR.exists():
        for p in ART_FILES_DIR.rglob("*"):
            if p.is_file():
                key = p.name.lower()
                pathstr = str(p.resolve())
                name_map.setdefault(key, []).append(pathstr)
    else:
        log("Warning: artifacts/files directory not found; artifacts may be in other paths.")

    # optionally compute SHA for artifact files (parallel)
    if compute_sha_flag:
        # prepare list of files to compute
        all_paths = []
        for paths in name_map.values():
            all_paths.extend(paths)
        # deduplicate
        all_paths = list(dict.fromkeys(all_paths))
        if all_paths:
            log(f"Computing SHA256 for {len(all_paths)} artifact files (workers={min(FILE_WORKERS, len(all_paths))})")
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(FILE_WORKERS, len(all_paths))) as ex:
                for path, sha in zip(all_paths, ex.map(compute_sha, all_paths)):
                    if sha:
                        if sha not in sha_map:
                            sha_map[sha] = path

    log(f"Built artifacts index: filenames={len(name_map)} sha_entries={len(sha_map)}")
    return name_map, sha_map

# --- Candidate check ---
def row_is_candidate(row, name_map, sha_map):
    """
    Determine if row should be remediated and return tuple (is_candidate, reason)
    """
    # normalize columns
    risk = (row.get("risk") or row.get("status") or "").strip().lower()
    try:
        vt = int(float(row.get("vt_score") or 0))
    except Exception:
        vt = 0
    try:
        ab = int(float(row.get("abuse_score") or 0))
    except Exception:
        ab = 0
    # direct score/risk criteria
    if vt >= REM_VT_THRESH:
        return True, f"vt_score={vt}"
    if ab >= REM_ABUSE_THRESH:
        return True, f"abuse_score={ab}"
    if risk and any(k in risk for k in ("suspicious","malicious","infected","vt_detected","danger")):
        return True, f"risk_tag:{risk}"
    # force match if enabled: any file under artifacts with that filename
    fn = (row.get("file_name") or "").strip()
    if FORCE_MATCH_ARTIFACT_FILENAMES and fn:
        if fn.lower() in name_map:
            return True, "force_match_artifact_filename"
    # if row has sha and that sha in sha_map, treat as candidate
    sha = (row.get("sha256") or "").strip()
    if sha and sha in sha_map:
        return True, "sha_map_match"
    # else not candidate
    return False, ""

# --- Main remediation flow ---
def remediate():
    log("=== Remediation run started ===")
    log(f"Settings: DRY_RUN={DRY_RUN}, REM_VT_THRESH={REM_VT_THRESH}, REM_ABUSE_THRESH={REM_ABUSE_THRESH}, COMPUTE_SHA={COMPUTE_SHA}, FORCE_MATCH={FORCE_MATCH_ARTIFACT_FILENAMES}")

    if not SCORED_CSV.exists():
        log(f"final_scored.csv not found at {SCORED_CSV}. Nothing to remediate.")
        return {"quarantined": [], "blocked_ips": [], "errors": ["no_csv"]}

    name_map, sha_map = build_artifacts_index(compute_sha_flag=COMPUTE_SHA)

    debug_rows = []
    quarantined = []
    blocked_ips = []
    errors = []

    # open CSV
    with open(SCORED_CSV, newline='', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                is_cand, reason = row_is_candidate(row, name_map, sha_map)
                if not is_cand:
                    continue

                # attempt to resolve matched artifact path (prefer file_path -> sha -> filename -> substring)
                matched_path = ""
                # 1) file_path or path column
                for k in ("file_path","path","filepath","exe_path"):
                    v = (row.get(k) or "").strip()
                    if v:
                        p = pathlib.Path(v)
                        if p.exists():
                            matched_path = str(p.resolve())
                            break
                        p2 = ROOT / v
                        if p2.exists():
                            matched_path = str(p2.resolve())
                            break
                # 2) sha match
                if not matched_path:
                    sha = (row.get("sha256") or "").strip()
                    if sha and sha in sha_map:
                        matched_path = sha_map[sha]
                # 3) exact filename match
                if not matched_path:
                    fn = (row.get("file_name") or "").strip()
                    if fn and fn.lower() in name_map:
                        matched_path = name_map[fn.lower()][0]
                # 4) substring search in name_map keys
                if not matched_path:
                    fn = (row.get("file_name") or "").strip().lower()
                    if fn:
                        for k, paths in name_map.items():
                            if fn in k:
                                matched_path = paths[0]
                                break

                debug_rows.append({
                    "file_name": row.get("file_name",""),
                    "sha256": row.get("sha256",""),
                    "vt_score": row.get("vt_score",""),
                    "abuse_score": row.get("abuse_score",""),
                    "risk": row.get("risk",""),
                    "reason": reason,
                    "matched_path": matched_path
                })

                if not matched_path:
                    log(f"Candidate found but no disk match: file_name={row.get('file_name')} sha={row.get('sha256')} reason={reason}")
                    errors.append(f"no_disk_match:{row.get('file_name') or row.get('sha256')}")
                    continue

                # attempt quarantine
                ok, info = quarantine_path(matched_path, reason=reason)
                if ok:
                    quarantined.append({"src": matched_path, "dest": info, "reason": reason})
                else:
                    errors.append(f"quarantine_failed:{matched_path}:{info}")

                # attempt blocking IP if present
                ip = (row.get("remote_ip") or row.get("ip") or "").strip()
                if ip:
                    b_ok, b_info = block_ip_simple(ip)
                    if b_ok:
                        blocked_ips.append({"ip": ip, "method": b_info})
                    else:
                        errors.append(f"block_failed:{ip}:{b_info}")

            except Exception as e:
                log(f"Error processing row for remediation: {e}")
                errors.append(str(e))

    # write debug CSV
    try:
        with open(DEBUG_CSV, "w", newline='', encoding='utf-8', errors='replace') as dbg:
            fieldnames = ["file_name","sha256","vt_score","abuse_score","risk","reason","matched_path"]
            writer = csv.DictWriter(dbg, fieldnames=fieldnames)
            writer.writeheader()
            for r in debug_rows:
                writer.writerow(r)
        log(f"Wrote remediation debug CSV: {DEBUG_CSV} rows={len(debug_rows)}")
    except Exception as e:
        log(f"Failed writing debug CSV: {e}")

    log(f"Remediation finished. Candidates={len(debug_rows)}, quarantined={len(quarantined)}, blocked_ips={len(blocked_ips)}, errors={len(errors)}")
    return {"quarantined": quarantined, "blocked_ips": blocked_ips, "errors": errors}

# --- simple IP block helper (best-effort) ---
def block_ip_simple(ip):
    system = platform.system().lower()
    log(f"Attempting to block IP {ip} on {system}")
    try:
        if DRY_RUN:
            log(f"[DRY_RUN] would block IP {ip}")
            return True, "dry_run"
        if "windows" in system:
            rule_name = f"Block_IP_{ip}"
            subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                            f"name={rule_name}", "dir=in", "action=block", f"remoteip={ip}"], check=False)
            subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                            f"name={rule_name}_out", "dir=out", "action=block", f"remoteip={ip}"], check=False)
            return True, "windows_netsh"
        else:
            subprocess.run(["sudo", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"], check=False)
            subprocess.run(["sudo", "iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP"], check=False)
            return True, "iptables"
    except Exception as e:
        log(f"Failed to block IP {ip}: {e}")
        return False, str(e)

# --- entrypoint ---
if __name__ == "__main__":
    res = remediate()
    print("Remediation summary:", res)
