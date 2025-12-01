#!/usr/bin/env python3
"""
sync_threat_db.py

Purpose:
 - Read the artifacts JSON produced by your collector/anomaly step (auto-detect common paths).
 - Cross-reference with any existing threat DB CSV (processed_data/final_scored.csv) OR the artifacts/files/ folder.
 - Produce a canonical processed_data/final_scored.csv containing columns remediation.py expects:
   file_name,file_path,sha256,size,created_at,pid,remote_ip,vt_score,abuse_score,risk

How to use:
  python sync_threat_db.py
  (Place it in the same folder as run_pipeline.py)
"""

import os
import csv
import json
import hashlib
import pathlib
import datetime
import random

ROOT = pathlib.Path.cwd()
PROCESSED = ROOT / "processed_data"
PROCESSED.mkdir(exist_ok=True)
FINAL_CSV = PROCESSED / "final_scored.csv"
ARTIFACTS_DIR = ROOT / "artifacts" / "files"
THREAT_CSV_CANDIDATES = [
    PROCESSED / "final_scored.csv",
    ROOT / "processed_data" / "threats.csv",
    ROOT / "threat_db.csv",
]
ARTIFACTS_JSON_CANDIDATES = [
    ROOT / "artifacts" / "artifacts.json",
    ROOT / "processed_data" / "artifacts.json",
    ROOT / "artifacts.json",
    ROOT / "collected_artifacts.json",
]

# columns we will produce
FIELDNAMES = ["file_name", "file_path", "sha256", "size", "created_at",
              "pid", "remote_ip", "vt_score", "abuse_score", "risk"]

def find_artifacts_json():
    for p in ARTIFACTS_JSON_CANDIDATES:
        if p.exists():
            return p
    return None

def load_artifacts_json(p):
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        # Support both list-of-dicts and dict with 'artifacts'
        if isinstance(data, dict) and "artifacts" in data and isinstance(data["artifacts"], list):
            return data["artifacts"]
        if isinstance(data, list):
            return data
        # fallback: try to find a nested list
        for v in data.values() if isinstance(data, dict) else []:
            if isinstance(v, list):
                return v
    except Exception as e:
        print(f"Failed to read artifacts JSON {p}: {e}")
    return []

def compute_sha256(pathp):
    try:
        h = hashlib.sha256()
        with open(pathp, "rb") as f:
            for blk in iter(lambda: f.read(8192), b""):
                h.update(blk)
        return h.hexdigest()
    except Exception:
        return ""

def load_threat_csv():
    for p in THREAT_CSV_CANDIDATES:
        if p.exists():
            # read as dict mapping by filename and sha256
            rows = []
            try:
                with open(p, newline='', encoding='utf-8') as f:
                    r = csv.DictReader(f)
                    for row in r:
                        rows.append(row)
                print("Loaded threat CSV:", p)
                return rows
            except Exception as e:
                print("Error loading threat CSV", p, e)
    return []

def find_threat_for_artifact(artifact, threat_rows):
    # artifact may contain name, path, sha256, etc.
    a_name = artifact.get("name") or artifact.get("file_name") or artifact.get("file") or ""
    a_path = artifact.get("path") or artifact.get("file_path") or ""
    a_sha = artifact.get("sha256") or artifact.get("hash") or ""
    a_name_l = a_name.lower() if a_name else ""
    # try matching by sha first
    for r in threat_rows:
        if r.get("sha256") and a_sha and r.get("sha256").lower() == a_sha.lower():
            return r
    # try by filename
    for r in threat_rows:
        if r.get("file_name") and a_name and r.get("file_name").lower() == a_name_l:
            return r
    # try by path basename
    for r in threat_rows:
        if r.get("file_path") and a_name:
            if pathlib.Path(r.get("file_path")).name.lower() == a_name_l:
                return r
    return None

def gather_artifacts_from_filesdir():
    # if JSON isn't present, fall back to scanning artifacts/files folder
    rows = []
    if not ARTIFACTS_DIR.exists():
        return rows
    for p in sorted(ARTIFACTS_DIR.iterdir()):
        if not p.is_file():
            continue
        name = p.name
        sha = compute_sha256(p)
        size = p.stat().st_size
        created_at = datetime.datetime.utcfromtimestamp(p.stat().st_mtime).isoformat()
        rows.append({
            "file_name": name,
            "file_path": str(p.resolve()),
            "sha256": sha,
            "size": size,
            "created_at": created_at,
            "pid": "",
            "remote_ip": "",
            "vt_score": "0",
            "abuse_score": "0",
            "risk": "suspicious" if "test_malware_like" in name.lower() else "clean"
        })
    return rows

def main():
    print("sync_threat_db.py starting...")
    art_json_path = find_artifacts_json()
    threat_rows = load_threat_csv()  # may be empty
    artifacts = []
    if art_json_path:
        print("Found artifacts JSON:", art_json_path)
        artifacts = load_artifacts_json(art_json_path)
    else:
        print("Artifacts JSON not found. Falling back to scanning artifacts/files/")
        artifacts = gather_artifacts_from_filesdir()

    final_rows = []
    # If JSON entries are dicts with different keys, normalize
    for a in artifacts:
        # try multiple possible keys to extract useful info
        fname = a.get("file_name") or a.get("name") or a.get("file") or ""
        fpath = a.get("file_path") or a.get("path") or a.get("location") or ""
        sha = a.get("sha256") or a.get("hash") or ""
        size = a.get("size") or ""
        pid = a.get("pid") or a.get("process_id") or ""
        remote_ip = a.get("remote_ip") or a.get("ip") or ""
        created_at = a.get("created_at") or a.get("timestamp") or datetime.datetime.utcnow().isoformat()

        # If file path is relative or empty, try to map to artifacts/files/<fname>
        if fpath:
            if not os.path.isabs(fpath):
                fpath = str((ROOT / fpath).resolve())
        else:
            # guess path from artifacts folder
            if fname:
                guess = ARTIFACTS_DIR / fname
                if guess.exists():
                    fpath = str(guess.resolve())

        # compute sha if missing and file exists
        if not sha and fpath and os.path.exists(fpath):
            sha = compute_sha256(fpath)
        # file size if missing
        if not size and fpath and os.path.exists(fpath):
            size = os.path.getsize(fpath)
        # if threat CSV has a matching row, use its risk/vt/abuse
        matched = find_threat_for_artifact({"file_name": fname, "file_path": fpath, "sha256": sha}, threat_rows)
        if matched:
            risk = matched.get("risk") or matched.get("label") or "suspicious"
            vt_score = matched.get("vt_score") or matched.get("vt") or matched.get("score") or "0"
            abuse_score = matched.get("abuse_score") or matched.get("abuse") or "0"
            # try to prefer matched path
            if matched.get("file_path"):
                fpath = matched.get("file_path")
            if matched.get("file_name") and not fname:
                fname = matched.get("file_name")
        else:
            # heuristic: if file name pattern indicates our generated threat, mark suspicious
            risk = "suspicious" if (fname and "test_malware_like" in fname.lower()) else "clean"
            vt_score = "0"
            abuse_score = "0"

        if not fname and fpath:
            fname = pathlib.Path(fpath).name

        final_rows.append({
            "file_name": fname,
            "file_path": fpath or "",
            "sha256": sha or "",
            "size": size or "",
            "created_at": created_at,
            "pid": str(pid) if pid else "",
            "remote_ip": remote_ip or "",
            "vt_score": str(vt_score),
            "abuse_score": str(abuse_score),
            "risk": risk.lower()  # canonicalize
        })

    # If nothing found, try the filesdir scan
    if not final_rows:
        print("No artifacts found in JSON or path. Scanning artifacts/files folder...")
        final_rows = gather_artifacts_from_filesdir()

    # Write final CSV
    with open(FINAL_CSV, "w", newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=FIELDNAMES)
        w.writeheader()
        for r in final_rows:
            w.writerow(r)

    print(f"Wrote {len(final_rows)} rows to {FINAL_CSV}")
    print("Sample rows:")
    for r in final_rows[:5]:
        print(" -", r["file_name"], "| risk:", r["risk"], "| path:", r["file_path"])
    print("Done.")
    return 0

if __name__ == "__main__":
    main()
