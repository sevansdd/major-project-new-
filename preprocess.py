#!/usr/bin/env python3
"""
Faster preprocess.py — drop-in replacement.

Key improvements:
 - persistent cache: processed_data/preprocess_cache.json
 - compute sha/entropy only when missing or when mtime changed
 - optional SHA/entropy via env COMPUTE_SHA (default 0)
 - parallel SHA/entropy via ThreadPoolExecutor controlled by FILE_WORKERS
 - faster directory scanning with os.scandir
 - preserves original outputs: processed_data/preprocessed.json and .csv
"""
import os
import sys
import json
import csv
import hashlib
import math
import datetime
import pathlib
import concurrent.futures
from typing import List, Dict, Any

ROOT = pathlib.Path(__file__).resolve().parent
ART_FILES_DIR = ROOT / "artifacts" / "files"
PROCESSED_DIR = ROOT / "processed_data"
PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

OUT_JSON = PROCESSED_DIR / "preprocessed.json"
OUT_CSV = PROCESSED_DIR / "preprocessed.csv"
CACHE_FILE = PROCESSED_DIR / "preprocess_cache.json"

# env knobs
COMPUTE_SHA = os.getenv("COMPUTE_SHA", "0") == "1"    # default: don't compute sha (fast)
FILE_WORKERS = int(os.getenv("FILE_WORKERS", os.getenv("WORKERS", "6")))
READ_CHUNK = 65536  # 64KB

# JSON candidates from original file (keeps compatibility)
ART_JSON_CANDIDATES = [
    ROOT / "artifacts" / "artifacts.json",
    ROOT / "artifacts.json",
    ROOT / "collected_artifacts.json",
]

# ---------------- Helpers ----------------
def load_json_candidates() -> List[Dict[str, Any]]:
    for p in ART_JSON_CANDIDATES:
        try:
            if p.exists():
                with p.open("r", encoding="utf-8") as fh:
                    data = json.load(fh)
                if isinstance(data, list):
                    return data
                if isinstance(data, dict) and isinstance(data.get("artifacts"), list):
                    return data["artifacts"]
                if isinstance(data, dict):
                    for v in data.values():
                        if isinstance(v, list):
                            return v
        except Exception:
            continue
    return []

def compute_sha256(path: pathlib.Path) -> str:
    try:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(READ_CHUNK), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        # keep function robust
        return ""

def shannon_entropy_bytes(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    entropy = 0.0
    L = len(data)
    for cnt in freq.values():
        p = cnt / L
        entropy -= p * math.log2(p)
    return round(entropy, 3)

def compute_entropy_of_file(path: pathlib.Path, max_bytes: int = READ_CHUNK) -> float:
    try:
        with path.open("rb") as f:
            data = f.read(max_bytes)
        return shannon_entropy_bytes(data)
    except Exception:
        return 0.0

def canonicalize_path(candidate: str) -> str:
    if not candidate:
        return ""
    p = pathlib.Path(candidate)
    if p.is_absolute() and p.exists():
        return str(p.resolve())
    cand = ROOT / candidate
    if cand.exists():
        return str(cand.resolve())
    cand2 = ART_FILES_DIR / candidate
    if cand2.exists():
        return str(cand2.resolve())
    try:
        return str(p.resolve())
    except Exception:
        return str(p)

# ---------------- Cache helpers ----------------
def load_cache() -> Dict[str, Any]:
    if CACHE_FILE.exists():
        try:
            return json.loads(CACHE_FILE.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}

def save_cache(cache: Dict[str, Any]):
    try:
        CACHE_FILE.write_text(json.dumps(cache, indent=2), encoding="utf-8")
    except Exception:
        pass

# Minimal worker that returns computed fields for a path
def _worker_compute(path_str: str) -> Dict[str, Any]:
    p = pathlib.Path(path_str)
    entry = {"file_path": path_str}
    try:
        st = p.stat()
        entry["size"] = st.st_size
        entry["created_at"] = datetime.datetime.utcfromtimestamp(st.st_mtime).isoformat()
    except Exception:
        entry["size"] = 0
        entry["created_at"] = ""
    if COMPUTE_SHA:
        entry["sha256"] = compute_sha256(p)
        entry["entropy"] = compute_entropy_of_file(p)
    else:
        entry["sha256"] = ""
        entry["entropy"] = 0.0
    entry["file_name"] = p.name
    entry["pid"] = ""
    entry["remote_ip"] = ""
    return entry

# ---------------- Main processing ----------------
def gather_files_fast() -> List[pathlib.Path]:
    """Return list of files in artifacts/files using os.scandir for speed."""
    result = []
    if not ART_FILES_DIR.exists():
        return result
    try:
        # Use scandir for speed — yields DirEntry objects
        with os.scandir(ART_FILES_DIR) as it:
            for entry in it:
                if entry.is_file():
                    result.append(pathlib.Path(entry.path))
    except Exception:
        # fallback to Path.iterdir
        for p in ART_FILES_DIR.iterdir():
            if p.is_file():
                result.append(p)
    result.sort(key=lambda p: p.name)
    return result

def main():
    print("[*] Preprocess (fast) starting... (COMPUTE_SHA={})".format(COMPUTE_SHA))
    cache = load_cache()  # format: { file_path: { mtime: <float>, sha256:..., entropy:..., size:... , created_at:... , file_name:... } }
    # load JSON candidate artifacts and normalize (like original)
    artifacts_json = load_json_candidates()
    normalized_json = []
    for a in artifacts_json:
        try:
            name = a.get("file_name") or a.get("name") or a.get("filename") or ""
            path = a.get("file_path") or a.get("path") or a.get("location") or ""
            sha = a.get("sha256") or a.get("hash") or ""
            pid = str(a.get("pid") or a.get("process_id") or "")
            remote_ip = a.get("remote_ip") or a.get("ip") or ""
            created = a.get("created_at") or a.get("timestamp") or ""
            if path:
                path = canonicalize_path(path)
            normalized_json.append({
                "file_name": str(name),
                "file_path": str(path),
                "sha256": str(sha),
                "pid": pid,
                "remote_ip": str(remote_ip),
                "created_at": str(created),
            })
        except Exception:
            continue

    # fast gather files from folder
    file_paths = gather_files_fast()
    print(f"[INFO] Found {len(file_paths)} files under {ART_FILES_DIR}")

    # Determine which files need hashing / entropy compute (when COMPUTE_SHA)
    to_compute = []
    final_map: Dict[str, Dict[str, Any]] = {}

    for p in file_paths:
        fp = str(p.resolve())
        try:
            mtime = p.stat().st_mtime
        except Exception:
            mtime = None
        cache_entry = cache.get(fp)
        if cache_entry and mtime is not None and cache_entry.get("mtime") == mtime:
            # reuse cached
            final_map[fp] = {
                "file_name": cache_entry.get("file_name", p.name),
                "file_path": fp,
                "sha256": cache_entry.get("sha256", ""),
                "size": cache_entry.get("size", 0),
                "entropy": cache_entry.get("entropy", 0.0),
                "created_at": cache_entry.get("created_at", ""),
                "pid": cache_entry.get("pid", ""),
                "remote_ip": cache_entry.get("remote_ip", ""),
            }
        else:
            # schedule compute (worker) — worker will compute sha/entropy only if COMPUTE_SHA
            to_compute.append(fp)
            # put a placeholder; worker will fill
            final_map[fp] = None

    # Parallel compute for new/changed files
    if to_compute:
        workers = min(FILE_WORKERS, max(1, len(to_compute)))
        print(f"[INFO] Computing metadata for {len(to_compute)} files using {workers} workers (COMPUTE_SHA={COMPUTE_SHA})")
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
            for fp, res in zip(to_compute, ex.map(_worker_compute, to_compute)):
                # update final_map and cache
                final_map[fp] = res
                try:
                    mtime = pathlib.Path(fp).stat().st_mtime
                except Exception:
                    mtime = None
                cache[fp] = {
                    "mtime": mtime,
                    "sha256": res.get("sha256", ""),
                    "entropy": res.get("entropy", 0.0),
                    "size": res.get("size", 0),
                    "created_at": res.get("created_at", ""),
                    "file_name": res.get("file_name", ""),
                    "pid": res.get("pid", ""),
                    "remote_ip": res.get("remote_ip", ""),
                }

    # Merge JSON-only entries like original script
    for n in normalized_json:
        fp = n.get("file_path") or ""
        if not fp:
            # try to resolve by file_name inside artifacts/files
            fname = n.get("file_name") or ""
            if fname:
                candidate = ART_FILES_DIR / fname
                if candidate.exists():
                    fp = str(candidate.resolve())
                    n["file_path"] = fp
                else:
                    # skip unresolvable JSON-only entries for speed
                    continue
            else:
                continue

        if fp in final_map and final_map[fp] is not None:
            merged = final_map[fp]
            # augment fields if missing
            if (not merged.get("pid")) and n.get("pid"):
                merged["pid"] = n.get("pid")
            if (not merged.get("remote_ip")) and n.get("remote_ip"):
                merged["remote_ip"] = n.get("remote_ip")
            if (not merged.get("created_at")) and n.get("created_at"):
                merged["created_at"] = n.get("created_at")
            final_map[fp] = merged
        else:
            # JSON path exists? compute quickly like worker
            pth = pathlib.Path(fp)
            if pth.exists():
                # compute minimal fields (sha/entropy only if COMPUTE_SHA)
                entry = _worker_compute(fp) if COMPUTE_SHA else {
                    "file_name": pth.name,
                    "file_path": fp,
                    "sha256": n.get("sha256",""),
                    "size": pth.stat().st_size if pth.exists() else 0,
                    "entropy": 0.0,
                    "created_at": n.get("created_at",""),
                    "pid": n.get("pid",""),
                    "remote_ip": n.get("remote_ip",""),
                }
                final_map[fp] = entry
                try:
                    cache[fp] = {
                        "mtime": pth.stat().st_mtime,
                        "sha256": entry.get("sha256",""),
                        "entropy": entry.get("entropy",0.0),
                        "size": entry.get("size",0),
                        "created_at": entry.get("created_at",""),
                        "file_name": entry.get("file_name",""),
                        "pid": entry.get("pid",""),
                        "remote_ip": entry.get("remote_ip",""),
                    }
                except Exception:
                    pass
            else:
                final_map[fp] = {
                    "file_name": n.get("file_name") or os.path.basename(fp),
                    "file_path": fp,
                    "sha256": n.get("sha256",""),
                    "size": "",
                    "entropy": "",
                    "created_at": n.get("created_at",""),
                    "pid": n.get("pid",""),
                    "remote_ip": n.get("remote_ip",""),
                }

    final_list = [v for v in final_map.values() if v is not None]
    print(f"[INFO] Final preprocessed artifact count: {len(final_list)}")

    # save JSON and CSV outputs (same schema as original)
    try:
        OUT_JSON.write_text(json.dumps(final_list, indent=2), encoding="utf-8")
        print(f"[INFO] Wrote JSON: {OUT_JSON}")
    except Exception as e:
        print(f"[ERROR] Failed to write {OUT_JSON}: {e}")

    fieldnames = ["file_name","file_path","sha256","size","entropy","created_at","pid","remote_ip"]
    try:
        with OUT_CSV.open("w", newline='', encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            for row in final_list:
                safe_row = {k: row.get(k, "") for k in fieldnames}
                writer.writerow(safe_row)
        print(f"[INFO] Wrote CSV: {OUT_CSV}")
    except Exception as e:
        print(f"[ERROR] Failed to write {OUT_CSV}: {e}")

    # save cache for future speedups
    save_cache(cache)
    print("[*] Preprocess finished.")

if __name__ == "__main__":
    main()
