#!/usr/bin/env python3
"""
virustotal_checker.py — parallel, cached VirusTotal checker

- Reads artifacts (artifacts/artifacts_index.json) or scans artifacts/files/
- Computes missing sha256 in parallel (FILE_WORKERS)
- Queries VT in parallel (VT_CONCURRENCY) using requests.Session
- Caches VT responses to processed_data/vt_cache.json
- Writes processed_data/final_scored.csv (same schema you expect)
"""
import os
import csv
import json
import time
import hashlib
import pathlib
import concurrent.futures
import requests
from dotenv import load_dotenv

load_dotenv()
ROOT = pathlib.Path.cwd()
ART_INDEX = ROOT / "artifacts" / "artifacts_index.json"
ART_DIR = ROOT / "artifacts" / "files"
FINAL_CSV = ROOT / "processed_data" / "final_scored.csv"
VT_CACHE = ROOT / "processed_data" / "vt_cache.json"

API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
VT_CONCURRENCY = int(os.getenv("VT_CONCURRENCY", "8"))
VT_DELAY = float(os.getenv("VT_DELAY", "0.1"))
VT_BACKOFF_MAX = float(os.getenv("VT_BACKOFF_MAX", "10"))
FILE_WORKERS = int(os.getenv("FILE_WORKERS", "8"))
CHUNK = 65536

VT_URL = "https://www.virustotal.com/api/v3/files/{}"

def load_cache():
    if VT_CACHE.exists():
        try:
            return json.loads(VT_CACHE.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}

def save_cache(cache):
    VT_CACHE.parent.mkdir(parents=True, exist_ok=True)
    VT_CACHE.write_text(json.dumps(cache, indent=2), encoding="utf-8")

def compute_sha(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for blk in iter(lambda: f.read(CHUNK), b""):
                h.update(blk)
        return h.hexdigest()
    except Exception:
        return ""

def vt_query(session, sha):
    """Query VT for a sha. Returns vt_score integer and meta dict."""
    if not API_KEY:
        return 0, {"note": "no_api_key"}
    headers = {"x-apikey": API_KEY}
    url = VT_URL.format(sha)
    backoff = 0.1
    while True:
        try:
            r = session.get(url, headers=headers, timeout=30)
            if r.status_code == 200:
                js = r.json()
                stats = js.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                vt_score = sum(int(v) for v in stats.values()) if isinstance(stats, dict) else 0
                return vt_score, {"status": 200}
            elif r.status_code == 429:
                # rate limited: backoff with cap
                backoff = min(VT_BACKOFF_MAX, backoff * 2) if backoff else 0.5
                time.sleep(backoff)
            else:
                return 0, {"status": r.status_code, "text": r.text[:400]}
        except Exception as e:
            return 0, {"error": str(e)}

def gather_artifacts():
    """Return list of dicts with keys file_name, file_path, size, created_at, sha256(optional)"""
    items = []
    if ART_INDEX.exists():
        try:
            items = json.loads(ART_INDEX.read_text(encoding="utf-8"))
        except Exception:
            items = []
    else:
        if ART_DIR.exists():
            for p in sorted(ART_DIR.iterdir()):
                if p.is_file():
                    items.append({
                        "file_name": p.name,
                        "file_path": str(p.resolve()),
                        "size": p.stat().st_size,
                        "created_at": p.stat().st_mtime
                    })
    return items

def main():
    cache = load_cache()
    artifacts = gather_artifacts()

    # Compute missing SHAs in parallel
    paths_to_hash = []
    for e in artifacts:
        sha = e.get("sha256") or ""
        if not sha:
            fp = e.get("file_path") or ""
            if fp and pathlib.Path(fp).exists():
                paths_to_hash.append(fp)

    if paths_to_hash:
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(FILE_WORKERS, len(paths_to_hash))) as ex:
            for fp, sha in zip(paths_to_hash, ex.map(compute_sha, paths_to_hash)):
                for e in artifacts:
                    if e.get("file_path") == fp:
                        e["sha256"] = sha

    # Build list of unique SHAs to query (skip cached)
    sha_to_entries = {}
    for e in artifacts:
        sha = (e.get("sha256") or "").strip()
        if sha:
            sha_to_entries.setdefault(sha, []).append(e)

    shas_to_query = [s for s in sha_to_entries.keys() if s and s not in cache]

    # Parallel VT queries using requests.Session per worker
    if shas_to_query:
        session = requests.Session()
        with concurrent.futures.ThreadPoolExecutor(max_workers=VT_CONCURRENCY) as ex:
            futures = { ex.submit(vt_query, session, sha): sha for sha in shas_to_query }
            for fut in concurrent.futures.as_completed(futures):
                sha = futures[fut]
                try:
                    vt_score, meta = fut.result()
                except Exception as e:
                    vt_score, meta = 0, {"error": str(e)}
                cache[sha] = {"vt_score": int(vt_score), "meta": meta}
                # polite per-thread minimal delay
                time.sleep(VT_DELAY)
        save_cache(cache)

    # Write final_scored.csv combining vt scores and existing fields
    fieldnames = ["file_name","file_path","sha256","size","created_at","pid","remote_ip","vt_score","abuse_score","risk"]
    FINAL_CSV.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for e in artifacts:
        sha = (e.get("sha256") or "").strip()
        vt_score = int(cache.get(sha, {}).get("vt_score", 0)) if sha else 0
        row = {
            "file_name": e.get("file_name",""),
            "file_path": e.get("file_path",""),
            "sha256": sha,
            "size": e.get("size",""),
            "created_at": e.get("created_at",""),
            "pid": e.get("pid",""),
            "remote_ip": e.get("remote_ip",""),
            "vt_score": vt_score,
            "abuse_score": e.get("abuse_score", 0),
            "risk": e.get("risk","suspicious" if vt_score>0 else "unknown")
        }
        rows.append(row)

    with FINAL_CSV.open("w", newline='', encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)
    save_cache(cache)
    print(f"Wrote {len(rows)} rows to {FINAL_CSV}")

if __name__ == "__main__":
    main()
