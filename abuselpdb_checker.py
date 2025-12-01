#!/usr/bin/env python3
"""
abuselpdb_checker.py — parallel AbuseIPDB checks with cache

- Finds IPs from processed_data/final_scored.csv + live connections
- Queries AbuseIPDB in parallel with session pooling
- Caches results to processed_data/abuse_cache.json
- Updates processed_data/final_scored.csv with abuse_score field
- Provides helper functions extract_remote_ips() and check_ip(ip)
"""
import os
import csv
import json
import time
import pathlib
import concurrent.futures
import requests
import psutil
from dotenv import load_dotenv

load_dotenv()
ROOT = pathlib.Path.cwd()
FINAL_CSV = ROOT / "processed_data" / "final_scored.csv"
ABUSE_CACHE = ROOT / "processed_data" / "abuse_cache.json"
API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
ABUSE_CONCURRENCY = int(os.getenv("ABUSE_CONCURRENCY", "8"))
ABUSE_DELAY = float(os.getenv("ABUSE_DELAY", "0.05"))
ABUSE_URL = "https://api.abuseipdb.com/api/v2/check"
ABUSE_BACKOFF_MAX = float(os.getenv("ABUSE_BACKOFF_MAX", "10"))

def load_cache():
    if ABUSE_CACHE.exists():
        try:
            return json.loads(ABUSE_CACHE.read_text(encoding="utf-8"))
        except Exception:
            return {}
    return {}

def save_cache(c):
    ABUSE_CACHE.parent.mkdir(parents=True, exist_ok=True)
    ABUSE_CACHE.write_text(json.dumps(c, indent=2), encoding="utf-8")

def extract_remote_ips():
    ips = set()
    try:
        conns = psutil.net_connections(kind="inet")
        for c in conns:
            if c.raddr and c.status == psutil.CONN_ESTABLISHED:
                try:
                    ips.add(c.raddr.ip)
                except Exception:
                    pass
    except Exception:
        pass
    return list(ips)

def query_ip(session, ip):
    """Query AbuseIPDB for a single ip. Return dict with fields 'abuseConfidenceScore' and meta"""
    if not API_KEY:
        return {"abuseConfidenceScore": 0, "meta": {"note":"no_api_key"}}
    headers = {"Accept": "application/json", "Key": API_KEY}
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    backoff = 0.1
    while True:
        try:
            r = session.get(ABUSE_URL, headers=headers, params=params, timeout=20)
            if r.status_code == 200:
                js = r.json()
                data = js.get("data", {})
                return {"abuseConfidenceScore": int(data.get("abuseConfidenceScore", 0)), "meta": {"status":200}}
            elif r.status_code == 429:
                backoff = min(ABUSE_BACKOFF_MAX, backoff * 2) if backoff else 0.5
                time.sleep(backoff)
            else:
                return {"abuseConfidenceScore": 0, "meta": {"status": r.status_code}}
        except Exception as e:
            return {"abuseConfidenceScore": 0, "meta": {"error": str(e)}}

def check_ip(ip):
    """Convenience function used by monitor - will call AbuseIPDB for single IP (safe)."""
    cache = load_cache()
    if ip in cache:
        return {"data": {"abuseConfidenceScore": cache[ip].get("abuseConfidenceScore", 0)}}
    session = requests.Session()
    res = query_ip(session, ip)
    cache[ip] = res
    save_cache(cache)
    return {"data": {"abuseConfidenceScore": res.get("abuseConfidenceScore", 0)}}

def main():
    cache = load_cache()
    ips = set()

    # gather from final_scored.csv
    if FINAL_CSV.exists():
        with FINAL_CSV.open(encoding="utf-8") as f:
            r = csv.DictReader(f)
            for row in r:
                ip = (row.get("remote_ip") or "").strip()
                if ip:
                    ips.add(ip)

    # include current connections
    for ip in extract_remote_ips():
        ips.add(ip)

    ips = sorted([i for i in ips if i])
    to_query = [ip for ip in ips if ip not in cache]
    if to_query:
        session = requests.Session()
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(ABUSE_CONCURRENCY, len(to_query))) as ex:
            futures = { ex.submit(query_ip, session, ip): ip for ip in to_query }
            for fut in concurrent.futures.as_completed(futures):
                ip = futures[fut]
                try:
                    res = fut.result()
                except Exception as e:
                    res = {"abuseConfidenceScore": 0, "meta": {"error": str(e)}}
                cache[ip] = res
                time.sleep(ABUSE_DELAY)
        save_cache(cache)

    # update final_scored.csv abuse_score column
    if FINAL_CSV.exists():
        rows = []
        with FINAL_CSV.open(encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                ip = (row.get("remote_ip") or "").strip()
                if ip and ip in cache:
                    row["abuse_score"] = cache[ip].get("abuseConfidenceScore", 0)
                else:
                    row["abuse_score"] = row.get("abuse_score", 0)
                rows.append(row)
        fieldnames = ["file_name","file_path","sha256","size","created_at","pid","remote_ip","vt_score","abuse_score","risk"]
        with FINAL_CSV.open("w", newline='', encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in rows:
                writer.writerow(r)
        print(f"Updated {len(rows)} rows in {FINAL_CSV} with abuse_score.")
    else:
        print("No final_scored.csv found to update.")

if __name__ == "__main__":
    main()
