#!/usr/bin/env python3
# collect_artifacts.py — FIXED to collect actual .exe files in artifacts/files/

import os
import json
import pathlib
import hashlib
from dotenv import load_dotenv

load_dotenv()
ROOT = pathlib.Path.cwd()
FILES_DIR = ROOT / "artifacts" / "files"
OUT_JSON = ROOT / "artifacts" / "artifacts_index.json"

CHUNK = 65536

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for blk in iter(lambda: f.read(CHUNK), b""):
            h.update(blk)
    return h.hexdigest()

def main():
    FILES_DIR.mkdir(parents=True, exist_ok=True)

    rows = []

    # 👉 FIX: collect ALL .exe files from artifacts/files/
    for p in sorted(FILES_DIR.rglob("*.exe")):
        if p.is_file():
            try:
                st = p.stat()
                rows.append({
                    "file_name": p.name,
                    "file_path": str(p.resolve()),
                    "size": st.st_size,
                    "created_at": int(st.st_mtime),
                    "sha256": sha256_file(p)
                })
            except Exception:
                continue

    OUT_JSON.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    print(f"Collected {len(rows)} .exe artifacts -> {OUT_JSON}")

if __name__ == "__main__":
    main()
