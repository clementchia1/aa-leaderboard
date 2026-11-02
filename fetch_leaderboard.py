#!/usr/bin/env python3
"""Fetch the COMPLETE Artificial Analysis model dataset — no browser needed.

How the site actually delivers data
-----------------------------------
The leaderboard page is Next.js App Router. The `RSC: 1` flight payload only
carries `initialModels` (~278 models, partial metrics): that is why the old
fetcher produced an incomplete table.

The full table (722 models x 35 benchmark scores) ships as one blob:

    /data/<hash>.txt      AES-256-GCM ciphertext, 16-byte tag appended
    manifest.key          hex AES key, embedded in the page payload
    plaintext             gzip(JSON array of model objects)

IV = sha256(aes_key)[:12]. The page decrypts this client-side with
crypto.subtle + DecompressionStream("gzip"). We do the same in pure Python
(see aes_gcm.py), so the pipeline stays stdlib-only.

Usage:
    python3 fetch_leaderboard.py                 # writes data/leaderboard.json
    python3 fetch_leaderboard.py -o out.json     # custom output path
"""

import argparse
import gzip
import hashlib
import json
import re
import sys
import time
import urllib.request
from datetime import datetime, timezone

import aes_gcm

URL = "https://artificialanalysis.ai/leaderboards/models?status=all"
BASE = "https://artificialanalysis.ai"
UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"
)

# Gate: refuse to publish a partial dataset. Observed 2026-11-03: 722 models,
# 35 benchmark slugs, 110 omniscience rows, 242 automationbench rows.
MIN_MODELS = 700
MIN_BENCHMARKS = 30
MIN_ROWS = {"omniscience-non-hallucination": 95, "automationbench-aa": 230}

MANIFEST_RE = re.compile(
    r'\\?"path\\?":\\?"(/data/[A-Za-z0-9_.-]+\.txt)\\?",\s*'
    r'\\?"key\\?":\\?"([0-9a-fA-F]{64})\\?"'
)


def get(url: str, headers: dict | None = None, tries: int = 3) -> bytes:
    last = None
    for attempt in range(tries):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
            with urllib.request.urlopen(req, timeout=60) as r:
                return r.read()
        except Exception as exc:  # noqa: BLE001 - retry any transport error
            last = exc
            if attempt + 1 < tries:
                time.sleep(2 * (attempt + 1))
    raise RuntimeError(f"GET {url} failed: {last}")


def find_manifest() -> tuple[str, str]:
    """Locate the encrypted dataset URL + AES key in the page or RSC payload."""
    page = get(URL).decode("utf-8", errors="replace")
    m = MANIFEST_RE.search(page)
    if m:
        return m.group(1), m.group(2)

    # Fallback: the RSC flight payload carries the same manifest.
    rsc = get(URL, {"RSC": "1", "Accept": "text/x-component"}).decode("utf-8", errors="replace")
    m = MANIFEST_RE.search(rsc)
    if m:
        return m.group(1), m.group(2)
    raise RuntimeError("manifest {path,key} not found in page or RSC payload")


def fetch_models() -> list[dict]:
    path, key_hex = find_manifest()
    blob = get(BASE + path, {"Referer": URL})
    key = bytes.fromhex(key_hex)
    iv = hashlib.sha256(key).digest()[:12]
    plain = aes_gcm.decrypt(key, iv, blob)
    try:
        models = json.loads(gzip.decompress(plain))
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"decrypted payload is not gzip JSON: {exc}") from exc
    if not isinstance(models, list):
        raise RuntimeError("decrypted payload is not a JSON array")
    return models


def normalize(models: list[dict]) -> list[dict]:
    """Add the legacy flat aliases downstream scripts rely on; keep everything."""
    for m in models:
        scores = m.get("scores") or {}
        m["displayName"] = m.get("name") or m.get("shortName") or m.get("slug")
        m["creator"] = m.get("modelCreatorName")
        m["benchmarkCount"] = len(scores)
    return models


def validate(models: list[dict]) -> dict:
    bench: dict[str, int] = {}
    for m in models:
        for slug, val in (m.get("scores") or {}).items():
            if val is not None:
                bench[slug] = bench.get(slug, 0) + 1
    problems = []
    if len(models) < MIN_MODELS:
        problems.append(f"models={len(models)} < {MIN_MODELS}")
    if len(bench) < MIN_BENCHMARKS:
        problems.append(f"benchmarks={len(bench)} < {MIN_BENCHMARKS}")
    for slug, need in MIN_ROWS.items():
        got = bench.get(slug, 0)
        if got < need:
            problems.append(f"{slug}={got} < {need}")
    if problems:
        raise RuntimeError("incomplete dataset: " + "; ".join(problems))
    return bench


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--output", default="data/leaderboard.json")
    args = ap.parse_args()

    try:
        models = normalize(fetch_models())
        bench = validate(models)
    except Exception as exc:  # noqa: BLE001 - fail loudly, write nothing
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    out = {
        "source": URL,
        "dataSource": "encrypted dataset /data/<hash>.txt (AES-256-GCM + gzip)",
        "fetchedAt": datetime.now(timezone.utc).isoformat(),
        "modelCount": len(models),
        "benchmarkCount": len(bench),
        "benchmarks": dict(sorted(bench.items(), key=lambda kv: -kv[1])),
        "models": models,
    }
    import os

    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(out, f, ensure_ascii=False, indent=1)
    print(
        f"wrote {args.output}: {len(models)} models, {len(bench)} benchmarks",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
