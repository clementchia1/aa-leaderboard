# aa-leaderboard

Daily pipeline that scrapes the [Artificial Analysis LLM Leaderboard](https://artificialanalysis.ai/leaderboards/models) — all ~720 models with the full metric set (Intelligence Index, 35 benchmark scores, pricing, speed percentiles) — and picks out the **free models**, ranked by intelligence.

Data lands in `data/` every day via GitHub Actions. No browser, no API key, no headless Chrome — two HTTP GETs and a stdlib AES-GCM decrypt.

## Outputs

| File | What |
|---|---|
| `data/leaderboard.json` | Full leaderboard: 720+ models × 33 fields + nested `scores` (35 benchmarks) |
| `data/leaderboard.csv` | One row per model, one column per benchmark slug + metadata (71 columns) |
| `data/free_models.json` / `.csv` / `.md` | Free models only, ranked by Intelligence Index |

## Quick start

```bash
pip install -r requirements.txt   # nothing — stdlib only
python3 fetch_leaderboard.py      # → data/leaderboard.json
python3 to_csv.py                 # → data/leaderboard.csv
python3 pick_free_models.py       # → data/free_models.{json,csv,md}
```

### Options

```bash
# free models only (default)
python3 pick_free_models.py --max-price 0

# anything under $0.50/1M blended, top 50, intelligence ≥ 30
python3 pick_free_models.py --max-price 0.5 --top 50 --min-intelligence 30
```

## Daily automation

`.github/workflows/daily.yml` runs every day at 03:00 UTC (and on every push to `main` touching the scripts):

1. `fetch_leaderboard.py` — pull + decrypt + validate the dataset
2. `pick_free_models.py` — rank free models
3. `to_csv.py` — flatten leaderboard to CSV
4. Auto-commit updated `data/` back to `main`

## How the scraper works (no API key, no browser)

The leaderboard is a Next.js App Router page, and the `RSC: 1` flight payload is **not** the real dataset — it only carries `initialModels`, a ~278-row partial table. That was the old scraper's ceiling.

The complete table ships separately as one blob:

```
GET /data/<hash>.txt      AES-256-GCM ciphertext, 16-byte tag appended
manifest key              hex AES key, embedded in the page payload
plaintext                 gzip(JSON array of model objects)
IV                        sha256(aes_key)[:12]
```

`fetch_leaderboard.py` scrapes `{path, key}` from the page (RSC payload as fallback), fetches the blob, and decrypts it in pure Python — `aes_gcm.py` is a small vendored AES-GCM implementation, verified against the FIPS-197 AES-256 vector, so there is still nothing to `pip install` and no headless browser in CI. Decrypt of the 139 KB blob takes ~0.5 s. The result is byte-identical to what the site's own JS produces in a real browser.

Validation is a hard gate: if the payload yields fewer than 700 models, fewer than 30 benchmark slugs, or fewer than 95 `omniscience-non-hallucination` / 230 `automationbench-aa` rows, the script exits non-zero, writes no file, and the Action turns red — no silent partial data.

**Fragility:** the transform is custom but simple (AES-GCM + gzip). If the site rotates the key format, changes the IV derivation, swaps the cipher, or renames the manifest fields, `fetch_leaderboard.py` fails loudly with `GCM tag mismatch`/`manifest not found`. The fix in that case is to re-read the decrypt routine in `_next/static/chunks` and adjust `find_manifest()`; the browser-capture workaround (init-script hooking `Response.prototype.text`) is a stopgap, not part of this pipeline.

## Fields worth knowing

Top level per model: `slug`, `name`, `shortName`, `modelCreatorName`, `intelligenceIndex`, `intelligenceIndexIsEstimated`, `intelligenceIndexCostPerTask`, `omniscience`, `isReasoning`, `isOpenWeights`, `deprecated`, `paramClass`, `priceClass`, `contextWindowTokens`, pricing (`price1mInputTokens`, `price1mOutputTokens`, `cacheHitPrice`, `cacheWritePrice`), and speed percentiles/medians (tokens/s, time-to-first-token, end-to-end, reasoning time).

`scores` holds one entry per benchmark slug — `omniscience-accuracy`, `omniscience-non-hallucination`, `automationbench-aa`, `gdpval-aa-normalized`, `aa-briefcase`, `aa-3d`, `apex-agents-aa`, `itbench-aa`, `harvey-lab-aa`, `enterprise-ops-gym-aa`, `code2video-aa`, `terminalbench-2-1`, `terminalbench-4-0`, `critpt`, `critpt-v2-hard`, `frontiercode`, `frontiercode-2-0`, `healthbench`, and more. `to_csv.py` emits one column per slug, so new benchmarks appear automatically without code changes.

## License

MIT — see [LICENSE](LICENSE). Data originates from Artificial Analysis; check their terms if you republish at scale.
