#!/usr/bin/env python3
"""Flatten data/leaderboard.json into data/leaderboard.csv — every field kept.

Columns = all model metadata keys (union across models, stable order) followed
by one column per benchmark slug from the nested `scores` object. New benchmark
columns appear automatically as the site adds them; nothing is dropped.
"""

import csv
import json

# Preferred leading order; any other metadata key is appended alphabetically.
LEAD = [
    "displayName", "name", "shortName", "slug", "creator", "modelCreatorName",
    "intelligenceIndex", "intelligenceIndexIsEstimated", "intelligenceIndexCostPerTask",
    "omniscience", "isReasoning", "isOpenWeights", "deprecated", "paramClass",
    "priceClass", "contextWindowTokens",
    "price1mInputTokens", "price1mOutputTokens", "cacheHitPrice", "cacheWritePrice",
    "medianOutputTokensPerSecond", "medianTimeToFirstTokenSeconds",
    "medianEndToEndResponseTimeSeconds", "medianReasoningTimeSeconds",
    "percentile05OutputTokensPerSecond", "percentile95OutputTokensPerSecond",
    "quartile25OutputTokensPerSecond", "quartile75OutputTokensPerSecond",
    "benchmarkCount",
]
EXCLUDE = {"scores"}


def main() -> None:
    data = json.load(open("data/leaderboard.json"))
    models = data["models"]

    meta, bench = set(), set()
    for m in models:
        meta.update(k for k in m if k not in EXCLUDE)
        bench.update(m.get("scores") or {})

    cols = [c for c in LEAD if c in meta]
    cols += sorted(meta - set(cols))
    cols += sorted(bench)

    with open("data/leaderboard.csv", "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(cols)
        for m in models:
            scores = m.get("scores") or {}
            w.writerow(
                ["" if (v := (m.get(c) if c in meta else scores.get(c))) is None else v
                 for c in cols]
            )
    print(f"wrote data/leaderboard.csv: {len(models)} rows x {len(cols)} cols")


if __name__ == "__main__":
    main()
