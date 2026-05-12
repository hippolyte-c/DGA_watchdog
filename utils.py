"""Shared utilities: data loading with reservoir sampling and parquet cache."""

import gzip
import json
import os
import random

import numpy as np
import pandas as pd

DATA_PATH = "data/dga-training-data-encoded.json.gz"
CACHE_PATH = "data/sample_cache.parquet"
RANDOM_STATE = 42
SAMPLE_SIZE = 500_000
TEST_SIZE = 0.2
RESULTS_DIR = "results"
TOTAL_RECORDS = 16_246_014  # known dataset size


def load_sample(
    path: str = DATA_PATH,
    sample_size: int = SAMPLE_SIZE,
    random_state: int = RANDOM_STATE,
    use_cache: bool = True,
) -> pd.DataFrame:
    """Return a balanced (domain, label) DataFrame via per-class reservoir sampling.

    First call reads all 16M records (~60s); subsequent calls load the parquet cache.
    label: 0 = benign, 1 = dga
    """
    if use_cache and os.path.exists(CACHE_PATH):
        print(f"Loading cached sample from {CACHE_PATH}")
        return pd.read_parquet(CACHE_PATH)

    print(f"Streaming {path} — reservoir sampling {sample_size:,} records…")
    rng = random.Random(random_state)
    np.random.seed(random_state)

    target = sample_size // 2
    benign_res: list = []
    dga_res: list = []
    benign_n = 0
    dga_n = 0
    processed = 0

    with gzip.open(path, "rt", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            rec = json.loads(line)
            domain = rec["domain"]
            is_dga = rec["threat"] == "dga"
            processed += 1

            if processed % 2_000_000 == 0:
                pct = processed / TOTAL_RECORDS * 100
                print(f"  {processed:,} / {TOTAL_RECORDS:,} ({pct:.0f}%)")

            if is_dga:
                dga_n += 1
                if len(dga_res) < target:
                    dga_res.append(domain)
                else:
                    j = rng.randint(0, dga_n - 1)
                    if j < target:
                        dga_res[j] = domain
            else:
                benign_n += 1
                if len(benign_res) < target:
                    benign_res.append(domain)
                else:
                    j = rng.randint(0, benign_n - 1)
                    if j < target:
                        benign_res[j] = domain

    print(f"Done. benign={len(benign_res):,}  dga={len(dga_res):,}")

    df = pd.DataFrame(
        [(d, 0) for d in benign_res] + [(d, 1) for d in dga_res],
        columns=["domain", "label"],
    )
    df = df.sample(frac=1, random_state=random_state).reset_index(drop=True)

    os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
    df.to_parquet(CACHE_PATH, index=False)
    print(f"Sample cached → {CACHE_PATH}")

    return df
