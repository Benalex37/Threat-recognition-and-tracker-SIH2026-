"""Build the offline world map asset used by the SecOps dashboard.

The dashboard must render a world map with no internet access, so it cannot
pull map tiles or a country-outline GeoJSON from a CDN. Instead we rasterise
the lat/lon of every network in the local MaxMind database into a coarse
density grid and ship that as a small asset. Drawn as a dot matrix it reads as
a recognisable world map ("where the internet lives") and costs ~90 KB.

Output: desktop-app/static/world_grid.json

    {
      "version": 1,
      "lat_step": 0.5, "lon_step": 0.5,
      "cols": 720, "rows": 360,
      "levels": 3,                 # density levels 1..3 (0 = water/empty)
      "data": "<base64 of 2-bit-per-cell grid, row-major from lat +90 down>"
    }

Run:  python scripts/build_world_grid.py
"""

import base64
import json
import os
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

LAT_STEP = 0.5
LON_STEP = 0.5
COLS = int(360 / LON_STEP)  # 720
ROWS = int(180 / LAT_STEP)  # 360

OUT_PATH = BASE_DIR / "static" / "world_grid.json"


def _find_database() -> str:
    """Locate any local MaxMind city database, preferring an explicit path."""
    candidates = [
        os.environ.get("ETD_GEOIP_DB"),
        str(BASE_DIR / "GeoLite2" / "GeoLite2-City.mmdb"),
        str(BASE_DIR / "GeoLite2-City.mmdb"),
    ]
    for path in candidates:
        if path and os.path.exists(path):
            return path
    try:
        from _maxminddb_geolite2 import geolite2_database

        path = geolite2_database()
        if os.path.exists(path):
            return path
    except Exception:
        pass
    raise SystemExit(
        "No MaxMind city database found. Install `maxminddb-geolite2` "
        "(pip install maxminddb-geolite2) or set ETD_GEOIP_DB."
    )


def build_counts(db_path: str) -> list:
    import maxminddb

    counts = [0] * (COLS * ROWS)
    reader = maxminddb.open_database(db_path)
    seen = 0
    placed = 0
    started = time.time()
    for _network, record in reader:
        seen += 1
        if not record:
            continue
        loc = record.get("location") or {}
        lat = loc.get("latitude")
        lon = loc.get("longitude")
        if lat is None or lon is None:
            continue
        col = int((lon + 180.0) / LON_STEP)
        row = int((90.0 - lat) / LAT_STEP)
        if col < 0 or col >= COLS or row < 0 or row >= ROWS:
            continue
        counts[row * COLS + col] += 1
        placed += 1
        if seen % 500000 == 0:
            print(f"  ...{seen:,} networks scanned ({time.time() - started:.0f}s)")
    reader.close()
    print(f"  {seen:,} networks scanned, {placed:,} placed in {time.time() - started:.0f}s")
    return counts


def quantise(counts: list) -> bytes:
    """Collapse raw counts into 2 bits per cell (0=empty, 1..3 = density)."""
    non_zero = sorted(c for c in counts if c > 0)
    if not non_zero:
        raise SystemExit("Database produced no located networks.")
    mid = non_zero[int(len(non_zero) * 0.55)]
    high = non_zero[int(len(non_zero) * 0.88)]
    print(f"  density thresholds: low>=1  mid>={mid}  high>={high}")

    packed = bytearray(len(counts) // 4)
    for idx, count in enumerate(counts):
        if count <= 0:
            continue
        level = 3 if count >= high else (2 if count >= mid else 1)
        packed[idx >> 2] |= level << ((idx & 3) * 2)
    return bytes(packed)


def main() -> None:
    db_path = _find_database()
    print(f"Reading networks from: {db_path}")
    counts = build_counts(db_path)
    packed = quantise(counts)
    land_cells = sum(1 for c in counts if c > 0)

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "version": 1,
        "lat_step": LAT_STEP,
        "lon_step": LON_STEP,
        "cols": COLS,
        "rows": ROWS,
        "levels": 3,
        "cells": land_cells,
        "source": "MaxMind GeoLite2 network density (local, offline)",
        "data": base64.b64encode(packed).decode("ascii"),
    }
    with open(OUT_PATH, "w", encoding="utf-8") as handle:
        json.dump(payload, handle)
    size_kb = OUT_PATH.stat().st_size / 1024
    print(f"Wrote {OUT_PATH} ({size_kb:.0f} KB, {land_cells:,} populated cells)")


if __name__ == "__main__":
    main()
