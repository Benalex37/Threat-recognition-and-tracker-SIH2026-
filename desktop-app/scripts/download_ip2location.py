"""Install an IP2Location LITE database for offline IP enrichment.

IP2Location LITE is free but the download is behind a personal token, so this
script supports two routes:

  Download (needs the token from https://lite.ip2location.com/file-download):

      set IP2LOCATION_TOKEN=xxxxxxxx
      python scripts/download_ip2location.py

  Import a file you already have (useful on a slow link - fetch the ZIP on any
  machine, copy it across, then):

      python scripts/download_ip2location.py --file C:\\path\\IP2LOCATION-LITE-DB11.CSV.ZIP

Either way the CSV lands in desktop-app/data/geo/ and is compiled into the
binary index the engine memory-maps at startup. The engine keeps working on
the bundled MaxMind database until this succeeds - nothing breaks if you skip
it.

Codes worth knowing:  DB11LITECSV (city + lat/lon, recommended)
                      DB1LITECSV  (country only, smallest)
                      DB11LITEBIN (needs `pip install IP2Location`)
                      DBASNLITE   (ASN + organisation)
"""

import argparse
import os
import shutil
import sys
import time
import urllib.request
import zipfile
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from app.config import GEO_DATA_DIR
from app.services.ip2location import compile_csv

DOWNLOAD_URL = "https://www.ip2location.com/download/?token={token}&file={code}"
DEFAULT_CODE = "DB11LITECSV"


def _human(num_bytes: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if num_bytes < 1024:
            return f"{num_bytes:.0f} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f} TB"


def download(token: str, code: str, destination: Path) -> Path:
    url = DOWNLOAD_URL.format(token=token, code=code)
    target = destination / f"{code}.zip"
    print(f"Downloading {code} -> {target}")
    print("On a slow link this can take a while; the file resumes if you re-run it.")

    existing = target.stat().st_size if target.exists() else 0
    request = urllib.request.Request(url, headers={"User-Agent": "ETD-Engine/1.0"})
    if existing:
        print(f"  resuming from {_human(existing)}")
        request.add_header("Range", f"bytes={existing}-")

    started = time.time()
    downloaded = existing
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            if response.status not in (200, 206):
                raise RuntimeError(f"server returned HTTP {response.status}")
            mode = "ab" if response.status == 206 else "wb"
            if mode == "wb":
                downloaded = 0
            with open(target, mode) as handle:
                while True:
                    chunk = response.read(65536)
                    if not chunk:
                        break
                    handle.write(chunk)
                    downloaded += len(chunk)
                    rate = downloaded / max(time.time() - started, 0.001)
                    print(f"\r  {_human(downloaded)} at {_human(rate)}/s", end="", flush=True)
    except Exception as exc:
        print()
        raise SystemExit(
            f"Download failed: {exc}\n"
            "Check the token, or download the ZIP elsewhere and import it with --file."
        )
    print(f"\n  done in {time.time() - started:.0f}s")
    return target


def extract(archive: Path, destination: Path) -> list:
    """Pull the CSV/BIN members out of a LITE archive."""
    installed = []
    with zipfile.ZipFile(archive) as bundle:
        for member in bundle.namelist():
            upper = member.upper()
            if not upper.endswith((".CSV", ".BIN")):
                continue
            target = destination / Path(member).name
            with bundle.open(member) as source, open(target, "wb") as sink:
                shutil.copyfileobj(source, sink)
            installed.append(target)
            print(f"  extracted {target.name} ({_human(target.stat().st_size)})")
    if not installed:
        raise SystemExit(f"{archive.name} contained no .CSV or .BIN member")
    return installed


def install(paths: list) -> None:
    for path in paths:
        if path.suffix.upper() != ".CSV":
            print(f"  {path.name} is ready (BIN databases need: pip install IP2Location)")
            continue
        index_path = path.with_suffix(".etdidx")
        print(f"  compiling {path.name} -> {index_path.name}")
        started = time.time()
        stats = compile_csv(path, index_path)
        print(f"    {stats['records']:,} ranges indexed in {time.time() - started:.0f}s "
              f"({_human(index_path.stat().st_size)})")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--token", default=os.environ.get("IP2LOCATION_TOKEN", ""),
                        help="IP2Location download token (or set IP2LOCATION_TOKEN)")
    parser.add_argument("--code", default=DEFAULT_CODE, help=f"LITE database code (default {DEFAULT_CODE})")
    parser.add_argument("--file", dest="local_file", help="Install from an already-downloaded ZIP/CSV/BIN")
    args = parser.parse_args()

    GEO_DATA_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Target directory: {GEO_DATA_DIR}\n")

    if args.local_file:
        source = Path(args.local_file).expanduser()
        if not source.exists():
            raise SystemExit(f"No such file: {source}")
        if source.suffix.upper() == ".ZIP":
            install(extract(source, GEO_DATA_DIR))
        else:
            target = GEO_DATA_DIR / source.name
            if source.resolve() != target.resolve():
                shutil.copy2(source, target)
                print(f"  copied {target.name}")
            install([target])
    elif args.token:
        install(extract(download(args.token, args.code, GEO_DATA_DIR), GEO_DATA_DIR))
    else:
        raise SystemExit(
            "No token and no --file.\n\n"
            "  1. Sign up free at https://lite.ip2location.com/\n"
            "  2. Copy your download token\n"
            "  3. set IP2LOCATION_TOKEN=your_token  (then re-run this script)\n\n"
            "Or download IP2LOCATION-LITE-DB11.CSV.ZIP on any machine and run:\n"
            "  python scripts/download_ip2location.py --file <path-to-zip>\n\n"
            "The engine already geolocates offline using the bundled MaxMind "
            "database, so this is an upgrade rather than a requirement."
        )

    print("\nRestart the engine to pick up the new database.")
    print("Verify at:  http://127.0.0.1:8001/api/geo/status")


if __name__ == "__main__":
    main()
