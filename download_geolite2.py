"""Download the GeoLite2 City database for offline IP geolocation.

MaxMind now requires a license key for GeoLite2 downloads. Set the
`MAXMIND_LICENSE_KEY` environment variable (free at https://www.maxmind.com/en/geoip-databases)
and run this script to fetch the database into desktop-app/GeoLite2/.

Usage:
    python download_geolite2.py
"""
import os
import sys
import tarfile
import urllib.request
from pathlib import Path

LICENSE_KEY = os.environ.get("MAXMIND_LICENSE_KEY", "")
DB_DIR = Path(__file__).resolve().parent.parent / "desktop-app" / "GeoLite2"
DB_DIR.mkdir(parents=True, exist_ok=True)

URL = (
    f"https://download.maxmind.com/download/geoip/database/geoip2-city/"
    f"GeoLite2-City_20250101.tar.gz"
)
if LICENSE_KEY:
    URL += f"?license_key={LICENSE_KEY}"

print("Downloading:", URL)
print("Target dir:", DB_DIR)

try:
    tar_path = DB_DIR / "geolite.tar.gz"
    urllib.request.urlretrieve(URL, str(tar_path))
    with tarfile.open(str(tar_path), "r:gz") as tar:
        for member in tar.getmembers():
            if member.name.endswith("GeoLite2-City.mmdb"):
                tar.extract(member, path=DB_DIR)
                extracted = DB_DIR / member.name
                final = DB_DIR / "GeoLite2-City.mmdb"
                if extracted != final:
                    extracted.rename(final)
                print("Extracted:", final)
                break
    tar_path.unlink(missing_ok=True)
    print("Done. Set ETD_GEOIP_DB or place the .mmdb in desktop-app/GeoLite2/")
except Exception as e:
    print("Failed:", e)
    sys.exit(1)