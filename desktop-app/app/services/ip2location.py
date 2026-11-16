"""Offline IP intelligence backed by IP2Location LITE.

The engine runs on machines with poor or no connectivity, so IP enrichment
must never depend on a web API. Lookups walk a chain of local sources and
stop at the first hit:

  1. IP2Location LITE BIN  - the official .BIN read through the `IP2Location`
     package, when both the package and a database file are present.
  2. IP2Location LITE CSV  - any DB1/DB3/DB5/DB9/DB11 CSV export. The CSV is
     compiled once into a compact binary index (``*.etdidx``) that is then
     memory-mapped and binary-searched, so later starts are instant and RAM
     stays flat regardless of database size.
  3. MaxMind city database - a local .mmdb, including the one bundled with the
     `maxminddb-geolite2` package, so a fresh install still resolves IPs.
  4. Reserved-range table  - private/loopback/multicast space, answered
     without touching any database.

A web API is consulted only when the operator explicitly opts in by setting
``allow_online_lookups`` in config.json; it is off by default.

Databases are discovered in desktop-app/GeoLite2/ and desktop-app/data/geo/,
or at the path named by the ETD_IP2LOCATION_DB / ETD_GEOIP_DB variables.
Use ``python scripts/download_ip2location.py`` to fetch a LITE database.
"""

from __future__ import annotations

import csv
import ipaddress
import logging
import mmap
import os
import struct
import threading
import time
from pathlib import Path
from typing import Optional

logger = logging.getLogger("etd.ip2location")

BASE_DIR = Path(__file__).resolve().parent.parent.parent
GEO_DIRS = [BASE_DIR / "data" / "geo", BASE_DIR / "GeoLite2", BASE_DIR]

_MAGIC = b"ETDGEOIX"
_INDEX_VERSION = 1
_KIND_GEO = 1
_KIND_ASN = 2
_GEO_REC = struct.Struct("<IIHHIhh")   # from, to, country, region, city, lat*100, lon*100
_ASN_REC = struct.Struct("<IIII")      # from, to, asn, org
_HEADER = struct.Struct("<8sHHIQ")     # magic, version, kind, count, strings_offset

# Networks that never need a database lookup.
_RESERVED = [
    ("0.0.0.0/8", "this network"),
    ("10.0.0.0/8", "private network"),
    ("100.64.0.0/10", "carrier-grade NAT"),
    ("127.0.0.0/8", "loopback"),
    ("169.254.0.0/16", "link-local"),
    ("172.16.0.0/12", "private network"),
    ("192.0.2.0/24", "documentation"),
    ("192.168.0.0/16", "private network"),
    ("198.18.0.0/15", "benchmarking"),
    ("224.0.0.0/4", "multicast"),
    ("240.0.0.0/4", "reserved"),
]
_RESERVED_NETS = [(ipaddress.ip_network(cidr), label) for cidr, label in _RESERVED]

# Organisation-name fragments that mark an address as datacentre / proxy space
# rather than a residential or corporate mail sender.
_HOSTING_TOKENS = (
    "hosting", "host", "server", "datacenter", "data center", "colo", "cloud",
    "vps", "dedicated", "amazon", "aws", "azure", "microsoft", "google",
    "digitalocean", "digital ocean", "linode", "vultr", "ovh", "hetzner",
    "contabo", "scaleway", "leaseweb", "alibaba", "tencent", "oracle",
    "cloudflare", "fastly", "akamai", "choopa", "quadranet", "psychz",
)
_PROXY_TOKENS = ("vpn", "proxy", "tor ", "tor-", "torservers", "tunnel", "anonymi", "relay")


def _ip_to_int(ip: str) -> Optional[int]:
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return None
    return int(addr) if addr.version == 4 else None


def _reserved_label(ip: str) -> Optional[str]:
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return None
    for net, label in _RESERVED_NETS:
        if addr.version == net.version and addr in net:
            return label
    return None


# --------------------------------------------------------------------------
# Binary index: build + read
# --------------------------------------------------------------------------

class _StringTable:
    def __init__(self):
        self._items: list[str] = []
        self._index: dict[str, int] = {}
        self.intern("")

    def intern(self, value: str) -> int:
        value = (value or "").strip()
        if value in ("-", "Invalid IP address", "Not Supported"):
            value = ""
        idx = self._index.get(value)
        if idx is None:
            idx = len(self._items)
            self._items.append(value)
            self._index[value] = idx
        return idx

    def encode(self) -> bytes:
        out = bytearray(struct.pack("<I", len(self._items)))
        for item in self._items:
            raw = item.encode("utf-8")[:65535]
            out += struct.pack("<H", len(raw)) + raw
        return bytes(out)


def _detect_layout(row: list) -> Optional[dict]:
    """Work out which IP2Location LITE export a CSV row came from."""
    width = len(row)
    if width >= 5 and "/" in str(row[2]):
        return {"kind": _KIND_ASN, "asn": 3, "org": 4}
    if width == 4:
        return {"kind": _KIND_GEO, "country": 2, "region": None, "city": None, "lat": None, "lon": None}
    if width == 6:
        return {"kind": _KIND_GEO, "country": 2, "region": 4, "city": 5, "lat": None, "lon": None}
    if width >= 8:
        return {"kind": _KIND_GEO, "country": 2, "region": 4, "city": 5, "lat": 6, "lon": 7}
    return None


def _quantise(value: str, limit: int) -> int:
    try:
        scaled = int(round(float(value) * 100))
    except (TypeError, ValueError):
        return -32768
    return max(-limit, min(limit, scaled))


def compile_csv(csv_path: Path, index_path: Path) -> dict:
    """Compile an IP2Location LITE CSV into a memory-mappable binary index."""
    strings = _StringTable()
    records = bytearray()
    layout = None
    count = 0
    skipped = 0

    with open(csv_path, "r", encoding="utf-8", errors="replace", newline="") as handle:
        for row in csv.reader(handle):
            if not row or len(row) < 4:
                continue
            if layout is None:
                layout = _detect_layout(row)
                if layout is None:
                    raise ValueError(f"Unrecognised IP2Location CSV layout ({len(row)} columns)")
            try:
                ip_from = int(row[0])
                ip_to = int(row[1])
            except (TypeError, ValueError):
                skipped += 1   # header row, or an IPv6 export we cannot index
                continue
            if ip_from > 0xFFFFFFFF or ip_to > 0xFFFFFFFF:
                skipped += 1
                continue

            if layout["kind"] == _KIND_ASN:
                try:
                    asn = int(str(row[layout["asn"]]).strip() or 0)
                except (TypeError, ValueError):
                    asn = 0
                records += _ASN_REC.pack(ip_from, ip_to, asn, strings.intern(row[layout["org"]]))
            else:
                def cell(key):
                    pos = layout[key]
                    return row[pos] if pos is not None and pos < len(row) else ""

                records += _GEO_REC.pack(
                    ip_from,
                    ip_to,
                    strings.intern(cell("country")),
                    strings.intern(cell("region")),
                    strings.intern(cell("city")),
                    _quantise(cell("lat"), 9000),
                    _quantise(cell("lon"), 18000),
                )
            count += 1

    if not count:
        raise ValueError(f"No usable rows found in {csv_path.name}")

    header_size = _HEADER.size
    strings_offset = header_size + len(records)
    index_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = index_path.with_suffix(index_path.suffix + ".tmp")
    with open(tmp_path, "wb") as handle:
        handle.write(_HEADER.pack(_MAGIC, _INDEX_VERSION, layout["kind"], count, strings_offset))
        handle.write(records)
        handle.write(strings.encode())
    os.replace(tmp_path, index_path)
    return {"records": count, "skipped": skipped, "kind": layout["kind"]}


class _BinaryIndex:
    """Memory-mapped, binary-searched view over a compiled index."""

    def __init__(self, path: Path):
        self.path = path
        self._file = open(path, "rb")
        self._map = mmap.mmap(self._file.fileno(), 0, access=mmap.ACCESS_READ)
        magic, version, kind, count, strings_offset = _HEADER.unpack_from(self._map, 0)
        if magic != _MAGIC or version != _INDEX_VERSION:
            raise ValueError(f"{path.name} is not an ETD geo index")
        self.kind = kind
        self.count = count
        self._rec = _ASN_REC if kind == _KIND_ASN else _GEO_REC
        self._base = _HEADER.size
        self._strings = self._read_strings(strings_offset)
        self._lock = threading.Lock()

    def _read_strings(self, offset: int) -> list[str]:
        (total,) = struct.unpack_from("<I", self._map, offset)
        pos = offset + 4
        items = []
        for _ in range(total):
            (length,) = struct.unpack_from("<H", self._map, pos)
            pos += 2
            items.append(self._map[pos:pos + length].decode("utf-8", "replace"))
            pos += length
        return items

    def _row(self, idx: int) -> tuple:
        return self._rec.unpack_from(self._map, self._base + idx * self._rec.size)

    def find(self, ip_int: int) -> Optional[tuple]:
        low, high, hit = 0, self.count - 1, None
        while low <= high:
            mid = (low + high) // 2
            row = self._row(mid)
            if row[0] > ip_int:
                high = mid - 1
            else:
                hit = row
                low = mid + 1
        if hit is None or ip_int > hit[1]:
            return None
        return hit

    def text(self, idx: int) -> str:
        return self._strings[idx] if 0 <= idx < len(self._strings) else ""

    def close(self) -> None:
        with self._lock:
            try:
                self._map.close()
            finally:
                self._file.close()


# --------------------------------------------------------------------------
# Provider discovery
# --------------------------------------------------------------------------

def _candidate_files(patterns: tuple) -> list[Path]:
    found = []
    for directory in GEO_DIRS:
        if not directory.exists():
            continue
        for entry in sorted(directory.iterdir()):
            if not entry.is_file():
                continue
            name = entry.name.upper()
            if any(name.endswith(suffix) for suffix in patterns):
                found.append(entry)
    return found


class GeoResolver:
    """Lazily-initialised chain of local IP databases."""

    def __init__(self):
        self._ready = False
        self._lock = threading.Lock()
        self._bin_reader = None          # IP2Location .BIN reader
        self._bin_path = None
        self._geo_index: Optional[_BinaryIndex] = None
        self._geo_source = None
        self._asn_index: Optional[_BinaryIndex] = None
        self._asn_source = None
        self._mmdb = None
        self._mmdb_path = None
        self._notes: list[str] = []
        self._cache: dict[str, Optional[dict]] = {}
        self._cache_order: list[str] = []

    # -- setup ------------------------------------------------------------
    def ensure_ready(self) -> None:
        if self._ready:
            return
        with self._lock:
            if self._ready:
                return
            self._load_ip2location_bin()
            self._load_ip2location_csv()
            self._load_mmdb()
            self._ready = True

    def _load_ip2location_bin(self) -> None:
        explicit = os.environ.get("ETD_IP2LOCATION_DB")
        paths = [Path(explicit)] if explicit else []
        paths += [p for p in _candidate_files((".BIN",)) if "IP2LOCATION" in p.name.upper()]
        paths = [p for p in paths if p.exists()]
        if not paths:
            return
        try:
            import IP2Location  # type: ignore
        except ImportError:
            self._notes.append(
                f"Found {paths[0].name} but the IP2Location package is missing "
                "(pip install IP2Location); using the CSV/MaxMind tiers instead."
            )
            return
        try:
            self._bin_reader = IP2Location.IP2Location(str(paths[0]))
            self._bin_path = paths[0]
            logger.info("IP2Location LITE BIN loaded: %s", paths[0])
        except Exception as exc:
            self._notes.append(f"Could not open {paths[0].name}: {exc}")

    def _load_ip2location_csv(self) -> None:
        for csv_path in _candidate_files((".CSV",)):
            name = csv_path.name.upper()
            if "IP2LOCATION" not in name and "IP2PROXY" not in name:
                continue
            is_asn = "ASN" in name
            if is_asn and self._asn_index is not None:
                continue
            if not is_asn and self._geo_index is not None:
                continue
            index_path = csv_path.with_suffix(".etdidx")
            try:
                if (not index_path.exists()
                        or index_path.stat().st_mtime < csv_path.stat().st_mtime):
                    logger.info("Compiling %s -> %s (one time)", csv_path.name, index_path.name)
                    stats = compile_csv(csv_path, index_path)
                    logger.info("Compiled %s records from %s", stats["records"], csv_path.name)
                index = _BinaryIndex(index_path)
            except Exception as exc:
                self._notes.append(f"Could not use {csv_path.name}: {exc}")
                continue
            if index.kind == _KIND_ASN:
                self._asn_index, self._asn_source = index, csv_path.name
            else:
                self._geo_index, self._geo_source = index, csv_path.name
            logger.info("IP2Location LITE CSV ready: %s (%s ranges)", csv_path.name, index.count)

    def _load_mmdb(self) -> None:
        try:
            import maxminddb
        except ImportError:
            return
        candidates = []
        explicit = os.environ.get("ETD_GEOIP_DB")
        if explicit:
            candidates.append(Path(explicit))
        candidates += _candidate_files((".MMDB",))
        try:
            from _maxminddb_geolite2 import geolite2_database

            candidates.append(Path(geolite2_database()))
        except Exception:
            pass
        for path in candidates:
            if not path or not path.exists():
                continue
            try:
                self._mmdb = maxminddb.open_database(str(path))
                self._mmdb_path = path
                logger.info("MaxMind city database loaded: %s", path)
                return
            except Exception as exc:
                self._notes.append(f"Could not open {path.name}: {exc}")

    # -- lookups ----------------------------------------------------------
    def locate(self, ip: str) -> Optional[dict]:
        if not ip:
            return None
        if ip in self._cache:
            return self._cache[ip]
        self.ensure_ready()
        result = self._locate_uncached(ip)
        self._remember(ip, result)
        return result

    def _remember(self, ip: str, result: Optional[dict]) -> None:
        self._cache[ip] = result
        self._cache_order.append(ip)
        if len(self._cache_order) > 4096:
            oldest = self._cache_order.pop(0)
            self._cache.pop(oldest, None)

    def _locate_uncached(self, ip: str) -> Optional[dict]:
        reserved = _reserved_label(ip)
        if reserved:
            return {
                "country": "", "country_name": "", "region": "", "city": "",
                "lat": None, "lon": None, "source": "reserved-range",
                "precision": "none", "note": reserved, "is_private": True,
            }
        ip_int = _ip_to_int(ip)

        if self._bin_reader is not None:
            found = self._from_bin(ip)
            if found:
                return found
        if self._geo_index is not None and ip_int is not None:
            found = self._from_index(ip_int)
            if found:
                return found
        if self._mmdb is not None:
            found = self._from_mmdb(ip)
            if found:
                return found
        return None

    def _from_bin(self, ip: str) -> Optional[dict]:
        try:
            rec = self._bin_reader.get_all(ip)
        except Exception as exc:
            logger.debug("IP2Location BIN lookup failed for %s: %s", ip, exc)
            return None
        if rec is None:
            return None
        country = (getattr(rec, "country_short", "") or "").strip()
        if not country or country in ("-", "Invalid IP address"):
            return None
        lat = getattr(rec, "latitude", None)
        lon = getattr(rec, "longitude", None)
        return self._shape(
            country=country,
            country_name=getattr(rec, "country_long", "") or "",
            region=getattr(rec, "region", "") or "",
            city=getattr(rec, "city", "") or "",
            lat=lat, lon=lon,
            source="ip2location-lite-bin",
            detail=self._bin_path.name if self._bin_path else "",
        )

    def _from_index(self, ip_int: int) -> Optional[dict]:
        row = self._geo_index.find(ip_int)
        if row is None:
            return None
        _, _, country_idx, region_idx, city_idx, lat_q, lon_q = row
        country = self._geo_index.text(country_idx)
        if not country:
            return None
        return self._shape(
            country=country,
            country_name="",
            region=self._geo_index.text(region_idx),
            city=self._geo_index.text(city_idx),
            lat=None if lat_q == -32768 else lat_q / 100.0,
            lon=None if lon_q == -32768 else lon_q / 100.0,
            source="ip2location-lite-csv",
            detail=self._geo_source or "",
        )

    def _from_mmdb(self, ip: str) -> Optional[dict]:
        try:
            rec = self._mmdb.get(ip)
        except Exception as exc:
            logger.debug("MaxMind lookup failed for %s: %s", ip, exc)
            return None
        if not rec:
            return None
        country_block = rec.get("country") or rec.get("registered_country") or {}
        subdivisions = rec.get("subdivisions") or []
        location = rec.get("location") or {}
        return self._shape(
            country=country_block.get("iso_code", "") or "",
            country_name=(country_block.get("names") or {}).get("en", "") or "",
            region=((subdivisions[-1].get("names") or {}).get("en", "") if subdivisions else ""),
            city=((rec.get("city") or {}).get("names") or {}).get("en", "") or "",
            lat=location.get("latitude"),
            lon=location.get("longitude"),
            source="maxmind-local",
            detail=self._mmdb_path.name if self._mmdb_path else "",
        )

    @staticmethod
    def _shape(country, country_name, region, city, lat, lon, source, detail) -> dict:
        try:
            lat = float(lat) if lat is not None else None
            lon = float(lon) if lon is not None else None
        except (TypeError, ValueError):
            lat = lon = None
        if lat is not None and (lat == 0.0 and lon == 0.0):
            lat = lon = None
        precision = "city" if (city and lat is not None) else ("country" if lat is not None else "none")
        return {
            "country": (country or "").upper()[:2],
            "country_name": country_name or "",
            "region": region or "",
            "city": city or "",
            "lat": lat,
            "lon": lon,
            "source": source,
            "database": detail,
            "precision": precision,
            "is_private": False,
        }

    def asn(self, ip: str) -> dict:
        """ASN / organisation for an IP, from local data only."""
        empty = {"asn": None, "asn_org": "", "source": "unavailable"}
        if not ip:
            return empty
        self.ensure_ready()
        ip_int = _ip_to_int(ip)
        if self._asn_index is not None and ip_int is not None:
            row = self._asn_index.find(ip_int)
            if row is not None:
                return {
                    "asn": row[2] or None,
                    "asn_org": self._asn_index.text(row[3]),
                    "source": "ip2location-lite-asn",
                }
        if self._bin_reader is not None:
            try:
                rec = self._bin_reader.get_all(ip)
                asn_value = getattr(rec, "asn", None)
                org = getattr(rec, "as_name", None) or getattr(rec, "as", None) or ""
                if asn_value or org:
                    return {
                        "asn": int(asn_value) if str(asn_value or "").isdigit() else None,
                        "asn_org": str(org or ""),
                        "source": "ip2location-lite-bin",
                    }
            except Exception:
                pass
        if self._mmdb is not None:
            try:
                rec = self._mmdb.get(ip) or {}
                traits = rec.get("traits") or {}
                org = traits.get("autonomous_system_organization") or rec.get("autonomous_system_organization")
                number = traits.get("autonomous_system_number") or rec.get("autonomous_system_number")
                if org or number:
                    return {"asn": number, "asn_org": org or "", "source": "maxmind-local"}
            except Exception:
                pass
        return empty

    def classify(self, ip: str) -> dict:
        """Hosting / proxy classification derived from local data only."""
        info = self.asn(ip)
        org = (info.get("asn_org") or "").lower()
        geo = self.locate(ip) or {}
        hosting = any(token in org for token in _HOSTING_TOKENS)
        proxy = any(token in org for token in _PROXY_TOKENS)
        if geo.get("is_private"):
            hosting = proxy = False
        return {
            "asn": info.get("asn"),
            "asn_org": info.get("asn_org", ""),
            "is_hosting": hosting,
            "is_proxy": proxy,
            "source": info.get("source", "unavailable"),
        }

    # -- reporting --------------------------------------------------------
    def status(self) -> dict:
        self.ensure_ready()
        providers = []
        if self._bin_reader is not None:
            providers.append({
                "tier": 1, "name": "IP2Location LITE (BIN)", "active": True,
                "detail": self._bin_path.name if self._bin_path else "",
            })
        if self._geo_index is not None:
            providers.append({
                "tier": 2, "name": "IP2Location LITE (CSV index)",
                "active": self._bin_reader is None,
                "detail": f"{self._geo_source} · {self._geo_index.count:,} ranges",
            })
        if self._asn_index is not None:
            providers.append({
                "tier": 2, "name": "IP2Location LITE ASN", "active": True,
                "detail": f"{self._asn_source} · {self._asn_index.count:,} ranges",
            })
        if self._mmdb is not None:
            providers.append({
                "tier": 3, "name": "MaxMind city database (local)",
                "active": self._bin_reader is None and self._geo_index is None,
                "detail": self._mmdb_path.name if self._mmdb_path else "",
            })
        active = next((p["name"] for p in providers if p["active"]), None)
        return {
            "ready": bool(providers),
            "offline": True,
            "activeProvider": active or "none",
            "providers": providers,
            "notes": list(self._notes),
            "searchPaths": [str(d) for d in GEO_DIRS],
            "cacheSize": len(self._cache),
        }


_resolver = GeoResolver()


def locate(ip: str) -> Optional[dict]:
    return _resolver.locate(ip)


def asn_info(ip: str) -> dict:
    return _resolver.asn(ip)


def classify(ip: str) -> dict:
    return _resolver.classify(ip)


def status() -> dict:
    return _resolver.status()
