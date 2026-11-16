# Email Threat Detection Local Engine

FastAPI desktop app for locally-run email fraud detection.

## Run

```bash
python run.py
```

Server starts at `http://127.0.0.1:8000`.

## Endpoints

- `GET /health`
- `POST /api/analyze`
- `POST /api/badge-score`
- `GET /api/config`
- `GET /api/stats/today`
- `POST /api/categories`
- `GET /oauth/gmail/start`
- `POST /oauth/gmail/complete`
- `GET /oauth/admin/start`
- `POST /oauth/admin/complete`
- `GET /dashboard`

---

## Offline IP intelligence (IP2Location LITE)

IP geolocation, ASN and hosting/proxy checks are answered from **local
databases**. The old `ip-api.com` calls are gone from the default path — they
cost three 5-second network round trips per email and failed outright on a
slow link.

Resolution order (first hit wins), reported at `/api/geo/status`:

1. **IP2Location LITE BIN** — official `.BIN` via `pip install IP2Location`
2. **IP2Location LITE CSV** — DB1/DB3/DB5/DB9/DB11 exports, compiled once into
   a memory-mapped binary index (`*.etdidx`) for instant startup
3. **MaxMind city database** — a local `.mmdb`, including the one bundled with
   `maxminddb-geolite2`, so a fresh install geolocates with no setup
4. **Reserved-range table** — private/loopback space, answered without any DB

Databases are read from `desktop-app/data/geo/`, `desktop-app/GeoLite2/`, or
the path in `ETD_IP2LOCATION_DB` / `ETD_GEOIP_DB`.

### Installing IP2Location LITE

```
# with a free token from https://lite.ip2location.com/
set IP2LOCATION_TOKEN=your_token
python scripts/download_ip2location.py

# or, on a slow link, download the ZIP anywhere and import it
python scripts/download_ip2location.py --file C:\path\IP2LOCATION-LITE-DB11.CSV.ZIP
```

Online lookups stay off unless `allow_online_lookups` is set to `true` in
`data/config.json`. DNS and WHOIS remain enabled but are cached and bounded by
`dns_timeout_seconds` / `whois_timeout_seconds`.

## SecOps dashboard

`http://127.0.0.1:<port>/dashboard` — no CDN, no tile server, no webfonts. The
basemap is a dot grid built from the local IP database:

```
python scripts/build_world_grid.py        # regenerates static/world_grid.json
```

Every map encoding is documented in the on-page legend. Data comes from
`/api/cases`, which the page polls every 15 seconds.

## Ports

`run.py` uses `local_port` from `data/config.json` (default **8001**).
`ETD_PORT` overrides it for a one-off run. The browser extension discovers the
port automatically, probing 8001, 8000, 8010 and 8080.
