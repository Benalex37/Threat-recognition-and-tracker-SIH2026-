"""Header forensics and sender reputation features.

IP enrichment (geolocation, ASN, hosting/proxy classification) is served from
local IP2Location LITE / MaxMind databases via `app.services.ip2location`, so
analysis stays fast and complete on a poor link. The web API that used to back
these features is now opt-in: set "allow_online_lookups": true in
desktop-app/data/config.json to re-enable it.

DNS and WHOIS still go out to the network because SPF/DKIM/DMARC and domain
age cannot be answered locally, but both are cached and bounded by a timeout
so a slow link degrades the result instead of stalling the request.
"""

import logging
import re
import threading
import time
from typing import Optional

import dns.resolver
import dns.reversename

from app.services import ip2location

logger = logging.getLogger("etd.forensics")

_DNS_CACHE = {}
_DNS_CACHE_TTL = 3600
_WHOIS_CACHE = {}
_WHOIS_CACHE_TTL = 86400
_CACHE_LOCK = threading.Lock()

_SETTINGS_TTL = 30
_settings_cache = {"at": 0.0, "value": None}

_DEFAULT_SETTINGS = {
    "allow_online_lookups": False,
    "enable_dns_lookups": True,
    "enable_whois_lookups": True,
    "dns_timeout_seconds": 3.0,
    "whois_timeout_seconds": 6.0,
}


def _settings() -> dict:
    """Config values that govern outbound lookups, re-read at most every 30s."""
    now = time.time()
    if _settings_cache["value"] is not None and now - _settings_cache["at"] < _SETTINGS_TTL:
        return _settings_cache["value"]
    values = dict(_DEFAULT_SETTINGS)
    try:
        from app.config import load_config

        config = load_config()
        for key in values:
            if key in config:
                values[key] = config[key]
    except Exception as exc:
        logger.debug("Falling back to default lookup settings: %s", exc)
    _settings_cache.update({"at": now, "value": values})
    return values


def _cache_get(cache, key):
    with _CACHE_LOCK:
        entry = cache.get(key)
        if entry and time.time() - entry["t"] < entry["ttl"]:
            return entry["v"]
    return None


def _cache_set(cache, key, value, ttl):
    with _CACHE_LOCK:
        cache[key] = {"t": time.time(), "v": value, "ttl": ttl}


def _call_with_timeout(func, timeout, *args):
    """Run a blocking network call with a hard wall-clock ceiling."""
    box = {}

    def target():
        try:
            box["value"] = func(*args)
        except Exception as exc:
            box["error"] = exc

    worker = threading.Thread(target=target, daemon=True)
    worker.start()
    worker.join(timeout)
    if worker.is_alive():
        logger.debug("%s timed out after %.1fs", getattr(func, "__name__", func), timeout)
        return None
    if "error" in box:
        return None
    return box.get("value")


def _resolver() -> dns.resolver.Resolver:
    timeout = float(_settings()["dns_timeout_seconds"])
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    return resolver


def _resolve_txt(name: str) -> list:
    """Cached TXT lookup that returns [] rather than raising on any failure."""
    if not _settings()["enable_dns_lookups"]:
        return []
    cached = _cache_get(_DNS_CACHE, name)
    if cached is not None:
        return cached
    records = []
    try:
        answers = _resolver().resolve(name, "TXT")
        records = [str(rdata).strip('"') for rdata in answers]
    except Exception as exc:
        logger.debug("TXT lookup failed for %s: %s", name, exc)
    _cache_set(_DNS_CACHE, name, records, _DNS_CACHE_TTL)
    return records


_IP_RE = re.compile(r"([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})")
_SANCTIONED_COUNTRIES = {"RU", "CN", "KP", "IR", "SY"}
_EXPECTED_GEO_COUNTRIES = {
    "US", "CA", "GB", "AU", "DE", "FR", "NL", "SG", "JP", "KR", "CH", "SE",
    "NO", "DK", "FI", "IE", "PL", "CZ", "AT", "BE", "MX", "BR", "IN",
}


def geolocate_ip(ip: str) -> Optional[dict]:
    """Resolve an IP to {country, region, city, lat, lon} from local databases."""
    if not ip:
        return None
    result = ip2location.locate(ip)
    if result:
        return result
    if _settings()["allow_online_lookups"]:
        return _geolocate_online(ip)
    return None


def _geolocate_online(ip: str) -> Optional[dict]:
    """Last-resort web lookup. Only reached when the operator opts in."""
    try:
        import requests

        response = requests.get(
            f"http://ip-api.com/json/{ip}"
            "?fields=status,country,countryCode,regionName,city,lat,lon,org,as",
            timeout=5,
        )
        data = response.json()
        if data.get("status") != "success":
            return None
        return {
            "country": data.get("countryCode", ""),
            "country_name": data.get("country", ""),
            "region": data.get("regionName", ""),
            "city": data.get("city", ""),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "source": "ip-api.com",
            "database": "online",
            "precision": "city",
            "is_private": False,
        }
    except Exception as exc:
        logger.debug("Online geolocation failed for %s: %s", ip, exc)
        return None


def normalize_headers(raw_headers: dict) -> dict:
    """Lower-case the header names and group repeated ones.

    RFC 5322 field names are case-insensitive, and real mail capitalises them
    (`Received`, `Authentication-Results`). The lookups here used to be
    case-sensitive, so a genuine header block produced relay_hop_count 0 and no
    sender IP — the engine was scoring every message as if it had no headers.
    """
    normalized: dict = {}
    for key, value in (raw_headers or {}).items():
        low = str(key).strip().lower()
        if low == "received":
            existing = normalized.setdefault("received", [])
            existing.extend(value if isinstance(value, list) else [value])
        else:
            normalized[low] = value
    return normalized


def parse_headers(raw_headers: dict) -> dict:
    result = {
        "received": [],
        "authentication_results": "",
        "spf": None,
        "dkim": None,
        "dmarc": None,
    }
    for key, value in raw_headers.items():
        low = key.lower()
        if low == "received":
            result["received"].append(value)
        elif low == "authentication-results":
            result["authentication_results"] = value
            lowered = value.lower()
            if "spf=pass" in lowered:
                result["spf"] = "pass"
            elif "spf=fail" in lowered:
                result["spf"] = "fail"
            elif "spf=softfail" in lowered:
                result["spf"] = "softfail"
            if "dkim=pass" in lowered:
                result["dkim"] = "pass"
            elif "dkim=fail" in lowered:
                result["dkim"] = "fail"
            if "dmarc=pass" in lowered:
                result["dmarc"] = "pass"
            elif "dmarc=fail" in lowered:
                result["dmarc"] = "fail"
    return result


def extract_trust_boundary_ip(headers: dict) -> Optional[str]:
    ar = headers.get("authentication-results", "")
    if ar:
        match = re.search(r"ip[=:]\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})", ar, re.IGNORECASE)
        if match:
            return match.group(1)
    received = headers.get("received", [])
    if isinstance(received, str):
        received = [received]
    if received:
        for hop in received:
            match = re.search(
                r"from\s+\S+\s+\([^)]*\s+([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})",
                hop, re.IGNORECASE,
            )
            if match:
                return match.group(1)
        for hop in received:
            match = _IP_RE.search(hop or "")
            if match:
                return match.group(1)
    return None


def dns_spf_lookup(domain: str) -> bool:
    for txt in _resolve_txt(domain):
        if txt.startswith("v=spf1"):
            return True
    return False


_DKIM_SELECTORS = {
    "google.com": ["google"],
    "googlemail.com": ["google"],
    "gmail.com": ["google"],
    "microsoft.com": ["selector1", "selector2", "selector3", "default"],
    "outlook.com": ["selector1", "selector2", "default"],
    "hotmail.com": ["selector1", "selector2", "default"],
    "amazon.com": ["amazonses", "default"],
    "amazon.co.uk": ["amazonses", "default"],
    "amazon.de": ["amazonses", "default"],
    "sendgrid.net": ["s1", "default"],
    "mailgun.org": ["default", "s1"],
    "mailchimp.com": ["k1", "default"],
    "stripe.com": ["stripe", "default"],
    "intercom.com": ["intercom", "default"],
}

_DEFAULT_DKIM_SELECTORS = ["default", "selector1", "selector2", "s1", "s2"]

_KNOWN_GOOD_DOMAINS = {
    "google.com", "googlemail.com", "gmail.com", "google.co.uk",
    "microsoft.com", "outlook.com", "hotmail.com", "live.com", "msn.com",
    "amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.ca",
    "netflix.com", "accounts.google.com",
    "indeed.com", "match.indeed.com",
    "wondershare.com", "mail-service.wondershare.com",
    "sendgrid.net", "mailgun.org",
    "github.com", "gitlab.com", "stackoverflow.com",
    "stripe.com", "shopify.com",
    "salesforce.com", "sfdc.net", "force.com",
    "atlassian.com", "slack.com",
    "zendesk.com", "hubspot.com", "typeform.com", "airtable.com",
    "notion.so", "notion.com", "linear.app", "figma.com",
    "trello.com", "dropbox.com", "box.com",
    "okta.com", "okta.net", "zoom.us", "webex.com", "teams.microsoft.com",
    "linkedin.com", "paypal.com", "etsy.com",
    "fastmail.com", "protonmail.com",
}


def _parent_domains(domain: str) -> list:
    parts = domain.split(".")
    return [".".join(parts[i:]) for i in range(1, len(parts))]


def dns_dkim_lookup(domain: str) -> bool:
    """Probe DKIM selectors, newest-first, within a single time budget.

    Every selector miss costs a full DNS round trip, so the whole probe shares
    one budget instead of letting a slow link multiply out to 25 queries.
    """
    if domain in _KNOWN_GOOD_DOMAINS:
        return True
    settings = _settings()
    if not settings["enable_dns_lookups"]:
        return False
    budget = float(settings["dns_timeout_seconds"]) * 3
    started = time.time()
    for candidate in [domain] + _parent_domains(domain):
        selectors = _DKIM_SELECTORS.get(candidate, _DEFAULT_DKIM_SELECTORS)
        for selector in selectors:
            if time.time() - started > budget:
                logger.debug("DKIM probe budget exhausted for %s", domain)
                return False
            for txt in _resolve_txt(f"{selector}._domainkey.{candidate}"):
                if "v=DKIM1" in txt:
                    return True
    return False


def dns_dmarc_lookup(domain: str) -> bool:
    """True when the domain publishes a DMARC policy at all.

    This used to demand `p=reject`, which scored the majority of legitimate
    senders as DMARC failures — `p=none` and `p=quarantine` are valid published
    policies, and most real domains use them. Policy strictness is a separate
    signal from "is DMARC configured", and conflating the two was a large
    source of false positives.
    """
    for txt in _resolve_txt(f"_dmarc.{domain}"):
        if "v=DMARC1" in txt:
            return True
    return False


def dns_dmarc_policy(domain: str) -> Optional[str]:
    """The published DMARC policy — 'reject', 'quarantine', 'none' or None."""
    for txt in _resolve_txt(f"_dmarc.{domain}"):
        if "v=DMARC1" not in txt:
            continue
        match = re.search(r"p\s*=\s*(reject|quarantine|none)", txt, re.IGNORECASE)
        if match:
            return match.group(1).lower()
    return None


def reverse_dns(ip: str) -> Optional[str]:
    if not ip or not _settings()["enable_dns_lookups"]:
        return None
    cache_key = f"ptr:{ip}"
    cached = _cache_get(_DNS_CACHE, cache_key)
    if cached is not None:
        return cached or None
    value = ""
    try:
        name = dns.reversename.from_address(ip)
        answers = _resolver().resolve(name, "PTR")
        for rdata in answers:
            value = str(rdata)
            break
    except Exception as exc:
        logger.debug("PTR lookup failed for %s: %s", ip, exc)
    _cache_set(_DNS_CACHE, cache_key, value, _DNS_CACHE_TTL)
    return value or None


def get_asn_info(ip: str) -> dict:
    """ASN and owning organisation, resolved from local databases."""
    if not ip:
        return {"asn": None, "asn_org": "", "country": ""}
    info = ip2location.asn_info(ip)
    geo = ip2location.locate(ip) or {}
    return {
        "asn": info.get("asn"),
        "asn_org": info.get("asn_org", ""),
        "country": geo.get("country", ""),
        "source": info.get("source", "unavailable"),
    }


def is_known_vpn_or_hosting(ip: str) -> bool:
    if not ip:
        return False
    verdict = ip2location.classify(ip)
    if verdict.get("is_hosting") or verdict.get("is_proxy"):
        return True
    ptr = reverse_dns(ip)
    if ptr:
        lowered = ptr.lower()
        hosting_markers = ("cloud", "host", "server", "vps", "colo", "static", "datacenter",
                           "vpn", "proxy", "tor", "tunnel")
        return any(marker in lowered for marker in hosting_markers)
    return False


def compute_asn_reputation_score(ip: str) -> float:
    """0 (hostile infrastructure) .. 1 (reputable sender network)."""
    if not ip:
        return 0.5
    verdict = ip2location.classify(ip)
    org = (verdict.get("asn_org") or "").lower()
    if verdict.get("is_proxy"):
        return 0.1
    if verdict.get("is_hosting"):
        return 0.25
    if any(name in org for name in ("amazon", "google", "microsoft", "cloudflare")):
        return 0.85
    if not org:
        return 0.5
    return 0.7


def whois_lookup(domain: str) -> dict:
    """Domain age and registrar, cached for a day and bounded by a timeout."""
    # A failed lookup means the age is unknown, not "one year old". The old
    # numeric fallback read as a young domain and pushed every whois timeout
    # toward a fraud verdict.
    fallback = {"domain_age_days": float("nan"), "registrar": "unknown", "created_date": None}
    if not domain:
        return fallback
    cached = _cache_get(_WHOIS_CACHE, domain)
    if cached is not None:
        return cached
    settings = _settings()
    if not settings["enable_whois_lookups"]:
        return fallback

    def query():
        import whois

        return whois.whois(domain)

    record = _call_with_timeout(query, float(settings["whois_timeout_seconds"]))
    result = fallback
    if record is not None:
        created = getattr(record, "creation_date", None)
        if isinstance(created, list):
            created = created[0] if created else None
        parsed = _parse_created(created)
        if parsed is not None:
            from datetime import datetime, timezone

            now = datetime.now(timezone.utc)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            result = {
                "domain_age_days": max(0, (now - parsed).days),
                "registrar": getattr(record, "registrar", None) or "unknown",
                "created_date": parsed.strftime("%Y-%m-%d"),
            }
    _cache_set(_WHOIS_CACHE, domain, result, _WHOIS_CACHE_TTL)
    return result


def _parse_created(created):
    from datetime import datetime

    if created is None:
        return None
    if hasattr(created, "strftime"):
        return created
    if isinstance(created, str):
        try:
            return datetime.fromisoformat(created.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def compute_forensic_features(headers: dict, sender_domain: str) -> dict:
    """Forensic feature vector for Tier 0.

    Authentication is tri-state, not boolean. A result is only `False` when the
    receiving infrastructure actually reported a failure in
    `Authentication-Results`. When no such header is present we cannot verify
    the message at all — DNS only tells us what the domain *publishes*, never
    whether this particular message passed — so the value is NaN ("unknown")
    and the model routes it down its learned missing-value branch.

    Returning False for "unverified" is what made every legitimate sender whose
    DKIM selector could not be guessed look like a confirmed forgery.
    """
    headers = normalize_headers(headers)
    parsed = parse_headers(headers)

    def verified(result: Optional[str]) -> float:
        """Only the receiving infrastructure can decide pass or fail.

        DNS answers a different question — what the domain *publishes* — and a
        domain publishing no SPF record has not thereby failed authentication
        on this message. Treating those as failures is what flagged ordinary
        mail, so anything we cannot verify stays unknown.
        """
        if result == "pass":
            return 1.0
        if result in ("fail", "softfail"):
            return 0.0
        return float("nan")

    auth = {
        "spf_pass": verified(parsed.get("spf")),
        "dkim_pass": verified(parsed.get("dkim")),
        "dmarc_pass": verified(parsed.get("dmarc")),
    }
    ip = extract_trust_boundary_ip(headers)
    geo = geolocate_ip(ip) if ip else None
    domain_info = whois_lookup(sender_domain)

    received_headers = headers.get("received", [])
    if isinstance(received_headers, str):
        received_headers = [received_headers]
    relay_count = len(received_headers)
    # A normal delivery crosses roughly 2-5 relays; anomaly measures the excess
    # over that, so an ordinary message scores 0 rather than "slightly odd".
    anomaly = max(0.0, (relay_count - 5) / 5.0) if relay_count else 0.0

    geo_ok = True
    if geo and not geo.get("is_private"):
        country = geo.get("country", "")
        if country in _SANCTIONED_COUNTRIES:
            geo_ok = False
        elif country and country not in _EXPECTED_GEO_COUNTRIES:
            geo_ok = False

    return {
        "spf_pass": auth["spf_pass"],
        "dkim_pass": auth["dkim_pass"],
        "dmarc_pass": auth["dmarc_pass"],
        "domain_age_days": domain_info.get("domain_age_days", float("nan")),
        "ip_in_spf_authorized_range": auth["spf_pass"],
        "geo_matches_expected_countries": geo_ok,
        "ip_is_known_vpn_or_hosting": is_known_vpn_or_hosting(ip) if ip else False,
        "asn_reputation_score": round(compute_asn_reputation_score(ip) if ip else 0.5, 2),
        "header_anomaly_score": round(anomaly, 2),
        "relay_hop_count": relay_count,
    }
