import json
import math
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse
from app.models.schemas import AnalysisRequest, BadgeScoreRequest, CategoryUpdate
from app.services.storage import (append_case, has_case, read_cases_today, read_all_cases,
                                  read_fingerprints, json_safe, full_analysis_for)
from app.services.forensics import compute_forensic_features, extract_trust_boundary_ip, geolocate_ip
from app.services.fingerprint import compute_fingerprint
from app.services.gatekeeper import run as gatekeeper_run
from app.services import tier0_model, ip2location, ledger
from app._version import __version__ as APP_VERSION
from app.services.cascade import (
    ADAPTER_NAME_MAP,
    adapter_path_for,
    run as cascade_run,
    run_all as cascade_run_all,
)
from app.config import load_config, save_config, DATA_DIR, DEFAULT_PORT

STARTED_AT = time.time()


def active_port() -> int:
    """The port this process is actually serving on.

    run.py exports ETD_ACTIVE_PORT so the reported port matches reality even
    when an override was used; the extension trusts this to find the engine.
    """
    import os

    try:
        return int(os.environ.get("ETD_ACTIVE_PORT") or load_config().get("local_port", DEFAULT_PORT))
    except (TypeError, ValueError):
        return DEFAULT_PORT

# Severity bands. The dashboard legend, the map markers and the case table all
# colour from this one definition so they can never drift apart.
SEVERITY_BANDS = [
    {"id": "critical", "label": "Critical", "min": 90, "color": "#c62139",
     "description": "Confirmed attack - quarantine and notify the recipient"},
    {"id": "high", "label": "High", "min": 80, "color": "#d9660a",
     "description": "Flagged by the cascade - review before release"},
    {"id": "elevated", "label": "Elevated", "min": 50, "color": "#b8860b",
     "description": "Suspicious signals, below the flag threshold"},
    {"id": "low", "label": "Low", "min": 20, "color": "#1e88e5",
     "description": "Minor anomalies, delivered normally"},
    {"id": "safe", "label": "Safe", "min": 0, "color": "#0f9d76",
     "description": "Passed authentication and content checks"},
]


def severity_for(score) -> str:
    try:
        value = float(score)
    except (TypeError, ValueError):
        return "low"
    for band in SEVERITY_BANDS:
        if value >= band["min"]:
            return band["id"]
    return "safe"


def enrich_case(case: dict) -> dict:
    """Add the derived fields the dashboard renders from."""
    geo = case.get("geo") or {}
    enriched = dict(case)
    enriched["severity"] = severity_for(case.get("score"))
    enriched["country"] = geo.get("country") or ""
    enriched["city"] = geo.get("city") or ""
    enriched["lat"] = geo.get("lat")
    enriched["lon"] = geo.get("lon")
    enriched["geoSource"] = geo.get("source") or "unresolved"
    enriched["located"] = geo.get("lat") is not None and geo.get("lon") is not None
    features = case.get("features") or {}
    enriched["authPass"] = bool(features.get("spf_pass")) and bool(features.get("dkim_pass"))
    enriched["hosting"] = bool(features.get("ip_is_known_vpn_or_hosting"))

    # Cases logged before the sender/subject were stored still have to render.
    sender = case.get("sender") or ""
    enriched["sender"] = sender
    enriched["subject"] = case.get("subject") or ""
    enriched["senderDomain"] = case.get("senderDomain") or (
        sender.split("@")[-1] if "@" in sender else ""
    )
    return enriched


def _is_fail(value) -> bool:
    """True only for a reported failure, not for an unverifiable check.

    Authentication is tri-state: 1 pass, 0 fail, NaN/None unknown. A plain
    falsiness test would count "we could not check" as "it failed", which is
    the mistake that flagged ordinary mail.
    """
    if value is None:
        return False
    try:
        number = float(value)
    except (TypeError, ValueError):
        return False
    return number == 0.0


def _known(value):
    """The numeric value when it is known, otherwise None."""
    if value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        return None
    return None if math.isnan(number) else number


def build_evidence(features: dict, text: str, tier0_pred) -> list:
    """The weighted factors behind a verdict, shared by both scoring paths."""
    evidence = []

    for key, label, weight, detail in (
        ("spf_pass", "SPF Check", -15, "Sending IP is not authorised by the domain's SPF record"),
        ("dkim_pass", "DKIM Check", -10, "DKIM signature is present but did not validate"),
        ("dmarc_pass", "DMARC Check", -10, "Message did not satisfy the domain's DMARC policy"),
    ):
        if _is_fail(features.get(key)):
            evidence.append({"factor": label, "contribution": weight, "explanation": detail})

    age = _known(features.get("domain_age_days"))
    if age is not None:
        if age < 7:
            evidence.append({"factor": "Domain Age", "contribution": -25,
                             "explanation": f"Sender domain was registered {int(age)} days ago"})
        elif age < 30:
            evidence.append({"factor": "Domain Age", "contribution": -10,
                             "explanation": f"Sender domain was registered {int(age)} days ago"})

    if features.get("ip_is_known_vpn_or_hosting"):
        evidence.append({"factor": "IP Reputation", "contribution": -15,
                         "explanation": "Sending IP belongs to a hosting or VPN provider"})

    anomaly = _known(features.get("header_anomaly_score")) or 0
    if anomaly > 0.7:
        evidence.append({"factor": "Header Anomaly", "contribution": -20,
                         "explanation": "Relay chain is longer than a normal delivery"})

    hops = _known(features.get("relay_hop_count")) or 0
    if hops > 5:
        evidence.append({"factor": "Relay Hops", "contribution": -10,
                         "explanation": f"Message traversed {int(hops)} relays"})

    lower_text = (text or "").lower()
    if "urgent" in lower_text:
        evidence.append({"factor": "Urgent Language", "contribution": -10,
                         "explanation": "Message contains urgency triggers"})
    if "wire transfer" in lower_text:
        evidence.append({"factor": "Wire Transfer", "contribution": -15,
                         "explanation": "Message requests a wire transfer"})
    if "password" in lower_text and "click" in lower_text:
        evidence.append({"factor": "Credential Phish", "contribution": -10,
                         "explanation": "Password request combined with a call to action"})

    if tier0_pred is not None:
        evidence.append({
            "factor": "Tier 0 ML (LightGBM)",
            "contribution": int(tier0_pred["overall_scam_score"] - 50),
            "explanation": f"LightGBM predicted class '{tier0_pred['predicted_class']}' "
                           f"with scam score {tier0_pred['overall_scam_score']}",
        })
    return evidence


def build_case_payload() -> dict:
    # json_safe first: a stored NaN feature would otherwise serialise as a bare
    # `NaN`, which is not valid JSON. The embedded payload then fails
    # JSON.parse in the browser and the dashboard silently renders no cases.
    cases = [enrich_case(json_safe(c)) for c in read_all_cases()]

    # The log is append-only, so a message scanned in the inbox and later
    # opened has two records. Show the most recent one — opening a message
    # runs the full cascade, which supersedes the subject-only scan.
    latest: dict = {}
    for case in cases:
        latest[case.get("messageId")] = case
    cases = list(latest.values())

    cases.sort(key=lambda c: str(c.get("timestamp") or ""), reverse=True)
    fingerprints = read_fingerprints()

    clusters = defaultdict(list)
    for case in cases:
        if case.get("fingerprint"):
            clusters[case["fingerprint"]].append(case["messageId"])
    campaigns = [
        {
            "fingerprint": fingerprint,
            "size": len(members),
            "members": members,
            "firstSeen": (fingerprints.get(fingerprint) or {}).get("first_seen"),
        }
        for fingerprint, members in sorted(clusters.items(), key=lambda kv: -len(kv[1]))
    ]

    flagged = [c for c in cases if c.get("flagged")]
    by_category = Counter(c.get("category") or "uncategorised" for c in cases)
    by_country = Counter(c["country"] for c in cases if c.get("country"))
    by_severity = Counter(c["severity"] for c in cases)

    return {
        "cases": cases,
        "campaigns": campaigns,
        "fingerprints": fingerprints,
        "severityBands": SEVERITY_BANDS,
        "totals": {
            "analyzed": len(cases),
            "flagged": len(flagged),
            "safe": len(cases) - len(flagged),
            "located": sum(1 for c in cases if c["located"]),
            "campaigns": sum(1 for c in campaigns if c["size"] > 1),
            "countries": len(by_country),
        },
        "byCategory": by_category.most_common(),
        "byCountry": by_country.most_common(),
        "bySeverity": by_severity,
        "generatedAt": datetime.now(timezone.utc).isoformat(),
    }

TIER0_TO_ADAPTER = {
    "business_email_compromise": "bec",
    "ceo_fraud_executive_spoofing": "ceo_fraud",
    "credential_harvesting": "credential_harvest",
    "fake_invoice_fraud": "fake_invoice",
    "tax_government_impersonation": "tax_impersonation",
}


def installed_adapters() -> list:
    """Categories whose LoRA adapter is actually present on disk."""
    return [name for name in ADAPTER_NAME_MAP if adapter_path_for(name).is_dir()]


def select_tier1_categories(tier0_pred, enabled: dict) -> list:
    """The specialists to consult, in Tier 0's probability order.

    Only categories that have a trained adapter on disk are eligible. The
    config enables thirty category names, but five of them have adapters; the
    other twenty-five resolved to a missing directory and fell through to
    `_simulate()`, a keyword counter whose score was then thrown into the same
    `max()` as the real model's. That meant thirty inferences per email, of
    which twenty-five were keyword guesses competing with the trained ones.
    """
    ranked = []
    if tier0_pred is not None:
        for cat in tier0_pred.get("categories", []):
            mapped = TIER0_TO_ADAPTER.get(cat.get("category"))
            if mapped and mapped not in ranked and enabled.get(mapped, True):
                ranked.append(mapped)
    for name in ADAPTER_NAME_MAP:
        if name not in ranked and enabled.get(name, True):
            ranked.append(name)
    return ranked

router = APIRouter()


@router.get("/health")
async def health():
    """Liveness probe.

    The extension treats status == "ok" as "engine reachable" and reads the
    rest to tell a warming-up engine apart from a fully loaded one.
    """
    return JSONResponse(content={
        "status": "ok",
        "version": APP_VERSION,
        "uptimeSeconds": round(time.time() - STARTED_AT, 1),
        "tier0ModelLoaded": tier0_model.is_available(),
    })


@router.get("/api/engine/status")
def engine_status():
    """Everything the popup shows about engine readiness in one call."""
    config = load_config()
    enabled = [k for k, v in config.get("enabled_categories", {}).items() if v]
    today = read_cases_today()
    geo = ip2location.status()
    tier0_ready = tier0_model.is_available()
    tier1_adapters = installed_adapters()

    components = [
        {
            "id": "api",
            "label": "Local API",
            "state": "ready",
            "detail": f"127.0.0.1:{active_port()}",
        },
        {
            "id": "tier0",
            "label": "Tier 0 classifier",
            "state": "ready" if tier0_ready else "unavailable",
            "detail": "LightGBM model loaded" if tier0_ready else "tier0_model.txt not found",
        },
        {
            "id": "tier1",
            "label": "Tier 1 adapters",
            # What matters is how many adapters exist on disk, not how many
            # category names the config leaves ticked. Reporting the config
            # count said "30 categories enabled" while five adapters were
            # installed and, at one point, only one of those could load.
            "state": "ready" if tier1_adapters else "unavailable",
            "detail": (", ".join(tier1_adapters) if tier1_adapters
                       else "no trained adapters found"),
            "adapters": tier1_adapters,
        },
        {
            "id": "geo",
            "label": "IP intelligence",
            "state": "ready" if geo.get("ready") else "unavailable",
            "detail": geo.get("activeProvider", "none"),
        },
    ]
    ready = all(c["state"] in ("ready", "idle") for c in components)

    return {
        "status": "ok",
        "state": "loaded" if ready else "degraded",
        "version": APP_VERSION,
        "uptimeSeconds": round(time.time() - STARTED_AT, 1),
        "port": active_port(),
        "profile": config.get("profile", "Default"),
        "components": components,
        "offlineMode": not config.get("allow_online_lookups", False),
        "today": {
            "analyzed": len(today),
            "flagged": sum(1 for c in today if c.get("flagged")),
            "safe": sum(1 for c in today if not c.get("flagged")),
        },
    }


@router.get("/api/geo/status")
async def geo_status():
    """Which IP database is answering lookups, and what it resolves."""
    status = ip2location.status()
    samples = []
    for probe in ("8.8.8.8", "1.1.1.1", "185.220.101.1"):
        located = ip2location.locate(probe) or {}
        samples.append({
            "ip": probe,
            "country": located.get("country", ""),
            "city": located.get("city", ""),
            "source": located.get("source", "unresolved"),
        })
    status["samples"] = samples
    return status


@router.get("/api/cases")
def cases():
    return build_case_payload()


@router.get("/api/stats")
def stats():
    payload = build_case_payload()
    return {
        "totals": payload["totals"],
        "byCategory": payload["byCategory"],
        "byCountry": payload["byCountry"],
        "bySeverity": payload["bySeverity"],
        "generatedAt": payload["generatedAt"],
    }


@router.get("/api/info")
async def service_info():
    return JSONResponse(content={"service": "TrT — Threat Recognition and Tracker", "status": "ok", "version": APP_VERSION, "dashboard": "/dashboard", "health": "/health"})


@router.get("/api/case/{message_id:path}")
def case_detail(message_id: str):
    """One case plus its ledger block — the forensic report's data source."""
    cases = [enrich_case(c) for c in read_all_cases()]
    match = next((c for c in cases if c.get("messageId") == message_id), None)
    if match is None:
        return JSONResponse(status_code=404, content={"error": "No case with that message id"})

    siblings = [c for c in cases
                if c.get("fingerprint") and c.get("fingerprint") == match.get("fingerprint")
                and c.get("messageId") != message_id]
    return {
        "case": match,
        "block": ledger.block_for(message_id),
        "severityBands": SEVERITY_BANDS,
        "campaign": {
            "fingerprint": match.get("fingerprint"),
            "size": len(siblings) + 1,
            "siblings": siblings,
        },
    }


@router.get("/api/ledger")
async def ledger_state():
    chain = ledger.read_chain()
    return {
        "height": len(chain),
        "headHash": chain[-1]["hash"] if chain else ledger.GENESIS_HASH,
        "algorithm": "SHA-256 linked hash chain",
        "blocks": chain[-50:][::-1],
    }


@router.get("/api/ledger/verify")
def ledger_verify():
    return ledger.verify(read_all_cases())


@router.get("/favicon.ico")
async def favicon():
    return JSONResponse(content={}, status_code=204)


# Scoring and case-log routes are plain `def`, so FastAPI runs them in its
# thread pool. As `async def` they ran model inference on the event loop, and
# while a Gmail page was being scored /health could not answer inside the
# extension's probe timeout: the popup showed "Engine offline" / Retry for an
# engine that was running.
@router.post("/api/analyze")
def analyze(req: AnalysisRequest):
    config = load_config()
    enabled = config.get("enabled_categories", {})
    sender_domain = req.sender.split("@")[-1] if "@" in req.sender else req.sender
    features = compute_forensic_features(req.headers, sender_domain)
    score, category_probs = gatekeeper_run(features, req.emailBody, enabled)
    tier0_pred = tier0_model.predict(features)
    tier0_payload = tier0_pred if tier0_pred is not None else None

    print("\n" + "=" * 60)
    print(" ETD LIVE TIER 0 (GATEKEEPER) INPUT & FEATURE ANALYSIS")
    print("=" * 60)
    print(f" [MESSAGE ID]: {req.messageId}")
    print(f" [SENDER]:     {req.sender} (Domain: {sender_domain})")
    print(f" [SUBJECT]:    {req.subject}")
    print(f" [BODY LEN]:   {len(req.emailBody or '')} chars")
    print("-" * 60)
    print(" [COMPUTED FORENSIC FEATURES (TIER 0 INPUTS)]:")
    for k, v in features.items():
        print(f"    - {k:<30}: {v}")
    print("-" * 60)
    print(" [ENABLED CATEGORIES]:", [k for k, v in enabled.items() if v])
    if tier0_pred is not None:
        print(" [TIER 0 MODEL SCAM CATEGORIES]:", [c["category"] for c in tier0_pred["categories"]])
        print(f" [GATEKEEPER INITIAL SCORE]: {score}/100  (Tier 0 model overall_scam_score: {tier0_pred['overall_scam_score']})")
        print(" [CATEGORY PROBABILITIES]:")
        for cat in tier0_pred["categories"]:
            print(f"    - {cat['category']:<30}: {cat['confidence']}%")
    else:
        print(f" [GATEKEEPER INITIAL SCORE]: {score}/100")
        print(" [CATEGORY PROBABILITIES]:")
        for cat, prob in sorted(category_probs.items(), key=lambda x: -x[1]):
            print(f"    - {cat:<30}: {prob}")
    print("=" * 60 + "\n")
    evidence = build_evidence(features, req.emailBody, tier0_pred)
    thresholds = config.get("thresholds", {})
    high_threshold = thresholds.get("high", 80)
    ambiguous_low = thresholds.get("ambiguous_low", 15)

    flagged = score >= high_threshold
    # The ranking always has a top entry, but naming a threat category on mail
    # that scored clean reads as an accusation in the dashboard. Below the
    # ambiguous band there is no threat to categorise.
    category = None
    if category_probs and score >= ambiguous_low:
        category = max(category_probs, key=category_probs.get)
    cascade_results = []

    # Tier 1 reads everything Tier 0 has not already flagged, including mail
    # Tier 0 scored as clean.
    #
    # That looks wasteful next to the documented "skip the specialists below
    # the ambiguous band", but the most valuable case this product has breaks
    # that rule: business email compromise sent from a genuine, stolen mailbox
    # passes SPF, DKIM and DMARC from an established domain, so Tier 0 — which
    # only ever sees headers and infrastructure — correctly reports nothing
    # wrong. The tell is the wording, and only Tier 1 reads wording. Gating on
    # the Tier 0 score let those through untouched.
    #
    # This was briefly gated because the old adapter called 36% of safe mail a
    # threat. On the binary target it misclassifies none of it, so coverage is
    # no longer paid for in false positives.
    if not flagged:
        tier1_cats = select_tier1_categories(tier0_pred, enabled)
        if tier1_cats:
            print(" [TIER 1 AI (LoRA ADAPTER CHECKS IN TIER 0 PROBABILITY ORDER)]:")
            print("-" * 60)
        cascade_results = cascade_run_all(tier1_cats, {
            "sender": req.sender,
            "subject": req.subject,
            "body": req.emailBody,
        })
        for cr in cascade_results:
            print(f"    >>> Checking adapter: {cr.get('adapter', 'N/A')} (model: {cr.get('model', 'N/A')})")
            print(f"    - confidence   : {cr.get('confidence', 0)}")
            if cr.get("label_probs"):
                for k, v in cr.get("label_probs", {}).items():
                    print(f"    - {k:<30}: {v}")
            print("-" * 60)
        if cascade_results:
            best = max(cascade_results, key=lambda r: r.get("confidence", 0))
            cascade_result = best
            if best.get("confidence", 0) >= config.get("thresholds", {}).get("tier1_confirm", 0.7) and not flagged:
                score = min(100, max(score, 70))
                flagged = True
                evidence.append({
                    "factor": "Tier 1 AI",
                    "contribution": int((best.get("confidence", 0) - 0.5) * 50),
                    "explanation": f"LoRA adapter {best.get('adapter', 'N/A')} confirmed with confidence {best.get('confidence', 0)}",
                })
        else:
            print(" [TIER 1 AI]: Skipped (Tier 0 proved scam)")
            print("-" * 60)
    fp = compute_fingerprint(req.emailBody)
    ip = extract_trust_boundary_ip(req.headers)
    geo = geolocate_ip(ip) if ip else None
    safe_score = max(0, 100 - score)
    result = {
        "messageId": req.messageId,
        "sender": req.sender,
        "senderDomain": sender_domain,
        "subject": req.subject,
        "score": round(score, 1),
        "flagged": flagged,
        "category": category,
        "safeScore": round(safe_score, 1),
        "evidence": evidence,
        "processedLocally": True,
        "fingerprint": fp,
        "features": features,
        "geo": geo,
        "tier0": tier0_payload,
        "tier1": cascade_results,
    }
    result = json_safe(result)
    append_case(result)
    return result


@router.post("/api/badge-score")
def badge_score(req: BadgeScoreRequest):
    # A message that has been opened was scored on its full body and headers.
    # Re-scoring it from the preview line alone let the row badge contradict
    # the opened-message banner, so the full verdict wins.
    full = full_analysis_for(req.sender, req.subject)
    if full is not None:
        return {**full, "messageId": req.messageId, "source": "full-analysis"}

    config = load_config()
    enabled = config.get("enabled_categories", {})
    sender_domain = req.sender.split("@")[-1] if "@" in req.sender else req.sender
    features = compute_forensic_features({}, sender_domain)
    score, category_probs = gatekeeper_run(features, req.subject, enabled)
    tier0_pred = tier0_model.predict(features)

    print("\n" + "=" * 60)
    print(" ETD LIVE TIER 0 (GATEKEEPER) INPUT & FEATURE ANALYSIS")
    print("=" * 60)
    print(f" [MESSAGE ID]: {req.messageId}")
    print(f" [SENDER]:     {req.sender} (Domain: {sender_domain})")
    print(f" [SUBJECT]:    {req.subject}")
    print("-" * 60)
    print(" [COMPUTED FORENSIC FEATURES (TIER 0 INPUTS)]:")
    for k, v in features.items():
        print(f"    - {k:<30}: {v}")
    print("-" * 60)
    print(" [ENABLED CATEGORIES]:", [k for k, v in enabled.items() if v])
    if tier0_pred is not None:
        print(" [TIER 0 MODEL SCAM CATEGORIES]:", [c["category"] for c in tier0_pred["categories"]])
        print(f" [GATEKEEPER INITIAL SCORE]: {score}/100  (Tier 0 model overall_scam_score: {tier0_pred['overall_scam_score']})")
        print(" [CATEGORY PROBABILITIES]:")
        for cat in tier0_pred["categories"]:
            print(f"    - {cat['category']:<30}: {cat['confidence']}%")
    else:
        print(f" [GATEKEEPER INITIAL SCORE]: {score}/100")
        print(" [CATEGORY PROBABILITIES]:")
        for cat, prob in sorted(category_probs.items(), key=lambda x: -x[1]):
            print(f"    - {cat:<30}: {prob}")
    print("=" * 60 + "\n")

    thresholds = config.get("thresholds", {})
    high_threshold = thresholds.get("high", 80)
    ambiguous_low = thresholds.get("ambiguous_low", 15)

    flagged = score >= high_threshold
    # The ranking always has a top entry, but naming a threat category on mail
    # that scored clean reads as an accusation in the dashboard. Below the
    # ambiguous band there is no threat to categorise.
    category = None
    if category_probs and score >= ambiguous_low:
        category = max(category_probs, key=category_probs.get)
    cascade_results = []

    # Tier 1 reads everything Tier 0 has not already flagged, including mail
    # Tier 0 scored as clean.
    #
    # That looks wasteful next to the documented "skip the specialists below
    # the ambiguous band", but the most valuable case this product has breaks
    # that rule: business email compromise sent from a genuine, stolen mailbox
    # passes SPF, DKIM and DMARC from an established domain, so Tier 0 — which
    # only ever sees headers and infrastructure — correctly reports nothing
    # wrong. The tell is the wording, and only Tier 1 reads wording. Gating on
    # the Tier 0 score let those through untouched.
    #
    # This was briefly gated because the old adapter called 36% of safe mail a
    # threat. On the binary target it misclassifies none of it, so coverage is
    # no longer paid for in false positives.
    if not flagged:
        tier1_cats = select_tier1_categories(tier0_pred, enabled)
        if tier1_cats:
            print(" [TIER 1 AI (LoRA ADAPTER CHECKS IN TIER 0 PROBABILITY ORDER)]:")
            print("-" * 60)
        # Scored from the inbox row. There is no full body, but Gmail renders
        # a preview line and the extension forwards it, so Tier 1 has real
        # wording to read instead of a bare subject. Without it a credential
        # harvesting email subjected "Urgent" is indistinguishable from any
        # other one-word subject, and the row is badged safe while the preview
        # beside it asks for a password and an OTP.
        cascade_results = cascade_run_all(tier1_cats, {
            "sender": req.sender,
            "subject": req.subject,
            "body": req.snippet or "",
        })
        for cr in cascade_results:
            print(f"    >>> Checking adapter: {cr.get('adapter', 'N/A')} (model: {cr.get('model', 'N/A')})")
            print(f"    - confidence   : {cr.get('confidence', 0)}")
            if cr.get("label_probs"):
                for k, v in cr.get("label_probs", {}).items():
                    print(f"    - {k:<30}: {v}")
            print("-" * 60)
        if cascade_results:
            best = max(cascade_results, key=lambda r: r.get("confidence", 0))
            if best.get("confidence", 0) >= config.get("thresholds", {}).get("tier1_confirm", 0.7) and not flagged:
                score = min(100, max(score, 70))
                flagged = True
        else:
            print(" [TIER 1 AI]: Skipped (Tier 0 proved scam)")
            print("-" * 60)
    result = json_safe({
        "messageId": req.messageId,
        "sender": req.sender,
        "senderDomain": sender_domain,
        "subject": req.subject,
        "score": round(score, 1),
        "flagged": flagged,
        "category": category,
        "safeScore": round(max(0, 100 - score), 1),
        "features": features,
        "categoryProbs": category_probs,
        "enabledCategories": [k for k, v in enabled.items() if v],
        "tier0": tier0_pred,
        "tier1": cascade_results,
        # Scored from the inbox row alone: the sender and subject are known,
        # the headers and body are not. Opening the message runs /api/analyze,
        # which logs the full-evidence version over the top of this one.
        "source": "inbox-scan",
        "processedLocally": True,
        "evidence": build_evidence(features, req.subject, tier0_pred),
    })

    # Record it so the dashboard reflects the inbox sweep. Without this the
    # engine scored every row and reported "0 analysed", which looked broken.
    if not has_case(req.messageId):
        append_case(result)
    return result


@router.get("/api/config")
async def get_config():
    config = load_config()
    return {
        "version": APP_VERSION,
        "profile": config.get("profile", "Default"),
        "activeAdapters": sum(1 for v in config.get("enabled_categories", {}).values() if v),
        "deviceTier": config.get("device_tier", "high"),
        "tier0ModelAvailable": tier0_model.is_available(),
        "tier0ModelPath": str(tier0_model.model_path()) if tier0_model.model_path() else None,
        "tier0Classes": tier0_model.CLASSES,
    }


@router.get("/api/tier0/info")
async def tier0_info():
    return {
        "available": tier0_model.is_available(),
        "model_path": str(tier0_model.model_path()) if tier0_model.model_path() else None,
        "classes": tier0_model.CLASSES,
        "feature_cols": tier0_model.FEATURE_COLS,
    }


@router.get("/api/stats/today")
def stats_today():
    cases = read_cases_today()
    analyzed = len(cases)
    flagged = sum(1 for c in cases if c.get("flagged"))
    safe = analyzed - flagged
    return {"analyzed": analyzed, "flagged": flagged, "safe": safe}


@router.post("/api/categories")
async def update_categories(request: Request):
    """Accepts {"enabledCategories": {...}} or a bare {category: bool} map.

    The options page historically posted the bare map, which failed validation
    and silently left the engine on its previous categories.
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"ok": False, "error": "Body must be JSON"})
    if isinstance(body, dict) and "enabledCategories" in body:
        body = body["enabledCategories"]
    if not isinstance(body, dict) or not body:
        return JSONResponse(status_code=400, content={"ok": False, "error": "Expected a category map"})

    categories = {str(k): bool(v) for k, v in body.items() if isinstance(v, (bool, int))}
    if not categories:
        return JSONResponse(status_code=400, content={"ok": False, "error": "No valid categories supplied"})

    config = load_config()
    merged = dict(config.get("enabled_categories", {}))
    merged.update(categories)
    config["enabled_categories"] = merged
    save_config(config)
    return {"ok": True, "enabled": sum(1 for v in merged.values() if v), "total": len(merged)}


def _templates():
    from fastapi.templating import Jinja2Templates
    from app.config import TEMPLATES_DIR
    return Jinja2Templates(directory=str(TEMPLATES_DIR))


@router.get("/", response_class=HTMLResponse)
async def landing(request: Request):
    """Product home page — what the system does, and the live engine's state."""
    cases = read_all_cases()
    chain = ledger.read_chain()
    flagged = [c for c in cases if c.get("flagged")]
    by_category = Counter(c.get("category") or "uncategorised" for c in flagged)

    return _templates().TemplateResponse(request, "landing.html", {
        "app_version": APP_VERSION,
        "totals": {
            "analyzed": len(cases),
            "flagged": len(flagged),
            "categories": len(by_category),
            "blocks": len(chain),
        },
        "engine_port": active_port(),
        "tier0_ready": tier0_model.is_available(),
    })


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    """Render the SecOps dashboard with its data embedded.

    The payload is inlined so the page paints with no follow-up request; the
    page then refreshes itself from /api/cases in the background.
    """
    payload = build_case_payload()
    return _templates().TemplateResponse(request, "dashboard.html", {
        "embedded_payload": json.dumps(payload, default=str),
        "embedded_geo": json.dumps(ip2location.status(), default=str),
        "app_version": APP_VERSION,
    })


@router.get("/report/{message_id:path}", response_class=HTMLResponse)
def report(request: Request, message_id: str):
    """Full forensic report for one message, printable as-is."""
    cases = [enrich_case(c) for c in read_all_cases()]
    match = next((c for c in cases if c.get("messageId") == message_id), None)
    if match is None:
        return HTMLResponse(status_code=404, content=
            "<!doctype html><meta charset=utf-8>"
            "<title>Report not found</title>"
            "<body style=\"font:15px system-ui;padding:60px;color:#0a1f3c\">"
            "<h1>No report for that message</h1>"
            "<p>The engine has no case stored under that id.</p>"
            "<p><a href=\"/dashboard\">Back to the dashboard</a></p>")

    siblings = [c for c in cases
                if c.get("fingerprint") and c.get("fingerprint") == match.get("fingerprint")
                and c.get("messageId") != message_id]

    return _templates().TemplateResponse(request, "report.html", {
        "app_version": APP_VERSION,
        "embedded_case": json.dumps({
            "case": match,
            "block": ledger.block_for(message_id),
            "severityBands": SEVERITY_BANDS,
            "campaign": {
                "fingerprint": match.get("fingerprint"),
                "size": len(siblings) + 1,
                "siblings": siblings,
            },
        }, default=str),
    })
