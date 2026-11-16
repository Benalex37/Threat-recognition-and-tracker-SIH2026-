"""Tier 0 LightGBM classifier service.

Loads the trained `tier0_model.txt` booster and exposes a single predict()
entry point that maps forensic features -> scam score + category ranking.
"""

from pathlib import Path

try:
    import numpy as np
    import lightgbm as lgb
    HAS_LGB = True
except ImportError:
    HAS_LGB = False

CLASSES = [
    "business_email_compromise",
    "ceo_fraud_executive_spoofing",
    "credential_harvesting",
    "fake_invoice_fraud",
    "legitimate",
    "tax_government_impersonation",
]
LEGIT_IDX = CLASSES.index("legitimate")
# The 5 scam categories the Tier 0 model was trained to detect (excludes "legitimate")
SCAM_CLASSES = [c for c in CLASSES if c != "legitimate"]

FEATURE_COLS = [
    "spf_pass", "dkim_pass", "dmarc_pass", "domain_age_days",
    "ip_in_spf_authorized_range", "geo_matches_expected_countries",
    "ip_is_known_vpn_or_hosting", "asn_reputation_score",
    "header_anomaly_score", "relay_hop_count",
]

CATEGORY_ALIASES = {
    "bec": "business_email_compromise",
    "vec": "business_email_compromise",
    "wire_fraud": "business_email_compromise",
    "ceo_fraud": "ceo_fraud_executive_spoofing",
    "whaling": "ceo_fraud_executive_spoofing",
    "credential_harvest": "credential_harvesting",
    "fake_login": "credential_harvesting",
    "phishing_mass": "credential_harvesting",
    "phishing_spear": "credential_harvesting",
    "mfa_fatigue": "credential_harvesting",
    "fake_invoice": "fake_invoice_fraud",
    "payroll_diversion": "fake_invoice_fraud",
    "advance_fee": "fake_invoice_fraud",
    "tax_impersonation": "tax_government_impersonation",
    "overpayment": "fake_invoice_fraud",
    "gift_card": "fake_invoice_fraud",
    "lottery": "fake_invoice_fraud",
    "romance_scam": "business_email_compromise",
    "identity_theft": "credential_harvesting",
    "fake_tech_support": "credential_harvesting",
    "sextortion": "credential_harvesting",
    "ransomware": "credential_harvesting",
    "deepfake": "business_email_compromise",
    "llm_phishing": "credential_harvesting",
    "mystery_shopper": "fake_invoice_fraud",
    "work_from_home": "fake_invoice_fraud",
    "greeting_card": "fake_invoice_fraud",
    "clone_phishing": "business_email_compromise",
    "angler_phishing": "credential_harvesting",
    "lookalike_domain": "credential_harvesting",
}

_model = None


def _candidate_paths():
    here = Path(__file__).resolve()
    return [
        here.parent.parent.parent / "tier0_model.txt",
        here.parent.parent.parent.parent / "tier0_model.txt",
        here.parent.parent.parent.parent.parent / "tier0_model.txt",
    ]


def model_path():
    for p in _candidate_paths():
        if p.exists():
            return p
    return None


def load_model():
    global _model
    if _model is not None:
        return _model
    if not HAS_LGB:
        return None
    path = model_path()
    if path is None:
        return None
    _model = lgb.Booster(model_file=str(path))
    return _model


def is_available():
    return load_model() is not None


def predict(features):
    model = load_model()
    if model is None:
        return None
    import numpy as np

    def as_float(value):
        # None is how "unknown" survives a JSON round trip; the model wants the
        # NaN it was trained to branch on.
        if value is None:
            return float("nan")
        try:
            return float(value)
        except (TypeError, ValueError):
            return float("nan")

    X = np.array([[as_float(features.get(c)) for c in FEATURE_COLS]], dtype=float)
    probs = model.predict(X)[0]
    probs = np.clip(probs, 0.0, 1.0)
    total = float(np.sum(probs))
    if total > 0:
        probs = probs / total
    legit_prob = float(probs[LEGIT_IDX])
    scam_score = round((1.0 - legit_prob) * 100.0, 1)
    cats = []
    for i, c in enumerate(CLASSES):
        if c == "legitimate":
            continue
        cats.append({"category": c, "confidence": round(float(probs[i]) * 100.0, 1)})
    cats.sort(key=lambda x: -x["confidence"])
    pred_class = CLASSES[int(np.argmax(probs))]
    return {
        "overall_scam_score": scam_score,
        "predicted_class": pred_class,
        "categories": cats,
        "model": "LightGBM Tier 0",
    }


def category_confidence_for(predicted, category_key):
    if predicted is None:
        return 0.0
    model_class = CATEGORY_ALIASES.get(category_key, category_key)
    for c in predicted["categories"]:
        if c["category"] == model_class:
            return c["confidence"] / 100.0
    return 0.0
