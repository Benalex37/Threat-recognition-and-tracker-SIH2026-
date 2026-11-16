"""Gatekeeper (Tier 0) decision engine.

Primary path: LightGBM classifier trained on `tier0_training_dataset.jsonl`
forensic features -> scam score + category ranking.

Fallback path: rule-based scoring (used when the model file or lightgbm is
unavailable) so the app still runs in environments without ML deps.
"""

from app.services import tier0_model


def _normalize(features: dict) -> dict:
    """Coerce forensic feature values to plain Python types."""
    out = {}
    for k, v in features.items():
        if hasattr(v, "item"):
            try:
                v = v.item()
            except Exception:
                pass
        out[k] = v
    return out


def run(features: dict, email_text: str, enabled_categories: dict) -> tuple[float, dict]:
    feats = _normalize(features)

    # ---- Tier 0 ML path ----
    pred = tier0_model.predict(feats)
    if pred is not None:
        score = pred["overall_scam_score"]
        active = [k for k, v in enabled_categories.items() if v]
        if not active:
            active = list(enabled_categories.keys())
        category_probs: dict = {}
        for cat in active:
            category_probs[cat] = round(
                tier0_model.category_confidence_for(pred, cat), 2
            )
        total = sum(category_probs.values())
        if total > 0:
            for cat in active:
                category_probs[cat] = round(category_probs.get(cat, 0.01) / total, 2)
        else:
            for cat in active:
                category_probs[cat] = round(1.0 / len(active), 2)
        return score, category_probs

    # ---- Fallback rule-based path ----
    score = 50
    if features.get("spf_pass"):
        score += 10
    else:
        score -= 15
    if features.get("dkim_pass"):
        score += 10
    else:
        score -= 10
    if features.get("dmarc_pass"):
        score += 5
    else:
        score -= 10
    age = features.get("domain_age_days", 365)
    if age < 7:
        score -= 25
    elif age < 30:
        score -= 10
    if features.get("ip_is_known_vpn_or_hosting"):
        score -= 15
    if features.get("header_anomaly_score", 0) > 0.7:
        score -= 20
    if features.get("relay_hop_count", 0) > 5:
        score -= 10
    lower_text = (email_text or "").lower()
    if "urgent" in lower_text:
        score -= 10
    if "wire transfer" in lower_text:
        score -= 15
    if "password" in lower_text and "click" in lower_text:
        score -= 10
    score = max(0, min(100, score))
    active = [k for k, v in enabled_categories.items() if v]
    if not active:
        active = list(enabled_categories.keys())
    subject = email_text.lower()
    category_probs = {}
    for cat in active:
        prob = 0.01
        keywords = {
            "bec": ["business email", "compromise", "invoice"],
            "vec": ["vendor", "payment", "change account"],
            "fake_invoice": ["invoice", "payment overdue", "billing"],
            "ceo_fraud": ["ceo", "executive", "urgent request", "confidential"],
            "payroll_diversion": ["payroll", "direct deposit", "account number"],
            "wire_fraud": ["wire", "transfer", "bank account"],
            "advance_fee": ["advance fee", "processing", "lottery"],
            "phishing_mass": ["verify your account", "click here", "login"],
            "phishing_spear": ["project update", "meeting", "proposal"],
            "whaling": ["ceo", "president", "board", "executive"],
            "clone_phishing": ["previous email", "resend", "updated"],
            "angler_phishing": ["support", "account issue", "help desk"],
            "lookalike_domain": ["paypa1", "go0gle", "micorsoft"],
            "sextortion": ["password", "browsing", "video"],
            "ransomware": ["encrypted", "bitcoin", "payment"],
            "credential_harvest": ["login", "credentials", "password"],
            "identity_theft": ["ssn", "social security", "identity"],
            "fake_tech_support": ["tech support", "remote access", "computer"],
            "mfa_fatigue": ["approve", "authentication", "mfa"],
            "fake_login": ["sign in", "verify identity", "update account"],
            "romance_scam": ["darling", "love", "sweetheart", "romance"],
            "gift_card": ["gift card", "apple", "itunes", "google play"],
            "lottery": ["winner", "lottery", "prize"],
            "overpayment": ["overpaid", "refund", "excess payment"],
            "tax_impersonation": ["irs", "tax", "penalty", "refund"],
            "deepfake": ["deepfake", "video call", "identity"],
            "llm_phishing": ["ai", "chatgpt", "language model", "automated"],
            "mystery_shopper": ["mystery shopper", "evaluate", "store"],
            "work_from_home": ["remote", "work from home", "salary"],
            "greeting_card": ["greeting card", "ecard", "click to view"],
        }
        words = keywords.get(cat, [])
        hits = sum(1 for w in words if w in subject)
        prob += hits * 0.2
        prob = min(prob, 0.99)
        category_probs[cat] = round(prob, 2)
    total = sum(category_probs.values())
    if total > 0:
        for cat in active:
            category_probs[cat] = round(category_probs.get(cat, 0.01) / total, 2)
    else:
        for cat in active:
            category_probs[cat] = round(1.0 / len(active), 2)
    return score, category_probs