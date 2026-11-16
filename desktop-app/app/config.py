from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

DATA_DIR = BASE_DIR / "data"
CONFIG_PATH = DATA_DIR / "config.json"
CASE_LOG_PATH = DATA_DIR / "case_log.jsonl"
LEDGER_PATH = DATA_DIR / "ledger.jsonl"
FINGERPRINT_INDEX_PATH = DATA_DIR / "fingerprint_index.json"
ADAPTER_MANIFEST_PATH = DATA_DIR / "adapter_manifest.json"
STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"
GEO_DATA_DIR = DATA_DIR / "geo"

# The port the engine listens on. The browser extension probes this first, so
# run.py, config.json and the extension must agree on one number.
DEFAULT_PORT = 8001

DEFAULT_CONFIG = {
    "device_tier": "high",
    "profile": "Default",
    "enabled_categories": {
        "bec": True,
        "vec": True,
        "fake_invoice": True,
        "ceo_fraud": True,
        "payroll_diversion": True,
        "wire_fraud": True,
        "advance_fee": True,
        "phishing_mass": True,
        "phishing_spear": True,
        "whaling": True,
        "clone_phishing": True,
        "angler_phishing": True,
        "lookalike_domain": True,
        "sextortion": True,
        "ransomware": True,
        "credential_harvest": True,
        "identity_theft": True,
        "fake_tech_support": True,
        "mfa_fatigue": True,
        "fake_login": True,
        "romance_scam": True,
        "gift_card": True,
        "lottery": True,
        "overpayment": True,
        "tax_impersonation": True,
        "deepfake": True,
        "llm_phishing": True,
        "mystery_shopper": True,
        "work_from_home": True,
        "greeting_card": True,
    },
    "thresholds": {
        "high": 80,
        "ambiguous_low": 15,
        "ambiguous_high": 80,
        "tier1_confirm": 0.7,
    },
    "local_port": DEFAULT_PORT,
    "campaign_sync_enabled": False,
    # Outbound-lookup policy. IP enrichment is served from local IP2Location
    # LITE / MaxMind databases, so the web API stays off unless asked for.
    "allow_online_lookups": False,
    "enable_dns_lookups": True,
    "enable_whois_lookups": True,
    "dns_timeout_seconds": 3.0,
    "whois_timeout_seconds": 6.0,
}

PRESETS = {
    "Financial Institution": {
        "bec": True,
        "vec": True,
        "wire_fraud": True,
        "whaling": True,
        "tax_impersonation": True,
        "payroll_diversion": True,
        "ceo_fraud": True,
        "fake_invoice": True,
        "advance_fee": True,
        "phishing_spear": True,
    },
    "Tech/SaaS": {
        "bec": True,
        "fake_invoice": True,
        "credential_harvest": True,
        "lookalike_domain": True,
        "phishing_spear": True,
        "mfa_fatigue": True,
        "fake_login": True,
        "llm_phishing": True,
        "phishing_mass": True,
        "ransomware": True,
    },
}


def ensure_data_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    GEO_DATA_DIR.mkdir(parents=True, exist_ok=True)


def load_config() -> dict:
    if CONFIG_PATH.exists():
        import json
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        merged = DEFAULT_CONFIG.copy()
        merged.update(cfg)
        file_cats = cfg.get("enabled_categories", {})
        default_cats = DEFAULT_CONFIG["enabled_categories"].copy()
        default_cats.update(file_cats)
        merged["enabled_categories"] = default_cats
        merged.setdefault("thresholds", DEFAULT_CONFIG["thresholds"].copy())
        return merged
    return DEFAULT_CONFIG.copy()


def save_config(config: dict) -> None:
    from app.services.storage import atomic_write_json
    atomic_write_json(CONFIG_PATH, config)


def get_preset(preset_name: str) -> dict:
    return PRESETS.get(preset_name, {}).copy()
