"""Seed the case log with a representative set of cases for the dashboard.

Every case carries a real sender IP that is resolved through the offline
IP2Location LITE / MaxMind chain, so the map, the legend and the geo panel all
render from the same code path that live traffic uses.

Run:  python scripts/generate_seed_data.py
"""

import json
import random
import sys
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from app.config import DATA_DIR
from app.services import ip2location

# Sender IPs spread across regions so the map has something to show. Each is
# resolved locally at generation time - nothing here is hand-placed.
SENDER_IPS = {
    "ru": "5.45.207.1",
    "ng": "41.58.128.1",
    "cn": "116.62.0.1",
    "in": "103.21.58.1",
    "fr": "51.15.0.1",
    "de": "85.10.192.1",
    "us_east": "23.20.0.1",
    "us_west": "52.52.0.1",
    "br": "177.53.128.1",
    "ua": "91.196.178.1",
    "gb": "51.140.0.1",
    "sg": "128.199.128.1",
}


def _case(message_id, score, category, fingerprint, ip, evidence, features, when):
    flagged = score >= 80
    geo = ip2location.locate(ip) or {}
    return {
        "messageId": message_id,
        "score": score,
        "flagged": flagged,
        "category": category,
        "safeScore": round(100 - score, 1),
        "evidence": evidence,
        "processedLocally": True,
        "fingerprint": fingerprint,
        "features": features,
        "senderIp": ip,
        "geo": geo or None,
        "timestamp": when.isoformat(),
    }


def generate_seed_data():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    case_log_path = DATA_DIR / "case_log.jsonl"
    fingerprint_index_path = DATA_DIR / "fingerprint_index.json"

    random.seed(20260911)
    now = datetime.now(timezone.utc)
    cases = []

    cases.append(_case(
        f"msg_{uuid.uuid4().hex[:12]}", 92.5, "bec", "bec_template_fingerprint_001",
        SENDER_IPS["ru"],
        [
            {"factor": "SPF Check", "contribution": -15, "explanation": "SPF record missing or failed"},
            {"factor": "Domain Age", "contribution": -25, "explanation": "Domain registered 3 days ago"},
            {"factor": "Tier 1 AI", "contribution": 45, "explanation": "LoRA adapter bec confirmed with confidence 0.95"},
        ],
        {"spf_pass": False, "dkim_pass": False, "dmarc_pass": False, "domain_age_days": 3,
         "ip_is_known_vpn_or_hosting": True, "asn_reputation_score": 0.15, "relay_hop_count": 7},
        now - timedelta(hours=5),
    ))
    cases.append(_case(
        f"msg_{uuid.uuid4().hex[:12]}", 88.0, "fake_invoice", "invoice_template_fingerprint_002",
        SENDER_IPS["fr"],
        [
            {"factor": "Urgent Language", "contribution": -10, "explanation": "Message contains urgency triggers"},
            {"factor": "Tier 1 AI", "contribution": 40, "explanation": "LoRA adapter fake_invoice confirmed with confidence 0.88"},
        ],
        {"spf_pass": True, "dkim_pass": False, "dmarc_pass": False, "domain_age_days": 150,
         "ip_is_known_vpn_or_hosting": True, "asn_reputation_score": 0.25, "relay_hop_count": 4},
        now - timedelta(hours=12),
    ))
    cases.append(_case(
        f"msg_{uuid.uuid4().hex[:12]}", 95.0, "ceo_fraud", "ceo_template_fingerprint_003",
        SENDER_IPS["ng"],
        [
            {"factor": "Wire Transfer", "contribution": -15, "explanation": "Message requests wire transfer"},
            {"factor": "Tier 1 AI", "contribution": 45, "explanation": "LoRA adapter ceo_fraud confirmed with confidence 0.98"},
        ],
        {"spf_pass": False, "dkim_pass": False, "dmarc_pass": False, "domain_age_days": 11,
         "ip_is_known_vpn_or_hosting": False, "asn_reputation_score": 0.3, "relay_hop_count": 6},
        now - timedelta(hours=26),
    ))
    cases.append(_case(
        f"msg_{uuid.uuid4().hex[:12]}", 85.5, "credential_harvest", "cred_template_fingerprint_004",
        SENDER_IPS["cn"],
        [
            {"factor": "Credential Phish", "contribution": -10, "explanation": "Password and CTA detected"},
            {"factor": "Tier 1 AI", "contribution": 35, "explanation": "LoRA adapter credential_harvest confirmed with confidence 0.82"},
        ],
        {"spf_pass": True, "dkim_pass": False, "dmarc_pass": False, "domain_age_days": 10,
         "ip_is_known_vpn_or_hosting": True, "asn_reputation_score": 0.2, "relay_hop_count": 5},
        now - timedelta(hours=2),
    ))
    cases.append(_case(
        f"msg_{uuid.uuid4().hex[:12]}", 89.0, "tax_impersonation", "tax_template_fingerprint_005",
        SENDER_IPS["in"],
        [
            {"factor": "DMARC Check", "contribution": -10, "explanation": "DMARC policy rejected or missing"},
            {"factor": "Tier 1 AI", "contribution": 42, "explanation": "LoRA adapter tax_impersonation confirmed with confidence 0.90"},
        ],
        {"spf_pass": True, "dkim_pass": True, "dmarc_pass": False, "domain_age_days": 42,
         "ip_is_known_vpn_or_hosting": False, "asn_reputation_score": 0.7, "relay_hop_count": 3},
        now - timedelta(hours=40),
    ))
    cases.append(_case(
        f"msg_{uuid.uuid4().hex[:12]}", 64.0, "credential_harvest", "cred_template_fingerprint_008",
        SENDER_IPS["br"],
        [{"factor": "Header Anomaly", "contribution": -20, "explanation": "Unusual relay hop count detected"}],
        {"spf_pass": True, "dkim_pass": True, "dmarc_pass": False, "domain_age_days": 95,
         "ip_is_known_vpn_or_hosting": False, "asn_reputation_score": 0.6, "relay_hop_count": 8},
        now - timedelta(hours=7),
    ))
    cases.append(_case(
        f"msg_{uuid.uuid4().hex[:12]}", 38.0, "bec", "bec_template_fingerprint_009",
        SENDER_IPS["sg"],
        [{"factor": "IP Reputation", "contribution": -15, "explanation": "IP belongs to known VPN/hosting provider"}],
        {"spf_pass": True, "dkim_pass": True, "dmarc_pass": True, "domain_age_days": 400,
         "ip_is_known_vpn_or_hosting": True, "asn_reputation_score": 0.25, "relay_hop_count": 3},
        now - timedelta(hours=3),
    ))

    for label, ip, hours in (("safe_006", SENDER_IPS["us_west"], 1), ("safe_007", SENDER_IPS["us_east"], 0.5)):
        cases.append(_case(
            f"msg_{uuid.uuid4().hex[:12]}", 10.0 if label.endswith("6") else 5.0, None,
            f"{label}_fingerprint", ip, [],
            {"spf_pass": True, "dkim_pass": True, "dmarc_pass": True, "domain_age_days": 3800,
             "ip_is_known_vpn_or_hosting": False, "asn_reputation_score": 0.85, "relay_hop_count": 2},
            now - timedelta(hours=hours),
        ))

    # A campaign: one template, several recipients, two staging countries.
    campaign_fp = "campaign_fingerprint_123"
    for index in range(5):
        cases.append(_case(
            f"msg_{uuid.uuid4().hex[:12]}", 90.0 + index * 0.5, "bec", campaign_fp,
            SENDER_IPS["ua"] if index % 2 == 0 else SENDER_IPS["de"],
            [{"factor": "Tier 1 AI", "contribution": 40, "explanation": "LoRA adapter bec confirmed"}],
            {"spf_pass": False, "dkim_pass": False, "dmarc_pass": False, "domain_age_days": 5,
             "ip_is_known_vpn_or_hosting": True, "asn_reputation_score": 0.15, "relay_hop_count": 6},
            now - timedelta(minutes=18 * index),
        ))

    # A second, smaller campaign reusing one invoice template.
    invoice_fp = "campaign_invoice_fingerprint_456"
    for index in range(3):
        cases.append(_case(
            f"msg_{uuid.uuid4().hex[:12]}", 86.0 + index, "fake_invoice", invoice_fp,
            SENDER_IPS["gb"],
            [{"factor": "Tier 1 AI", "contribution": 38, "explanation": "LoRA adapter fake_invoice confirmed"}],
            {"spf_pass": True, "dkim_pass": False, "dmarc_pass": False, "domain_age_days": 22,
             "ip_is_known_vpn_or_hosting": True, "asn_reputation_score": 0.25, "relay_hop_count": 5},
            now - timedelta(minutes=45 + 25 * index),
        ))

    cases.sort(key=lambda c: c["timestamp"])
    with open(case_log_path, "w", encoding="utf-8") as handle:
        for case in cases:
            handle.write(json.dumps(case) + "\n")

    fingerprints = {}
    for case in cases:
        fingerprint = case["fingerprint"]
        entry = fingerprints.setdefault(
            fingerprint, {"first_seen": case["timestamp"], "count": 0, "category": case["category"]}
        )
        entry["count"] += 1
        entry["first_seen"] = min(entry["first_seen"], case["timestamp"])
    with open(fingerprint_index_path, "w", encoding="utf-8") as handle:
        json.dump(fingerprints, handle, indent=2)

    located = sum(1 for c in cases if (c.get("geo") or {}).get("lat") is not None)
    print(f"Generated {len(cases)} cases in {case_log_path}")
    print(f"  {located} resolved to coordinates via {ip2location.status()['activeProvider']}")
    print(f"Generated {len(fingerprints)} fingerprints in {fingerprint_index_path}")


if __name__ == "__main__":
    generate_seed_data()
