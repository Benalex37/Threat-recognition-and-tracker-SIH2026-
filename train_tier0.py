"""Tier 0 gatekeeper training.

Replaces the previous trainer, which learned nothing useful because the source
dataset leaks its own labels: `dkim_pass`, `dmarc_pass` and
`ip_in_spf_authorized_range` are true for 300/300 legitimate rows and false for
0/3000 scam rows. Any one of them separates the classes perfectly, so the model
became a single-feature lookup and scored real mail at 100/100 fraud the moment
DKIM could not be verified.

Three things are fixed here.

1. The leak is broken by adding rows that reality actually produces:
   legitimate senders whose DKIM cannot be verified, legitimate bulk mail from
   hosting ASNs, and — most importantly — attacks sent from compromised
   accounts that pass SPF, DKIM and DMARC cleanly. Authentication is evidence,
   not proof, and the model has to learn that.

2. "Unverifiable" is represented as NaN rather than False, matching what
   `compute_forensic_features` now emits. LightGBM learns an explicit branch
   for missing values, so an unverified message is no longer scored as a
   confirmed forgery.

3. Evaluation reports the false-positive rate on legitimate mail separately,
   because that is the number the previous model failed on and overall
   accuracy hides it behind the 10:1 class imbalance.

The augmented rows are synthetic. They encode documented email behaviour, not
observed traffic, and they are a stopgap: the real fix is labelled mail from
the deployment itself, fed back through the confirm/override control.
"""

import json
import math
import random

import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

SEED = 42
random.seed(SEED)
np.random.seed(SEED)

SOURCE = "./tier0_training_dataset.jsonl"
OUT_MODEL = "./tier0_model.txt"

FEATURE_COLS = [
    "spf_pass", "dkim_pass", "dmarc_pass", "domain_age_days",
    "ip_in_spf_authorized_range", "geo_matches_expected_countries",
    "ip_is_known_vpn_or_hosting", "asn_reputation_score",
    "header_anomaly_score", "relay_hop_count",
]

SCAM_LABELS = [
    "business_email_compromise",
    "ceo_fraud_executive_spoofing",
    "credential_harvesting",
    "fake_invoice_fraud",
    "tax_government_impersonation",
]

NAN = float("nan")


def load_base():
    rows = []
    with open(SOURCE, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            item = dict(record["input_features"])
            item["true_label"] = record["true_label"]
            # The source caps nothing, but serving computes anomaly as the
            # excess over a normal 5-hop delivery. Rescale so both agree.
            item["header_anomaly_score"] = max(0.0, (item.get("relay_hop_count", 0) - 5) / 5.0)
            rows.append(item)
    return rows


def legit_unverifiable(n):
    """Legitimate mail the engine cannot authenticate.

    No Authentication-Results header, or a DKIM selector that cannot be
    guessed from DNS. This is the single largest real-world case and the one
    the old model called fraud every time.
    """
    out = []
    for _ in range(n):
        out.append({
            "spf_pass": random.choice([1.0, 1.0, NAN]),
            "dkim_pass": NAN,
            "dmarc_pass": random.choice([NAN, NAN, 1.0]),
            "domain_age_days": random.choice([
                random.randint(400, 12000),     # established organisation
                random.randint(60, 400),        # newer but legitimate
            ]),
            "ip_in_spf_authorized_range": random.choice([1.0, NAN]),
            "geo_matches_expected_countries": 1.0,
            "ip_is_known_vpn_or_hosting": 0.0,
            "asn_reputation_score": round(random.uniform(0.55, 0.9), 2),
            "relay_hop_count": random.randint(1, 8),
            "true_label": "legitimate",
        })
    return out


def legit_bulk_sender(n):
    """Legitimate transactional mail relayed by SaaS infrastructure.

    Stripe receipts, GitHub notifications, Zendesk replies: every one of these
    originates from a hosting ASN, which the old feature set treated as a
    fraud signal on its own.
    """
    out = []
    for _ in range(n):
        out.append({
            "spf_pass": 1.0,
            "dkim_pass": random.choice([1.0, NAN]),
            "dmarc_pass": random.choice([1.0, NAN]),
            "domain_age_days": random.randint(800, 9000),
            "ip_in_spf_authorized_range": 1.0,
            "geo_matches_expected_countries": random.choice([1.0, 1.0, 0.0]),
            "ip_is_known_vpn_or_hosting": 1.0,
            "asn_reputation_score": round(random.uniform(0.25, 0.6), 2),
            "relay_hop_count": random.randint(2, 7),
            "true_label": "legitimate",
        })
    return out


def compromised_account_attack(n):
    """Attacks sent from a real, fully authenticated mailbox.

    Vendor and business email compromise are exactly this: the attacker owns a
    genuine account, so SPF, DKIM and DMARC all pass and the domain is old.
    Without these rows the model concludes that passing authentication proves a
    message is safe, which is the inverse of the failure it has today.

    Every row carries at least one infrastructure anomaly — the session comes
    from somewhere the sender does not normally send from, or through relaying
    the domain does not normally use. That constraint matters: a takeover with
    no header-visible trace is genuinely indistinguishable from legitimate mail
    at this tier, and generating those rows would only teach the model to flag
    clean traffic. Attacks that are visible in the wording alone are Tier 1's
    job, which is why the cascade has a second stage at all.
    """
    out = []
    anomalies = ("geo", "hosting", "relay")
    for _ in range(n):
        chosen = random.sample(anomalies, random.randint(1, 3))
        out.append({
            "spf_pass": 1.0,
            "dkim_pass": 1.0,
            "dmarc_pass": 1.0,
            "domain_age_days": random.randint(600, 9000),
            "ip_in_spf_authorized_range": 1.0,
            "geo_matches_expected_countries": 0.0 if "geo" in chosen else 1.0,
            "ip_is_known_vpn_or_hosting": 1.0 if "hosting" in chosen else 0.0,
            "asn_reputation_score": round(
                random.uniform(0.1, 0.35) if "hosting" in chosen else random.uniform(0.5, 0.85), 2
            ),
            "relay_hop_count": random.randint(9, 13) if "relay" in chosen else random.randint(2, 6),
            "true_label": random.choice([
                "business_email_compromise",
                "business_email_compromise",
                "ceo_fraud_executive_spoofing",
                "fake_invoice_fraud",
            ]),
        })
    return out


def build_dataset():
    rows = load_base()
    base_legit = sum(1 for r in rows if r["true_label"] == "legitimate")
    base_scam = len(rows) - base_legit

    added = legit_unverifiable(1400) + legit_bulk_sender(600) + compromised_account_attack(900)
    rows.extend(added)

    df = pd.DataFrame(rows)
    print(f"Base rows      : {len(rows) - len(added)}  ({base_legit} legitimate, {base_scam} scam)")
    print(f"Added rows     : {len(added)}")
    print(f"Total          : {len(df)}")
    print()
    print("Label distribution:")
    for label, count in df["true_label"].value_counts().items():
        print(f"  {label:32s} {count}")
    return df


def leakage_report(df):
    """Fail loudly if any single feature still separates the classes."""
    print("\nLeakage check — a feature that alone separates the classes is a bug:")
    is_legit = df["true_label"] == "legitimate"
    worst = 0.0
    for col in ("spf_pass", "dkim_pass", "dmarc_pass", "ip_in_spf_authorized_range"):
        legit_true = float(np.nansum(df.loc[is_legit, col] == 1))
        scam_true = float(np.nansum(df.loc[~is_legit, col] == 1))
        legit_rate = legit_true / max(1, is_legit.sum())
        scam_rate = scam_true / max(1, (~is_legit).sum())
        gap = abs(legit_rate - scam_rate)
        worst = max(worst, gap)
        flag = "  <-- still separating" if gap > 0.95 else ""
        print(f"  {col:30s} legit {legit_rate:5.1%} | scam {scam_rate:5.1%} | gap {gap:5.1%}{flag}")
    if worst > 0.95:
        raise SystemExit("Aborting: a single feature still separates the classes.")


def main():
    df = build_dataset()
    leakage_report(df)

    labels = sorted(df["true_label"].unique())
    label_to_id = {name: i for i, name in enumerate(labels)}
    legit_idx = label_to_id["legitimate"]

    X = df[FEATURE_COLS].astype(float)
    y = df["true_label"].map(label_to_id).to_numpy()

    X_train, X_hold, y_train, y_hold = train_test_split(
        X, y, test_size=0.2, random_state=SEED, stratify=y
    )
    X_fit, X_val, y_fit, y_val = train_test_split(
        X_train, y_train, test_size=0.2, random_state=SEED, stratify=y_train
    )

    model = lgb.LGBMClassifier(
        objective="multiclass",
        num_class=len(labels),
        n_estimators=600,
        learning_rate=0.05,
        max_depth=5,
        num_leaves=24,
        min_child_samples=30,      # was 2 — the old value let leaves memorise
        subsample=0.85,
        subsample_freq=1,
        colsample_bytree=0.8,
        reg_lambda=1.0,
        class_weight="balanced",
        random_state=SEED,
        verbose=-1,
    )
    model.fit(
        X_fit, y_fit,
        eval_set=[(X_val, y_val)],
        eval_metric="multi_logloss",
        callbacks=[lgb.early_stopping(40, verbose=False), lgb.log_evaluation(0)],
    )
    print(f"\nBest iteration: {model.best_iteration_} of {model.n_estimators}")

    y_pred = model.predict(X_hold)
    print("\nHeld-out performance")
    print(classification_report(y_hold, y_pred, target_names=labels, zero_division=0))

    # The number that actually matters: how often legitimate mail is flagged.
    legit_mask = y_hold == legit_idx
    false_positives = int(np.sum(y_pred[legit_mask] != legit_idx))
    total_legit = int(np.sum(legit_mask))
    scam_mask = ~legit_mask
    missed = int(np.sum(y_pred[scam_mask] == legit_idx))
    print(f"False positives : {false_positives}/{total_legit} legitimate messages flagged "
          f"({false_positives / max(1, total_legit):.1%})")
    print(f"Missed attacks  : {missed}/{int(np.sum(scam_mask))} scam messages passed as legitimate "
          f"({missed / max(1, int(np.sum(scam_mask))):.1%})")

    print("\nConfusion matrix (rows = truth, cols = predicted)")
    print(pd.DataFrame(
        confusion_matrix(y_hold, y_pred),
        index=[f"true:{l[:18]}" for l in labels],
        columns=[f"pred:{l[:12]}" for l in labels],
    ).to_string())

    fit_diagnosis(model, X_fit, y_fit, X_hold, y_hold, legit_idx, labels)

    print("\nFeature importance (gain)")
    for name, gain in sorted(
        zip(FEATURE_COLS, model.booster_.feature_importance("gain")),
        key=lambda kv: -kv[1],
    ):
        print(f"  {name:32s} {gain:12.1f}")

    serving_check(model, labels, legit_idx)

    model.booster_.save_model(OUT_MODEL)
    print(f"\nSaved model to {OUT_MODEL}")


def fit_diagnosis(model, X_fit, y_fit, X_hold, y_hold, legit_idx, labels):
    """Separate the two jobs Tier 0 does, and say whether the fit is sound.

    Reporting one six-way accuracy conflates them and reads as a bad model.
    Tier 0 decides whether a message is suspicious, using header and
    infrastructure features only. Which *kind* of fraud it is depends on the
    wording, which Tier 0 never sees, so its category ranking exists to order
    the Tier 1 checks — not to be the verdict.
    """
    train_pred = model.predict(X_fit)
    hold_pred = model.predict(X_hold)

    def binary(y):
        return (y == legit_idx).astype(int)

    train_bin = float(np.mean(binary(train_pred) == binary(y_fit)))
    hold_bin = float(np.mean(binary(hold_pred) == binary(y_hold)))
    train_multi = float(np.mean(train_pred == y_fit))
    hold_multi = float(np.mean(hold_pred == y_hold))

    print("\nFit diagnosis")
    print(f"  legitimate vs suspicious  train {train_bin:.3f}   held-out {hold_bin:.3f}   "
          f"gap {train_bin - hold_bin:+.3f}   <- the decision Tier 0 makes")
    print(f"  which fraud category      train {train_multi:.3f}   held-out {hold_multi:.3f}   "
          f"gap {train_multi - hold_multi:+.3f}   <- ranking only, headers cannot see wording")

    gap = train_bin - hold_bin
    if gap > 0.10:
        print("  -> overfitting on the decision that matters")
    elif hold_bin < 0.85:
        print("  -> underfitting: the header signal is not being captured")
    else:
        print("  -> fits well: strong on held-out data with a small gap")


def serving_check(model, labels, legit_idx):
    """Score the vectors the live engine actually produces.

    Held-out accuracy is measured on the same generator that made the training
    rows, so it cannot reveal train/serve skew. These cases are hand-built to
    match what `compute_forensic_features` emits in each real situation.
    """
    cases = [
        ("legit, Gmail headers present, all pass",
         dict(spf_pass=1, dkim_pass=1, dmarc_pass=1, domain_age_days=4000,
              ip_in_spf_authorized_range=1, geo_matches_expected_countries=1,
              ip_is_known_vpn_or_hosting=0, asn_reputation_score=0.85,
              header_anomaly_score=0.2, relay_hop_count=6), "legitimate"),
        ("legit, DKIM unverifiable (custom selector)",
         dict(spf_pass=1, dkim_pass=NAN, dmarc_pass=NAN, domain_age_days=4000,
              ip_in_spf_authorized_range=1, geo_matches_expected_countries=1,
              ip_is_known_vpn_or_hosting=0, asn_reputation_score=0.85,
              header_anomaly_score=0.2, relay_hop_count=6), "legitimate"),
        ("legit SaaS receipt from hosting ASN",
         dict(spf_pass=1, dkim_pass=NAN, dmarc_pass=1, domain_age_days=3000,
              ip_in_spf_authorized_range=1, geo_matches_expected_countries=1,
              ip_is_known_vpn_or_hosting=1, asn_reputation_score=0.3,
              header_anomaly_score=0.0, relay_hop_count=4), "legitimate"),
        ("legit, whois failed so age unknown",
         dict(spf_pass=1, dkim_pass=NAN, dmarc_pass=NAN, domain_age_days=NAN,
              ip_in_spf_authorized_range=1, geo_matches_expected_countries=1,
              ip_is_known_vpn_or_hosting=0, asn_reputation_score=0.7,
              header_anomaly_score=0.2, relay_hop_count=6), "legitimate"),
        ("badge path: nothing verifiable at all",
         dict(spf_pass=NAN, dkim_pass=NAN, dmarc_pass=NAN, domain_age_days=NAN,
              ip_in_spf_authorized_range=NAN, geo_matches_expected_countries=1,
              ip_is_known_vpn_or_hosting=0, asn_reputation_score=0.5,
              header_anomaly_score=0.0, relay_hop_count=0), "legitimate"),
        ("attack: young domain, auth fails, hosting IP",
         dict(spf_pass=0, dkim_pass=0, dmarc_pass=0, domain_age_days=6,
              ip_in_spf_authorized_range=0, geo_matches_expected_countries=0,
              ip_is_known_vpn_or_hosting=1, asn_reputation_score=0.15,
              header_anomaly_score=0.6, relay_hop_count=8), "flag"),
        ("attack: compromised account, mild infra signal",
         dict(spf_pass=1, dkim_pass=1, dmarc_pass=1, domain_age_days=2500,
              ip_in_spf_authorized_range=1, geo_matches_expected_countries=0,
              ip_is_known_vpn_or_hosting=1, asn_reputation_score=0.5,
              header_anomaly_score=0.4, relay_hop_count=7), "escalate"),
    ]

    # The thresholds the live cascade uses (see data/config.json).
    AMBIGUOUS_LOW, HIGH = 15, 80

    def outcome(score):
        if score >= HIGH:
            return "flag"
        if score >= AMBIGUOUS_LOW:
            return "escalate"
        return "clean"

    print("\nServing-realism check (vectors the live engine actually emits)")
    print("  clean = delivered · escalate = handed to Tier 1 · flag = blocked at Tier 0")
    failures = 0
    for name, feats, expected in cases:
        row = np.array([[float(feats[c]) for c in FEATURE_COLS]], dtype=float)
        probs = model.predict_proba(row)[0]
        scam_score = round((1.0 - probs[legit_idx]) * 100, 1)
        got = outcome(scam_score)
        # Legitimate mail must never be flagged; escalation is acceptable
        # because Tier 1 clears it. An attack must at least escalate.
        if expected == "legitimate":
            ok = got != "flag"
        elif expected == "escalate":
            ok = got in ("escalate", "flag")
        else:
            ok = got == "flag"
        failures += not ok
        print(f"  [{'ok ' if ok else 'FAIL'}] {name:46s} scam={scam_score:5.1f}  -> {got}")
    if failures:
        print(f"\n  {failures} serving case(s) still wrong.")
    else:
        print("\n  All serving cases behave correctly.")


if __name__ == "__main__":
    main()
