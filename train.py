import json
import pandas as pd
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, classification_report

# ---- Load ----
rows = [json.loads(l) for l in open("./tier0_training_dataset.jsonl")]

records = []
for r in rows:
    rec = dict(r["input_features"])
    rec["true_label"] = r["true_label"]
    rec["email_id"] = r["email_id"]
    records.append(rec)
df = pd.DataFrame(records)

feature_cols = ["spf_pass", "dkim_pass", "dmarc_pass", "domain_age_days",
                "ip_in_spf_authorized_range", "geo_matches_expected_countries",
                "ip_is_known_vpn_or_hosting", "asn_reputation_score",
                "header_anomaly_score", "relay_hop_count"]

X = df[feature_cols].astype(float)
le = LabelEncoder()
y = le.fit_transform(df["true_label"])
CLASSES = le.classes_  # includes "legitimate" + 5 scam categories
LEGIT_IDX = list(CLASSES).index("legitimate")

# ---- 90/10 split ----
# NOTE: with only 50 rows, a 10% test split is 5 rows across 6 classes --
# stratification is mathematically impossible below (needs >= 1 test row per
# class, i.e. at least 6). Falling back to a plain random split and flagging
# this loudly rather than silently producing a meaningless "balanced" test set.
try:
    X_train, X_test, y_train, y_test, id_train, id_test = train_test_split(
        X, y, df["email_id"], test_size=0.1, random_state=42, stratify=y
    )
except ValueError as e:
    print(f"[WARNING] Stratified split failed ({e}) -- dataset is too small for a "
          f"9:1 split across {len(set(y))} classes. Falling back to a plain random "
          f"split. Treat the test metrics below as a smoke test, not a real evaluation.\n")
    X_train, X_test, y_train, y_test, id_train, id_test = train_test_split(
        X, y, df["email_id"], test_size=0.1, random_state=42
    )

print(f"Train size: {len(X_train)}  |  Test size: {len(X_test)}")
print(f"Test set email IDs: {list(id_test)}\n")

# ---- Train ----
model = lgb.LGBMClassifier(
    objective="multiclass",
    num_class=len(CLASSES),
    n_estimators=150,
    max_depth=4,
    min_child_samples=2,
    class_weight="balanced",
    verbose=-1,
)
model.fit(X_train, y_train)

# ---- Evaluate (diagnostic only -- see caveat below) ----
y_pred = model.predict(X_test)
print("Test accuracy:", accuracy_score(y_test, y_pred))
print(classification_report(y_test, y_pred, labels=range(len(CLASSES)),
                             target_names=CLASSES, zero_division=0))

# ---- Show real output format on the held-out test rows ----
print("=" * 60)
print("SAMPLE OUTPUT FORMAT (what Tier 0 should return per email)")
print("=" * 60)
probs = model.predict_proba(X_test)
for i, eid in enumerate(id_test):
    p = probs[i]
    scam_score = round((1 - p[LEGIT_IDX]) * 100, 1)
    scam_classes = [(c, prob) for c, prob in zip(CLASSES, p) if c != "legitimate"]
    total = sum(prob for _, prob in scam_classes) or 1e-9
    ranked = sorted(
        [{"category": c, "confidence": round(prob / total * 100)} for c, prob in scam_classes],
        key=lambda x: -x["confidence"]
    )
    print(f"\n{eid} (true: {CLASSES[y_test.tolist()[i]]})")
    print(f"  overall_scam_score: {scam_score}")
    for cat in ranked[:3]:
        print(f"    {cat['category']:30s}: {cat['confidence']}%")

model.booster_.save_model("./tier0_model.txt")
print("\nSaved model to tier0_model.txt")