# Desktop Application — Prototype Specification

---

## 1. Purpose

This is the "brain" of the system — the local Windows application that runs the actual detection models, exposes a local API to the browser extension, stores case history, and serves the Security Operations Dashboard. This document scopes it down to what's realistic to actually build and demo, not the full long-term feature set.

---

## 2. Prototype Scope — What's In, What's Cut

| Area | Full Vision | Prototype Scope |
|---|---|---|
| Scam categories | ~30 subtypes, full taxonomy | **5 categories**, fully working: BEC, Fake-Invoice Fraud, CEO Fraud/Whaling, Credential Harvesting, Tax/Government Agency Impersonation |
| Tier 1 specialists | LoRA adapter per category, all 30 | LoRA adapter per category, **5 trained** — architecture identical, just fewer adapters trained ahead of the demo |
| Device tiering | Multi-device config (work machine vs. laptop, admin-managed) | Single-device config file — the tiering *mechanism* is built and demoable (toggle categories on/off), but only tested on one machine |
| Campaign correlation | Cross-device fingerprint sync via shared org index | **Single-device demo**: seeded synthetic emails sharing a template fingerprint, clustered locally — proves the mechanism without needing a second machine live in the room |
| Security Ops Dashboard | Full investigator platform | Core version: geolocation map + campaign graph + basic stats — enough to be the demo's visual centerpiece, not the full admin suite |
| Storage | JSON/JSONL, as decided | Unchanged — same design, just smaller data volume |
| IP/header/geolocation forensics | Full | **Fully built** — this is cheap, deterministic, and doesn't depend on any model training, so there's no reason to scope it down |
| Multi-org / cross-org sharing | Roadmap only | Not built |

**Why these five categories specifically:** they're the most demo-friendly (clear before/after contrast), the most relevant to the financial-institution framing, and public/synthesizable training data is realistically available for all five within a hackathon timeline.

---

## 3. Core Features (Prototype Build)

### 3.1 Local API Server
- FastAPI app, bound to `127.0.0.1`, configurable port (default `8000`).
- This is the only interface the browser extension ever talks to — full build, not scoped down, since everything else depends on it.

### 3.2 Ingestion & Header Forensics
- Fetches full message headers via the Gmail API.
- Parses `Received:` chain, identifies the trust-boundary IP, cross-references `Authentication-Results` for the SPF-validated IP.
- Runs SPF/DKIM/DMARC validation.
- WHOIS lookup for domain age.
- Geolocates the trust-boundary IP via offline GeoLite2.
- **Fully built** — no model dependency, cheap to implement, and it's the foundation the dashboard's map (Section 3.6) needs anyway.

### 3.3 Tier 0 — Gatekeeper
- LightGBM/XGBoost classifier over engineered features (header anomalies, domain age, IP trust signals, basic content heuristics).
- Outputs an overall fraud probability and a probability distribution across the 5 prototype categories.
- **Fully built** — fast to train, no GPU needed, and every downstream feature depends on it working.

### 3.4 Tier 1 — Specialist Classification (Scoped)
- One ModernBERT-base instance loaded in memory.
- **5 trained LoRA adapters** (one per prototype category, Section 2), fine-tuned via HuggingFace PEFT on a combined dataset of public phishing corpora (Nazario, Enron-as-negative-examples) plus a small set of synthetically generated examples per category to cover patterns the public datasets don't (e.g., India-specific tax-impersonation phrasing, BEC-style executive tone).
- Dynamic attach/detach exactly as designed — the *mechanism* is fully built, only the number of trained adapters is scoped down.
- **Recommended prep timing:** fine-tune these 5 adapters *before* the build clock starts, if at all possible — training 5 classifiers live during a hackathon is a real time risk, and having them pre-trained lets the actual build hours go toward the pipeline, extension, and dashboard.

### 3.5 Evidence-Chain Scoring
- Composite score assembled from every signal above, returned as a structured list of `{factor, contribution, explanation}` — not collapsed into a single number.
- **Fully built** — this is glue logic over data already being computed, not a separate heavy component.

### 3.6 Security Operations Dashboard (Core Version)
- Served as a simple local web page by the same FastAPI app, at `/dashboard`.
- **Geolocation map:** plots every analyzed email's trust-boundary IP, with flagged ones visually distinguished. Fully functional — it's just reading data already computed in 3.2.
- **Campaign graph:** shows clustering across the seeded demo emails (Section 2) via the template-fingerprint mechanism — the graph rendering and clustering logic are fully built, just demonstrated on a single-device dataset rather than a live multi-device org.
- **Basic stats panel:** count analyzed, count flagged, breakdown by category — straightforward aggregation over `case_log.jsonl`.
- Skipped for prototype: full historical trend charts, per-device coverage reporting, admin user-management screens.

### 3.7 Config & Settings
- `config.json` holds: which of the 5 category adapters are enabled/disabled (so the "device tiering" *concept* is demoable even on one machine — toggle a category off, show the fallback header-check kick in instead), thresholds, org preset name.
- A minimal settings screen (can be a simple local web page or a lightweight desktop UI) to view/edit this.

### 3.8 Feedback Loop
- "Confirm Threat" / "Report False Positive" buttons write to the local case log and apply the immediate per-sender override described in the extension spec.
- The "feeds future retraining" half is built as a data-collection mechanism (appending labeled examples to a file) — actually re-running fine-tuning is out of scope for the prototype demo itself, but the pipeline that *would* consume that data should exist and be describable.

---

## 4. What's Explicitly Stubbed or Mocked for the Prototype

- **Cross-device sync:** no second physical machine — the shared fingerprint index is simulated by seeding the local case log with multiple synthetic "received" emails ahead of the demo, exactly as planned in the original demo script.
- **Multi-device admin management:** the config file mechanism is real and functional; there's no multi-user admin console needed since it's a single-machine demo.
- **Retraining pipeline execution:** feedback is logged for real; an actual retraining run is described, not executed live.

---

## 5. Tech Stack

| Layer | Choice |
|---|---|
| Application language | Python |
| Local API | FastAPI, `127.0.0.1` only |
| Base model | ModernBERT-base |
| Adapter training/serving | HuggingFace PEFT (LoRA) |
| Gatekeeper (Tier 0) | LightGBM |
| Header/protocol checks | Python `email`, `checkdmarc`, `dkimpy`, `pyspf` |
| Geolocation | MaxMind GeoLite2 (offline) |
| WHOIS | `python-whois` |
| Storage | Plain JSON / JSONL files |
| Dashboard rendering | Served via FastAPI; Leaflet.js for the map, `vis-network` or `d3-force` for the campaign graph |
| Gmail access | Gmail API, OAuth (`gmail.readonly` baseline; `gmail.modify` only if quarantine action is included in the demo) |

---

## 6. Folder Structure

```
desktop-app/
├── app/
│   ├── main.py                     # FastAPI entrypoint
│   ├── api/
│   │   └── routes.py               # /analyze, /health, /dashboard, /config
│   ├── ingestion/
│   │   └── parser.py               # header parsing, Gmail API client
│   ├── forensics/
│   │   ├── protocol.py             # SPF/DKIM/DMARC
│   │   ├── ip_trust.py             # trust-boundary extraction, geolocation
│   │   └── domain_intel.py         # WHOIS
│   ├── detection/
│   │   ├── gatekeeper.py           # Tier 0
│   │   ├── base_model.py           # ModernBERT loader
│   │   ├── adapters/               # 5 trained LoRA adapter files
│   │   └── cascade.py              # decision logic (Section 6 of system spec)
│   ├── fingerprint/
│   │   └── campaign.py             # template normalization, SimHash, clustering
│   ├── storage/
│   │   ├── config.json
│   │   ├── case_log.jsonl
│   │   └── fingerprint_index.json
│   └── dashboard/
│       ├── templates/              # dashboard HTML
│       └── static/                 # map/graph JS
├── scripts/
│   ├── train_adapter.py            # fine-tuning script, run once per category ahead of demo
│   └── generate_seed_data.py       # synthetic demo emails (5 categories + campaign-fingerprint set)
├── data/
│   └── training/                   # labeled examples per category
└── requirements.txt
```

---

## 7. API Contract (what the extension calls)

```
GET  /health                     -> {status: "ok", version, port}
POST /analyze/quick              -> Tier 0 only, for inbox-list badges (batchable)
POST /analyze/full                -> full cascade, for an opened email
GET  /config                     -> current device config (enabled categories, preset)
POST /config                     -> update enabled categories/thresholds
POST /feedback                   -> confirm-threat / report-false-positive
GET  /dashboard                  -> serves the Security Operations Dashboard page
GET  /stats/today                -> quick counts for the extension popup
```

---

## 8. Non-Functional Targets (Prototype)

- Tier 0 result under 200ms.
- Full cascade (Tier 0 + up to 2 Tier 1 checks) under ~2 seconds — acceptable for a live demo, doesn't need to be as tight as a production target yet.
- Application should run comfortably on a standard laptop CPU — no GPU dependency assumed for the demo machine.

---

## 9. Demo-Readiness Checklist

- [ ] All 5 category adapters trained and loaded.
- [ ] `/analyze/full` returns a complete evidence chain for a real test email in each of the 5 categories.
- [ ] Geolocation map renders at least one traced hop correctly.
- [ ] Campaign graph correctly clusters the seeded same-kit synthetic emails.
- [ ] Config toggle demonstrably changes behavior (disable a category, confirm it falls back to header-only checks).
- [ ] Extension successfully talks to the local app end-to-end, badges and evidence panel render correctly.
