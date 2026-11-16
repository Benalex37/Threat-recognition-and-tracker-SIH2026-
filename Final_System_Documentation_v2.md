# Organization-Grade, Locally-Run Email Fraud Detection System
### Final Technical & Product Documentation

---

## Table of Contents

1. Overview
2. Positioning
3. Scam Taxonomy Covered
4. System Architecture
5. Tab-Active-Only Execution Model
6. Detection Cascade
7. Why This Model Design, Specifically
8. Sender IP & Header Forensics
9. Campaign Correlation Across the Organization
10. Evidence-Chain Scoring
11. Security Operations Dashboard
12. End-to-End Data Flow
13. User-Facing Features
14. Device Configuration & Tiering
15. Data Storage Design
16. Tech Stack
17. Non-Functional Requirements
18. Privacy & Security Design
19. Roadmap
20. Summary of Key Decisions

---

## 1. Overview

A two-part system that detects fraudulent, phishing, and social-engineering email inside Gmail for organizations — running entirely on infrastructure the organization controls, with no email content ever sent to a third-party cloud service.

- **A Windows desktop application** — the "brain." Runs the actual AI models, holds all configuration, stores case history, and exposes a small local API on the same machine.
- **A browser extension** — the "face." Reads email inside Gmail, sends it to the Windows application running on the same computer, and displays the verdict directly inside the Gmail interface.

The two talk to each other over `localhost` only — a normal request from one program to another on the same PC, never touching the public internet. This is the architectural basis for the system's core privacy claim: **analysis happens on the machine where the email is opened, using models the organization owns and runs itself.**

---

## 2. Positioning

Most competing tools are cloud SaaS products, meaning email content leaves the organization's network to be scanned — a non-starter for regulated financial institutions and a real objection from any security-conscious enterprise buyer. This system is built the other way around: light enough to run on ordinary office hardware, precise enough to be tuned to what a *specific* organization actually faces (a financial institution and a tech company face very different scam profiles), and provably local — "your email never leaves your building" is a claim this architecture can actually back up, not just a slogan.

---

## 3. Scam Taxonomy Covered

Grouped into six categories — this grouping structures both the model design (Section 6) and the org configuration options (Section 14):

| Group | Subtypes |
|---|---|
| **Corporate & Financial Email Scams** | Business Email Compromise (BEC), Vendor Email Compromise (VEC), Fake-Invoice Fraud, CEO Fraud/Executive Spoofing, Payroll Diversion, Advance-Fee Fraud, Wire Transfer Fraud, Fee/Scholarship Phishing, Tax/Government Agency Impersonation |
| **Phishing & Deception Variants** | Mass Phishing, Spear Phishing, Whaling, Clone Phishing, Angler Phishing, Smishing, Vishing, Quishing, Search Engine Phishing, Pharming, Lookalike Domain/Typosquatting |
| **Extortion & Coercion** | Sextortion, Ransomware Delivery/Extortion, Hitman Scam, Cyberbullying/Cyberstalking |
| **Credential & Identity Theft** | Credential Harvesting, Identity Theft, Account Upgrade/Deactivation Scam, Fake Tech Support, Remote Access Scam, MFA Fatigue/Prompt Bombing, Fake Login Page, Fake File-Share Scam |
| **Social Engineering & Consumer Scams** | Romance Scam, Grandparent/Family Emergency, Survey Scam, Mystery Shopper, Work-from-Home Fraud, Gift Card Scam, Lottery/Sweepstakes Fraud, Overpayment Scam, Greeting Card Malware |
| **Next-Gen & AI-Powered** | LLM-Generated Phishing, Deepfake Audio/Voice-Cloning, Deepfake Video Fraud, Cyber Grooming |

**Scope boundary, stated plainly:** detection covers the *email-borne* form of every category — a QR code embedded in an email, a link to a voice-cloned audio file, an email that sets up a follow-on phone call — not standalone SMS/voice/video scanning outside the email channel.

---

## 4. System Architecture

```
┌─────────────────────────────────────────────┐
│  Browser Extension (Gmail tab only)           │
│  - Reads email content/headers                │
│  - Sends to local API on same machine          │
│  - Renders verdict badge + reasons in Gmail     │
│  - Watches tab active/inactive state             │
│  - No AI computation happens here                │
└─────────────────────┬─────────────────────────┘
                       │  HTTP requests to 127.0.0.1
                       │  (never leaves the machine)
                       ▼
┌─────────────────────────────────────────────┐
│  Windows Desktop Application                   │
│  ┌───────────────────────────────────────┐  │
│  │ Local API server (listens on localhost) │  │
│  ├───────────────────────────────────────┤  │
│  │ Ingestion & Forensics                    │  │
│  │  - Header parsing, SPF/DKIM/DMARC          │  │
│  │  - Trust-boundary IP extraction             │  │
│  │  - Geolocation, WHOIS/ASN                    │  │
│  ├───────────────────────────────────────┤  │
│  │ Detection Cascade                         │  │
│  │  Tier 0: fast gatekeeper (header/protocol  │  │
│  │          features + category suggestion)   │  │
│  │  Tier 1: one shared base classification     │  │
│  │          model + dynamically-attached       │  │
│  │          per-category adapters               │  │
│  ├───────────────────────────────────────┤  │
│  │ File-Based Storage (Section 15)            │  │
│  │  - config.json, case log (JSONL),          │  │
│  │    fingerprint index (JSON)                 │  │
│  ├───────────────────────────────────────┤  │
│  │ Settings / Admin UI                        │  │
│  │  - enable/disable checks, device profile     │  │
│  ├───────────────────────────────────────┤  │
│  │ Security Operations Dashboard (Sec. 11)     │  │
│  │  - geolocation map, campaign graph,          │  │
│  │    aggregate stats                            │  │
│  └───────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
```

Both components are installed on **every** employee machine — the same installer, the same code, on a powerful work desktop and a modest laptop alike. The only thing that differs between machines is **configuration**: which of the per-category adapters (Section 6) are downloaded and active. A work machine might run all ~30; a laptop might run a curated 6–8 the organization considers highest-priority, with the remainder falling back to cheap non-AI header/rule checks rather than being skipped entirely.

---

## 5. Tab-Active-Only Execution Model

The Windows application's detection cascade should not be doing meaningful work when nobody is looking at Gmail. Two things need separating, since they're often conflated:

- **Model files on disk between sessions** — these persist normally, the same way any installed application's files persist. Not a resource cost worth avoiding.
- **Active memory/CPU usage while idle** — this is the actual target, and is genuinely achievable.

**Mechanism:**
1. The browser extension's content script, injected only into `mail.google.com`, watches the page's `visibilitychange` event and the tab's focus state.
2. While the Gmail tab is active, the extension sends emails to the local Windows application for analysis as normal.
3. While the tab is inactive, the extension stops sending analysis requests. The Windows application's models stay loaded in memory briefly (a short grace period, to avoid reload thrashing on quick tab switches) then release the memory they were using.
4. New mail arriving while the tab is inactive is not silently missed: a lightweight, near-free check (not the AI cascade — just a mail-list sync) keeps a queue current, and the queue is processed the moment the tab becomes active again, with a brief "catching up" indicator shown to the user.

---

## 6. Detection Cascade

**Tier 0 — Gatekeeper (runs on every email):**
Fast, cheap checks over header/protocol features (SPF/DKIM/DMARC result, domain age, header anomaly flags, IP trust signals from Section 8) plus a lightweight content signal. Produces two things in one pass: an overall fraud probability, and a probability distribution across the six category groups from Section 3 — this second output is what drives which specialist check runs first in Tier 1, so the system checks the most likely category rather than everything.

**Tier 1 — Specialist Classification (only when Tier 0 lands in an ambiguous range):**
One base classification model — a modern, purpose-built encoder classifier (ModernBERT-base: 149 million parameters, 22 layers, natively handles up to 8,192 tokens of context so it reads full email threads without truncating, and is specifically designed and benchmarked for classification tasks rather than being a general-purpose or generative model) — is loaded into memory once per session.

Each of the ~30 scam subtypes has its own **LoRA adapter**: a small, independently trained set of weights (typically 1–5% of the base model's size) that gets dynamically attached to the base model for that specific check, then detached before the next one is attached. This means:
- Every category check is a genuine, independently trained classifier — not a shared heuristic or a hand-tuned threshold.
- Only one copy of the large base model ever needs to be in memory; the adapters swapping in and out are small enough that switching between them is fast.
- Categories are checked **in the order Tier 0's probabilities suggest, restricted to whichever adapters are enabled on this machine**, and the process stops the moment one confirms — so a clear case is usually resolved after one or two specialist checks, not thirty.

**Decision logic:**

```
score, category_probs = gatekeeper.run(features)

if score >= 80:
    flag_as_fraud(category = argmax(category_probs))
elif score < 15:
    mark_safe(safe_score = 100 - score)
else:
    for category in rank_by_probability(category_probs, enabled_only = device_config):
        base_model.attach_adapter(category)
        result = base_model.classify(email_text)
        base_model.detach_adapter()
        if result.confidence >= CONFIRM_THRESHOLD:
            flag_as_fraud(category, result)
            break
    else:
        mark_safe(safe_score, note = "passed specialist review")
```

---

## 7. Why This Model Design, Specifically

- **ModernBERT over an older encoder (e.g. classic BERT):** classic BERT truncates at 512 tokens, which would silently cut off part of a longer email thread — exactly where a scam attempt might sit. ModernBERT's native 8,192-token window avoids that gap, and it's measurably faster and more accurate on classification benchmarks than older encoders of similar size.
- **ModernBERT over a general-purpose/generative LLM:** classification is fundamentally a "which category does this belong to" decision, not a text-generation task. A purpose-built classification encoder is faster, smaller, and just as accurate for this job — a generative LLM would be heavier and slower without a corresponding accuracy benefit here.
- **LoRA adapters over 30 full fine-tuned model copies:** a fully fine-tuned copy of ModernBERT-base per category would mean ~30 separate ~100MB+ files. LoRA adapters shrink each category's footprint to a few megabytes while still being a genuinely, independently trained model for that category — this is the difference that makes "run many specialized checks on a resource-limited laptop" realistic instead of aspirational.

---

## 8. Sender IP & Header Forensics

- Headers are retrieved via the Gmail API, not by scraping the rendered page — structured, reliable, and doesn't break when Gmail's interface changes.
- `Received:` headers form a chain, one per mail server the message passed through, written newest-first. Not every line in that chain can be trusted equally — a sender's own mail server can write fake `Received:` lines before the message ever reaches infrastructure the organization trusts. The line that **can** be trusted is the one written by the recipient's own trusted mail infrastructure (Google's front-line server), because that's an IP address it observed on a live connection, not something the far end could fake in text.
- Gmail's `Authentication-Results` header already does most of this trust-boundary work — it reports the specific IP it checked against the sending domain's SPF record. This is the preferred primary source.
- Gmail-to-Gmail internal mail often won't expose a real originating IP at all (omitted for privacy) — not a practical gap, since external mail is what matters most for this use case.
- The IP should never be treated as a red flag in isolation: check whether it falls within the sending domain's own SPF-authorized range. If it does, geography is largely irrelevant (legitimate business tools routinely send from distant datacenters). If SPF fails or is absent **and** the geolocation is inconsistent with the organization's expected footprint, that combination is meaningful.
- Feed the *result* of these checks into Tier 0 as engineered features (`spf_ip_in_authorized_range`, `geo_matches_expected_countries`, `ip_is_known_vpn_or_hosting`, `asn_reputation_score`) — not the raw IP address itself.
- Every geolocated IP, and the full relay-hop chain it came from, is retained (in the case log, Section 15) specifically to feed the Security Operations Dashboard (Section 11) — this data is computed either way; the dashboard is what makes it visible rather than buried.

---

## 9. Campaign Correlation Across the Organization

Most of the pipeline above works entirely within one device analyzing one email — no visibility into anyone else's inbox needed. One feature is the exception: recognizing that several emails, received by different people across the organization, share the same underlying kit or attacker infrastructure ("these three emails are the same operation, not three separate incidents").

That requires some shared visibility across devices, so it's handled deliberately and narrowly:
- Each Windows application, when it flags an email, computes a **fingerprint** of the email's structural template — the variable fields (names, amounts, dates) stripped out and replaced with placeholders, then hashed in a way where similar templates produce similar hashes (not a plain cryptographic hash, which would break on any small difference).
- Only this fingerprint, plus the sender domain/IP, is optionally synced to a lightweight shared index — **never the email content itself.**
- Other devices' fingerprints are compared against this shared index to detect when multiple, separately-received emails are actually the same campaign, and this is visualized as a graph (nodes = flagged emails, edges = shared fingerprint or infrastructure) inside the Security Operations Dashboard.

This is the one precise exception to "nothing leaves the device" worth stating explicitly in any pitch or documentation, rather than leaving an unqualified claim that a technical follow-up question would break.

---

## 10. Evidence-Chain Scoring

The final fraud verdict is never a single opaque number. Every contributing factor is retained and shown individually:

`header anomaly + domain age + IP/geo trust signals + Tier 0 content risk + Tier 1 category-specific confidence + campaign-fingerprint match (if any)`

Each factor is returned as its own `{factor, contribution, explanation}` entry, so the eventual output is defensible enough to hand to HR, legal, or an investigator — not just a score to take on faith.

---

## 11. Security Operations Dashboard

This is the system's second UI surface — built for the security/IT team, distinct from the inline Gmail badges that employees see day to day. Where the badge answers "is this one email safe," the dashboard answers "what is happening across the organization right now," and it's designed to be the visual centerpiece of any live demonstration of the system.

**Geolocation map:** every analyzed email's origin — resolved through the trust-boundary IP extraction in Section 8 — is plotted on an interactive world map, with the full relay-hop chain drawn as a traced path from origin to the organization's mail server. Flagged emails are visually distinguished from clean ones. This uses data the pipeline is already computing for every email; the dashboard simply gives it a visible home instead of leaving it inside a collapsed evidence panel.

**Campaign correlation graph:** a force-directed node graph, fed by the fingerprint index from Section 9 — nodes are flagged emails, edges connect emails sharing a template fingerprint or sending infrastructure, and connected clusters visually surface as a single "campaign" rather than isolated incidents. This is the feature that answers "is this attacker also targeting other people here" — the one no single-email view can show.

**Aggregate statistics:** flags per category over time, most frequently impersonated senders/domains, top originating countries/ASNs, and per-device coverage (how many categories are actively checked on each registered machine).

**Case drill-down:** selecting any flagged email or campaign cluster opens the full evidence chain (Section 10) for investigation, with the same underlying data as the employee-facing badge, just presented for an investigator's workflow rather than a quick inbox glance.

**Why both surfaces matter, not just one:** the inline badge is what makes the system useful day-to-day for the person reading their email. The dashboard is what makes it a *platform* rather than a browser widget — the two aren't competing designs, they're built for two different users of the same underlying data.

---

## 12. End-to-End Data Flow

1. User switches to the Gmail tab. The extension's content script detects the tab becoming active and begins forwarding new/opened emails to the local Windows application.
2. Any emails queued while the tab was inactive are processed first, in order.
3. For each: the Windows application fetches full headers via the Gmail API, runs header/protocol/IP forensics, and passes the result through Tier 0.
4. If Tier 0 is decisive (very high or very low score), a verdict returns immediately.
5. If ambiguous, Tier 1 attaches the base model to the most likely category's adapter first, checking further categories only if needed, stopping at first confirmation.
6. The verdict (safe score, category if flagged, full evidence chain) returns to the extension over the local connection, and is appended to the local case log (Section 15).
7. The extension renders a badge directly inside Gmail's interface on the relevant email, with an expandable panel showing the evidence chain in plain language.
8. If flagged and the organization has campaign-sync enabled, only the fingerprint (not the content) is shared to the org-wide index for cross-device correlation, feeding the dashboard's campaign graph.
9. User switches away from Gmail → the cascade stops running, models release memory, the lightweight queue-only check continues in the background.
10. At any point, an admin can open the Security Operations Dashboard to see the map, the campaign graph, and aggregate stats drawn from the accumulated case log.

---

## 13. User-Facing Features

- Inline badges directly in the Gmail inbox and open-email view — no separate dashboard required to notice a threat.
- A visible safe score on every email, not only flagged ones, so "nothing's wrong" is a confident, visible result rather than silence.
- An expandable evidence-chain panel per email, explaining exactly why a verdict was reached.
- Specific category labeling on flagged emails (e.g., "Likely Fake-Invoice Fraud"), not just a generic "suspicious" tag.
- One-click confirm/override on any verdict, feeding back into that category's training data over time.
- An admin console (inside the Windows application) for: choosing which categories/adapters are active on this machine, picking an org preset, and managing per-device configuration.
- The full Security Operations Dashboard (Section 11) for security/IT teams.
- A "catching up" indicator when the queue is draining after the tab was inactive.
- A visible "processed on this device, nothing sent externally" indicator, since local-only processing is a genuine trust claim worth surfacing in the interface, not just documentation.

---

## 14. Device Configuration & Tiering

Every machine runs the identical application. Configuration — set centrally by an IT admin for consistency, or adjusted locally within admin-set limits — determines behavior:

| | High-capability machine | Resource-limited machine |
|---|---|---|
| Base model | Full ModernBERT-base | Same — the base model doesn't change |
| Adapters loaded | All ~30 category adapters | A curated priority subset (e.g., 6–10) |
| Remaining categories | Fully covered by AI adapters | Covered by cheap rule/header-based fallback checks instead of being skipped |
| Assignment | Set deterministically by IT admin | Same |

Org presets simplify setup for common cases (e.g., a "Financial Institution" preset that prioritizes BEC/VEC/wire-fraud/whaling/tax-impersonation adapters; a "Tech/SaaS" preset prioritizing BEC/fake-invoice/credential-harvesting/lookalike-domains) — presets are a starting point, individual categories remain adjustable underneath.

---

## 15. Data Storage Design

No database server — everything is plain files on disk, kept deliberately simple for a single-machine, single-process application:

| File | Format | Purpose |
|---|---|---|
| `config.json` | JSON | Device tier, enabled categories/adapters, thresholds, org preset selection |
| `case_log.jsonl` | JSONL (one JSON object per line, append-only) | One record per analyzed email — verdict, category, full evidence chain, timestamp. Append-only by design: new results are added as new lines, never rewritten in place |
| `fingerprint_index.json` | JSON | Local record of campaign fingerprints this device has seen or synced, for correlation lookups |
| `adapter_manifest.json` | JSON | Which LoRA adapter files are present locally, their version, and last-updated timestamp |

**Why this is a reasonable choice at this scale, and the honest tradeoff:** a single device handling one employee's mail doesn't need a database's concurrent-query performance — it needs simple, human-readable, easy-to-inspect storage, and JSON/JSONL delivers that with zero extra install dependency. The tradeoff is that JSON files aren't natively safe for concurrent writes the way a database is; this is handled by routing all writes through the single local API server process (Section 4), which processes requests one at a time, so there's never more than one writer touching a given file at once. This is a deliberate, appropriate choice for a single-process local application, not a shortcut.

For the Security Operations Dashboard (Section 11), the dashboard reads and aggregates across `case_log.jsonl` and `fingerprint_index.json` at query time rather than maintaining a separate database — sufficient at the scale of a single organization's flagged-email volume.

---

## 16. Tech Stack

| Layer | Choice | Why |
|---|---|---|
| Windows application | Python, packaged as a native desktop app | Full access to the mature PyTorch/HuggingFace ecosystem, no browser sandboxing constraints |
| Local API | FastAPI, bound to `127.0.0.1` only | Simple, well-documented, and enforces that the API is never reachable off the machine |
| Base model | ModernBERT-base | Purpose-built classification encoder, 8,192-token context, strong accuracy/speed tradeoff |
| Adapter fine-tuning/serving | HuggingFace PEFT (LoRA) | Mature, standard tooling for training and dynamically attaching per-category adapters |
| Gatekeeper (Tier 0) | LightGBM/XGBoost over engineered features | Near-instant, no neural-net overhead for the triage step |
| Header/protocol checks | Python `email` module, `checkdmarc`, `dkimpy`, `pyspf` | Mature, well-tested — avoids reimplementing RFC parsing |
| Geolocation | MaxMind GeoLite2 (offline) | No network dependency at inference time |
| WHOIS/ASN | `python-whois`, local ASN database | Domain-age and hosting-provider classification |
| Browser extension | Manifest V3, JavaScript | Standard current Chrome extension platform |
| Gmail access | Gmail API via OAuth (Workspace domain-wide delegation for org rollout) | Structured, reliable header/content access; org-level admin approval avoids per-user consent friction |
| Local storage | Plain JSON / JSONL files (Section 15) | No database dependency; simple, human-readable, sufficient for single-process local use |
| Dashboard mapping | Leaflet.js | Free, no billing surprises, well-suited for plotting geolocated hops |
| Dashboard graph | `vis-network` or `d3-force` | Force-directed layout for campaign clustering |
| Campaign fingerprint sync | Lightweight internal index (fingerprints/metadata only) | The one deliberate exception to fully local processing, scoped narrowly (Section 9) |

---

## 17. Non-Functional Requirements

- Tier 0 gatekeeper result well under 200ms on modest office hardware.
- Full cascade including one or two Tier 1 checks under roughly 1–2 seconds.
- The application should idle at effectively zero CPU/memory beyond baseline OS overhead while the Gmail tab is inactive.
- If the local Windows application is briefly unreachable, the extension should fail safe — queue for retry, never silently mark an email "safe" due to a backend hiccup.
- Configurable retention on the local case log, since data minimization is part of the privacy story.

---

## 18. Privacy & Security Design

- Email content and headers never leave the machine on which the email was opened, with the one narrow, explicitly stated exception of anonymized campaign fingerprints (Section 9).
- Gmail API OAuth scope kept to the minimum necessary for the organization's risk tolerance (headers-only vs. full content access, offered as a configurable mode).
- User overrides/feedback are stored as labels tied to fingerprints where possible, minimizing retained sensitive content.
- This is a genuine differentiator worth its own line in any pitch: most competing tools cannot make an equivalent claim, because they require sending content to a cloud service to function at all.

---

## 19. Roadmap (explicitly out of scope for the current build)

- Native SMS/voice/video scanning outside the email channel.
- Full deepfake audio/video forensic analysis (flagged via context/metadata signals for now; deep media forensics deferred).
- Broader cross-organization threat-intelligence sharing beyond the single-org fingerprint index in Section 9.
- Support for mail clients other than Gmail.

---

## 20. Summary of Key Decisions and Why

| Decision | Reason |
|---|---|
| Two-part app (Windows app + extension) over browser-only | Full native AI toolchain available, no browser sandbox constraints |
| Communication over localhost only | Core privacy claim — content never leaves the machine |
| Same application everywhere, config-only differences | One codebase to build and maintain; tiering is a settings question, not a software-branching question |
| ModernBERT-base as the shared classification backbone | Purpose-built for classification, long-context, fast, accurate |
| LoRA adapters per category instead of full fine-tuned copies | Real, independently trained models per category, at a fraction of the storage cost |
| Tier 0 gatekeeper before Tier 1 specialists | Avoids running the heavier model on the majority of clearly legitimate email |
| Category-ranked, stop-at-first-confirmation specialist checks | Resolves most ambiguous cases in one or two checks, not thirty |
| Tab-active gating | No meaningful compute while nobody is looking at Gmail, without missing new mail |
| Fingerprint-only cross-device sync, scoped narrowly | Enables the one feature that genuinely needs cross-device visibility without weakening the local-processing claim everywhere else |
| Plain JSON/JSONL files instead of a database | No extra install dependency, simple and human-readable, appropriate for a single-process local application |
| A dedicated Security Operations Dashboard alongside the inline badge | Gives the geolocation and campaign-correlation data a real visual home, and gives the demo a genuine "platform" centerpiece |
