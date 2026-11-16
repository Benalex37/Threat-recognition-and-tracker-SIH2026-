# Browser Extension — Design & Implementation Specification

---

## 1. Manifest V3 Structure

```json
{
  "manifest_version": 3,
  "name": "Email Threat Detection",
  "permissions": ["storage", "tabs", "scripting"],
  "host_permissions": [
    "https://mail.google.com/*",
    "http://127.0.0.1/*"
  ],
  "background": { "service_worker": "background.js" },
  "content_scripts": [{
    "matches": ["https://mail.google.com/*"],
    "js": ["content.js"],
    "run_at": "document_idle"
  }],
  "action": { "default_popup": "popup.html" },
  "options_page": "options.html",
  "content_security_policy": {
    "extension_pages": "default-src 'self'; connect-src 'self' http://127.0.0.1:*"
  }
}
```

**Key correction from a naive setup:** `host_permissions` (not just CSP) is what actually grants the background service worker permission to fetch `http://127.0.0.1`. Loopback addresses are treated as secure contexts by browsers even over plain HTTP, so no mixed-content issue arises from an HTTPS Gmail tab triggering a background-worker fetch to localhost — but the fetch should originate from the **background worker**, not the content script, for a clean permission boundary.

---

## 2. Component Architecture

| File | Role |
|---|---|
| `content.js` | Injected only into `mail.google.com`. Reads the DOM, watches for new inbox rows and opened emails, injects badges/banners/panels, relays data to the background worker — makes no direct network calls. |
| `background.js` | Service worker. Owns all communication with the local app (`127.0.0.1`), manages the tab-active state machine, holds the offline retry queue, routes messages between content script and local API. |
| `popup.html/js` | Toolbar popup — backend health, quick stats, profile overview, dashboard launch button. |
| `options.html/js` | Full settings page — local app port configuration, category toggles (if not fully admin-locked), OAuth consent flows. |

**Message flow, always:** `content.js` → `chrome.runtime.sendMessage` → `background.js` → `fetch('http://127.0.0.1:<port>/...')` → response flows back the same path. The content script never calls the local API directly.

---

## 3. Two-Depth Scanning Model

This is the piece that makes inbox badges and the resource-conscious cascade compatible with each other.

| | Inbox list badge | Opened-email alert card |
|---|---|---|
| Trigger | Row becomes visible in the inbox list | User opens the email |
| Depth | **Tier 0 only** — gatekeeper score, no adapters attached | **Full cascade** — Tier 0 + Tier 1 specialist(s) as needed |
| Cost | Cheap enough to run across a full page of rows | Heavier, but only for the one email actually being read |
| Output | Coarse badge: `Safe / Caution / High Risk` + rough category hint | Full verdict: exact category, confidence, complete evidence chain |

Badges can be visually refined once the full cascade runs (e.g., if the user opens the email and Tier 1 confirms a specific category, the inbox badge updates from a generic "Caution" to "BEC Risk" retroactively).

---

## 4. In-Context Gmail UI

### 4.1 Inbox Row Badges
- A `MutationObserver` watches the inbox list container for row insertions (Gmail virtualizes/recycles rows as the user scrolls, so this must be continuous, not a one-time scan).
- Each newly-observed row is matched by structural position and `data-legacy-message-id`/similar durable attributes — **not hardcoded CSS class names**, which Gmail rotates across UI experiment cohorts and will silently break a class-name-based selector.
- Row's basic metadata (sender, subject, minimal headers reachable without opening) is sent to the background worker → Tier 0 score → badge rendered inline (`[98% Safe]`, `[BEC Risk]`, `[Unverified Sender]`).
- Badges are cached per message ID for the session, so re-scrolling past an already-scored row doesn't re-trigger analysis.

### 4.2 Header Alert Card (opened email)
- Injected as a banner docked directly above the email body, once the content script detects the open-email view has rendered (again via `MutationObserver`, anchored to the email container's structural role, not a brittle class name).
- Three states:
  - **Green:** "Passed Security Checks" + safe score.
  - **Yellow:** specific low-trust signal named directly (e.g., "New domain, registered 4 days ago" / "SPF check failed").
  - **Red:** exact category named (e.g., "Warning: High-Confidence Business Email Compromise").

### 4.3 Expandable Evidence Panel
- Clicking the alert card expands a drawer sourced directly from the evidence-chain response (Section 10 of the system spec): domain age/WHOIS, SPF/DKIM/DMARC status, flagged language triggers (highlighted inline within a quoted excerpt, not reproduced as a wall of text), and the relay-route summary in plain language ("Sent via a hosting provider IP in Russia — does not match the claimed sender's usual origin").

### 4.4 Link & Attachment Interceptor
Two genuinely different mechanisms here, worth being precise about:

- **Hover preview (informational, cheap):** a `mouseover` listener on anchor tags within the email body compares the visible anchor text against the actual `href` domain, client-side, instantly — no backend call needed for the basic mismatch check. Flags lookalike domains (e.g., `paypa1.com`) using a simple edit-distance/homoglyph check against a small list of commonly-impersonated domains, done locally.
- **Click interception (preventive):** a **capture-phase** click listener on the email body's anchor tags, scoped strictly to `http(s)://` links inside the rendered message content — not Gmail's own UI chrome, to avoid breaking normal Gmail navigation (thread expand/collapse, etc.). On a flagged email, `event.preventDefault()` fires first, then a confirmation modal is shown before allowing the navigation to proceed.
- **Attachment handling — stated honestly:** the extension can intercept the *click* on an attachment element before Gmail's own download handler fires, and show a confirmation modal — but it cannot inspect or block the file's content after the fact, since the download itself is handled by Google's own infrastructure once initiated. This is a "confirm before proceeding" control, not a content-level sandboxing control — worth stating plainly rather than overclaiming attachment-level scanning that isn't actually happening.

### 4.5 "Processed Locally" Badge
- A small shield icon on every alert card/panel, with tooltip text: "Analyzed on this device via 127.0.0.1 — no cloud transfer." Static, always shown when a verdict is present — reinforces the core privacy claim directly at the point of use, not just in documentation.

---

## 5. User Actions & Feedback Loop

### 5.1 Confirm Threat / Report False Positive — two timescales, not one
- **Immediate effect:** the override is applied as a lightweight per-sender/per-domain rule stored locally (e.g., an allowlist entry for "Report False Positive," or a heightened-scrutiny flag for "Confirm Threat") — takes effect on the very next email from that sender, no retraining needed.
- **Longer-term effect:** the same override is appended as a labeled example to the local case log, feeding the next periodic adapter fine-tuning pass. This is stated explicitly as a batch process — not real-time model updating, which wouldn't be an honest claim to make.
- "Confirm Threat" additionally triggers the campaign-fingerprint computation (Section 9 of the system spec) for that email, since a confirmed threat is exactly the kind of event that should feed cross-device correlation.

### 5.2 Quick Remediation Actions
- **Quarantine / Move to Spam:** calls the Gmail API's message-modify endpoint to relabel the message. Requires the `gmail.modify` OAuth scope — a meaningfully bigger permission grant than the read-only baseline everything else needs, so this should be presented to the org admin as a separate, explicitly-opted-into capability, not bundled silently into the base install.
- **Strip Links & Images:** purely a local DOM transformation within the content script's rendered view of the email — disables `href`/`src` attributes, replaces images with a placeholder, keeps text readable. No Gmail API write involved, no extra OAuth scope needed, since the actual email in the user's mailbox is untouched — only how the extension renders it locally changes.

### 5.3 Escalate to SOC / Admin
- Pushes the email's fingerprint (not its content) to the org-wide index, exactly per the campaign-correlation design — this button is the manual trigger for the same sync path that "Confirm Threat" triggers automatically.

---

## 6. Extension Popup

- **Backend health:** background worker pings `GET /health` on an interval (e.g., every 10s while the popup is open, paused otherwise) and reflects `Connected to Local Engine at 127.0.0.1:<port>` or `Local Engine Offline`.
- **Launch SecOps Dashboard:** opens `http://localhost:<port>/dashboard` in a new tab.
- **Active profile overview:** reads the current device's `config.json` (via the local API) and displays the preset name and adapter count, e.g., "Financial Institution Profile — 10 Adapters Active."
- **Quick scan stats:** aggregated from the local `case_log.jsonl` for the current day — count analyzed, count flagged.

---

## 7. Under-the-Hood Operational Features

### 7.1 Tab Visibility Monitor
- Content script listens to `document.visibilityState` (`visibilitychange` event) and reports state to the background worker via message passing.
- Background worker also listens to `chrome.tabs.onActivated` and `chrome.windows.onFocusChanged` as a second, independent signal (covers cases the page-level visibility event alone might miss — e.g., whole browser window losing OS focus while Gmail remains the active tab within it).
- On "inactive," the background worker stops issuing full-cascade requests to the local app and signals it to release loaded models after a short grace period — the local app, not the extension, actually owns unloading model memory, since that's where the models run.

### 7.2 Queue Drainage Indicator
- New-mail IDs arriving while inactive are collected via a lightweight Gmail history-sync check (cheap, no model inference) and stored in `chrome.storage.local` as a small metadata queue — **message IDs and minimal headers only, not full email bodies**, keeping the offline queue consistent with the system's data-minimization principle.
- On reactivation, the popup/badge shows "Catching up — processing N background emails" while the queue drains through the full cascade in order.

### 7.3 Fail-Safe Retry Logic
- If the local app is unreachable, the extension shows a visible "Protection Paused — Reconnecting to Local App..." notice rather than failing silently.
- Incoming emails are queued in `chrome.storage.local` (same lightweight metadata-only format as 7.2) and retried with backoff (e.g., 2s, 5s, 15s, then every 30s) until the local app responds to a health check, at which point the queue drains automatically.
- The extension must never mark an email "safe" purely because the backend was unreachable — an unscored email stays visibly unscored, not defaulted to a false-positive-safe state.

### 7.4 Local App Discovery
- Default port `8000`, overridable in the options page, since a fixed port assumption is fragile if it's ever in conflict with another local service. The background worker's health check and all subsequent calls use the configured port, not a hardcoded value.

---

## 8. Content Security Policy — the correct MV3 mechanics

`connect-src 'self' http://127.0.0.1:*` in the extension's CSP restricts what *extension pages* (popup, options) can connect to. The equally important half, easy to miss, is the **`host_permissions`** entry for `http://127.0.0.1/*` — this is what actually grants the background service worker permission to fetch that origin at all; CSP alone doesn't grant network access, it restricts it. Together, these two mean the extension is technically incapable of transmitting email data anywhere except the local machine — a genuine, verifiable claim, not just a policy statement.

---

## 9. What's Explicitly Deferred (not part of this extension build)

- Any AI computation — the extension is a thin client throughout; every scoring decision happens in the Windows application.
- Full attachment content scanning — the extension can gate the click, not inspect the file.
- Cross-browser support beyond Chromium-based browsers for the initial build (Manifest V3 specifics assumed throughout).
