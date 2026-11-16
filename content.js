(function () {
  "use strict";

  const BADGE_CACHE = new Map();
  // Full-body verdicts from opened messages, keyed by contentKey(). These
  // outrank the preview-only badge score for the same message.
  const FULL_VERDICTS = new Map();
  const ANALYZED_EMAILS = new Set();
  const COMMONLY_IMPERSONATED = [
    "paypal.com",
    "google.com",
    "microsoft.com",
    "amazon.com",
    "apple.com",
    "facebook.com",
    "instagram.com",
    "netflix.com",
    "bankofamerica.com",
    "wellsfargo.com",
    "chase.com",
    "citibank.com",
  ];

  let contextDead = false;

  /**
   * Send a message to the extension background, retrying once after a short
   * delay if the service worker was recently terminated ("Extension context
   * invalidated"). Chrome MV3 service workers can be killed while idle, so a
   * single retry is usually enough to bring the context back.
   */
  async function safeRuntimeMessage(message, retries = 1) {
    for (let attempt = 0; attempt <= retries; attempt++) {
      try {
        if (!chrome?.runtime?.id) {
          contextDead = true;
          if (attempt < retries) {
            await new Promise((r) => setTimeout(r, 1500));
            continue;
          }
          throw new Error("Extension context invalidated");
        }
        contextDead = false;
        return await chrome.runtime.sendMessage(message);
      } catch (err) {
        if (err.message && err.message.includes("Extension context invalidated")) {
          contextDead = true;
          return null;
        }
        if (attempt < retries) {
          await new Promise((r) => setTimeout(r, 1500));
          continue;
        }
        throw err;
      }
    }
  }

  function levenshteinDistance(a, b) {
    const matrix = [];
    for (let i = 0; i <= b.length; i++) {
      matrix[i] = [i];
    }
    for (let j = 0; j <= a.length; j++) {
      matrix[0][j] = j;
    }
    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        if (b.charAt(i - 1) === a.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1,
            matrix[i][j - 1] + 1,
            matrix[i - 1][j] + 1
          );
        }
      }
    }
    return matrix[b.length][a.length];
  }

  function isLookalikeDomain(domain) {
    const normalized = domain.toLowerCase().replace(/^www\./, "");
    for (const target of COMMONLY_IMPERSONATED) {
      if (normalized === target) continue;
      const distance = levenshteinDistance(normalized, target);
      if (distance <= 2 && normalized.length > 3) {
        return { lookalike: true, target };
      }
    }
    return { lookalike: false };
  }

  function extractDomain(url) {
    try {
      return new URL(url).hostname.toLowerCase();
    } catch {
      return "";
    }
  }

  function simpleHash(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
      hash = ((hash << 5) - hash) + str.charCodeAt(i);
      hash = hash & hash;
    }
    return Math.abs(hash).toString(36);
  }

  function getMessageIdFromRow(row) {
    // Try multiple attribute patterns
    const attr = row.getAttribute("data-legacy-message-id") ||
                 row.getAttribute("data-message-id") ||
                 row.getAttribute("data-message-id-legacy") ||
                 row.getAttribute("data-thread-id");
    if (attr) return attr;
    const idAttr = row.id;
    if (idAttr && (idAttr.includes("msg_") || idAttr.includes("thread_"))) return idAttr;
    // Generate stable ID from row content if no attribute
    const sender = row.querySelector('[email], [href*="mailto:"]')?.textContent?.trim() || "";
    const subject = row.querySelector('td[role="gridcell"] + td, td:nth-child(2), .y6, .bog')?.textContent?.trim() || "";
    if (sender || subject) {
      return "etd_" + simpleHash(sender + "|" + subject);
    }
    return null;
  }

  function getRowMetadata(row) {
    const messageId = getMessageIdFromRow(row);
    if (!messageId) return null;

    // Multiple sender selectors — prefer email attr / mailto href over display text
    let sender = "";
    const senderSelectors = [
      '[email]',
      '[href*="mailto:"]',
      'span[title]:has(span[email])',
      'td[role="gridcell"] span[name]',
      'td[role="gridcell"] span[email]',
      'tr td:first-child + td span[email]',
    ];
    for (const sel of senderSelectors) {
      try {
        const el = row.querySelector(sel);
        if (!el) continue;
        // Try the email attribute first (full email address)
        const emailAttr = el.getAttribute("email");
        if (emailAttr && emailAttr.trim()) {
          sender = emailAttr.trim();
          break;
        }
        // Try mailto: href
        const href = el.getAttribute("href");
        if (href && href.includes("mailto:")) {
          sender = href.replace("mailto:", "").trim();
          break;
        }
        // Fall back to visible text content
        if (el.textContent?.trim()) {
          sender = el.textContent.trim();
          break;
        }
      } catch (e) {}
    }

    // Multiple subject selectors
    let subject = "";
    const subjectSelectors = [
      'td[role="gridcell"] + td + td',  // 3rd cell often subject
      '.y6', '.bog', '.yX', '.yW',
      'td[role="gridcell"] span[subject]',
      'tr td:nth-child(3) span',
      'tr td:nth-child(4) span',
    ];
    for (const sel of subjectSelectors) {
      try {
        const el = row.querySelector(sel);
        if (el && el.textContent?.trim()) {
          subject = el.textContent.trim();
          break;
        }
      } catch (e) {}
    }

    // Fallback: get all text and parse
    if (!subject) {
      const allText = row.textContent || "";
      const lines = allText.split("\n").map(l => l.trim()).filter(l => l.length > 3);
      if (lines.length >= 2) {
        subject = lines[1]; // second meaningful line often subject
      }
    }

    // The preview text Gmail already renders in the row. Scoring a row on
    // sender and subject alone leaves Tier 1 nothing to read: a credential
    // harvesting email whose subject is the single word "Urgent" is invisible
    // until it is opened, even when the preview beside it is literally asking
    // for a password and an OTP. That text is in the DOM, so send it.
    let snippet = "";
    for (const sel of ['.y2', 'span.y2', '.xW + .y2', 'td .y2']) {
      try {
        const el = row.querySelector(sel);
        if (el && el.textContent?.trim()) {
          snippet = el.textContent.trim();
          break;
        }
      } catch (e) {}
    }
    // Gmail prefixes the preview with an en/em dash separator.
    snippet = snippet.replace(/^[\s‐-―-]+/, "").trim();
    if (snippet && subject && snippet.startsWith(subject)) {
      snippet = snippet.slice(subject.length).replace(/^[\s‐-―-]+/, "").trim();
    }

    return { messageId, sender, subject, snippet, row };
  }

  // The confidence to put on the badge, read from whichever tier actually
  // decided. Tier 1 reports 0..1, Tier 0 reports 0..100.
  //
  // This used to read Tier 0's top category alone, which is exactly the number
  // that is zero for the attack this product exists to catch: business email
  // compromise from a stolen mailbox passes SPF, DKIM and DMARC, so Tier 0 has
  // nothing to report and only the wording gives it away. Tier 1 is the tier
  // that reads wording, so its confidence has to count here.
  function verdictConfidence(verdict) {
    let best = 0;
    const tier1 = Array.isArray(verdict.tier1) ? verdict.tier1 : [];
    for (const r of tier1) {
      const c = Number(r && r.confidence);
      if (Number.isFinite(c) && c > best) best = c;
    }
    if (best > 0) return Math.round(best * 100);
    const tier0 = verdict.tier0;
    if (tier0 && tier0.categories && tier0.categories.length) {
      const c = Number(tier0.categories[0].confidence);
      if (Number.isFinite(c) && c > 0) return Math.round(c);
    }
    return null;
  }

  // One place decides what a verdict looks like, so the row badge and the
  // opened-email banner can never disagree about the same email.
  function verdictStyle(verdict) {
    const score = verdict.score ?? 50;
    const category = verdict.category || "";
    const conf = verdictConfidence(verdict);
    const pct = conf && conf > 0 ? ` ${conf}%` : "";

    // A flagged email is never drawn as Safe. The previous rule did exactly
    // that — `flagged && score >= 80` with no Tier 0 confidence fell through
    // to a blue "Safe" badge — so the most dangerous mail in the inbox was
    // the mail most likely to be labelled safe.
    if (verdict.flagged || score >= 80) {
      return {
        label: (category ? `${category}${pct}` : `Suspicious${pct}`),
        bg: "#c62139", fg: "#ffffff", border: "1px solid #9e1a2e",
      };
    }
    if (score >= 40) {
      return {
        label: (category ? `${category}${pct}` : `Caution${pct}`),
        bg: "#d9660a", fg: "#ffffff", border: "1px solid #b35208",
      };
    }
    return { label: "Safe", bg: "#1479e6", fg: "#ffffff", border: "1px solid #0d5bc4" };
  }

  function renderBadge(row, verdict) {
    const existing = row.querySelector(".etd-badge");
    if (existing) existing.remove();

    const score = verdict.score ?? 50;
    const { label, bg, fg, border } = verdictStyle(verdict);

    const badge = document.createElement("span");
    badge.className = "etd-badge";
    badge.textContent = label;
    badge.title = `ETD verdict: ${label} (score ${Math.round(score)}/100)`;
    badge.style.cssText = `
      display: inline-block;
      margin-left: 8px;
      padding: 3px 10px;
      border-radius: 14px;
      font-size: 11px;
      font-weight: 700;
      font-family: Arial, sans-serif;
      line-height: 1.4;
      vertical-align: middle;
      white-space: nowrap;
      flex-shrink: 0;
      position: relative;
      background: ${bg};
      color: ${fg};
      border: ${border};
    `;
    return badge;
  }

  async function requestBadgeScore(messageId, sender, subject, snippet) {
    if (BADGE_CACHE.has(messageId)) {
      return BADGE_CACHE.get(messageId);
    }

    const sep60 = "=".repeat(60);
    const dash60 = "-".repeat(60);
    console.log(
      "%c" + sep60 + "\n ETD TIER 0 -- BADGE SCORE REQUEST\n" + sep60,
      "color: #1479e6; font-weight: bold; font-size: 13px;"
    );
    console.log(" Message ID :", messageId);
    console.log(" Sender     :", sender || "(empty)");
    console.log(" Subject    :", subject || "(empty)");
    console.log(" Preview    :", snippet ? snippet.slice(0, 120) : "(empty)");

    try {
      const response = await safeRuntimeMessage({
        type: "BADGE_SCORE",
        payload: { messageId, sender, subject, snippet: snippet || "" },
      });

      if (response?.success && response.data) {
        const d = response.data;
        const senderDomain = (sender || "").includes("@") ? (sender || "").split("@").pop() : "unknown";
        console.log(
          "%c" + sep60 + "\n ETD LIVE TIER 0 (GATEKEEPER) INPUT & FEATURE ANALYSIS\n" + sep60,
          "color: #c62139; font-weight: bold; font-size: 14px;"
        );
        console.log("  [MESSAGE ID]:", messageId);
        console.log("  [SENDER]:    ", sender || "(empty)", "(Domain:", senderDomain + ")");
        console.log("  [SUBJECT]:   ", subject || "(empty)");
        console.log(dash60);
        console.log("  [COMPUTED FORENSIC FEATURES (TIER 0 INPUTS)]:");
        if (d.features) {
          Object.entries(d.features).forEach(([k, v]) => {
            console.log("    - " + k.padEnd(30) + ": " + v);
          });
        }
        console.log(dash60);
        if (d.enabledCategories) {
          console.log("  [ENABLED CATEGORIES]:", JSON.stringify(d.enabledCategories).replace(/"/g, "'").replace(/,/g, ", "));
        }
        if (d.tier0) {
          console.log("  [TIER 0 MODEL SCAM CATEGORIES]:", JSON.stringify(d.tier0.categories.map((c) => c.category)));
          console.log("  [GATEKEEPER INITIAL SCORE]: " + (d.score != null ? d.score : "?") + "/100  (Tier 0 model overall_scam_score: " + d.tier0.overall_scam_score + ")");
          console.log("  [CATEGORY PROBABILITIES]:");
          for (const cat of d.tier0.categories) {
            console.log("    - " + cat.category.padEnd(30) + ": " + cat.confidence + "%");
          }
        } else {
          console.log("  [GATEKEEPER INITIAL SCORE]: " + (d.score != null ? d.score : "?") + "/100");
          console.log("  [CATEGORY PROBABILITIES]:");
          const probs = d.categoryProbs || {};
          Object.keys(probs).forEach((cat) => {
            console.log("    - " + cat.padEnd(30) + ": " + probs[cat]);
          });
        }
        if (d.tier1 && d.tier1.length > 0) {
          console.log("  [TIER 1 AI (LoRA ADAPTER CHECKS IN TIER 0 PROBABILITY ORDER)]:");
          console.log(dash60);
          d.tier1.forEach((t1, idx) => {
            console.log("  [" + (idx + 1) + "] adapter      :", t1.adapter || "N/A");
            console.log("      confidence   :", t1.confidence);
            console.log("      model        :", t1.model || "N/A");
            if (t1.label_probs) {
              Object.entries(t1.label_probs).forEach(([k, v]) => {
                console.log("      - " + k.padEnd(30) + ": " + v);
              });
            }
            console.log(dash60);
          });
        } else if (d.tier1 && d.tier1.length === 0) {
          console.log("  [TIER 1 AI]: Skipped (Tier 0 proved scam)");
        }
        console.log(sep60);
        BADGE_CACHE.set(messageId, d);
        return d;
      }
      if (response?.queued) {
        console.log("  Queued for offline retry");
        return { score: 50, flagged: false, queued: true };
      }
      if (response === null) {
        console.warn("  Badge skipped — background service worker was unavailable (will auto-retry when Gmail tab regains focus)");
        return { score: 50, flagged: false, offline: contextDead };
      }
    } catch (err) {
      console.warn("  Badge error:", err.message);
      // Surface a soft "offline" badge so the row still gets marked
      return { score: 50, flagged: false, error: true, offline: contextDead };
    }
    return { score: 50, flagged: false };
  }

  async function analyzeEmail(messageId, sender, subject, emailBody, headers) {
    const senderDomain = sender.includes("@") ? sender.split("@")[1] : (sender || "unknown");

    const sep60 = "=".repeat(60);
    const dash60 = "-".repeat(60);
    console.log(
      "%c" + sep60 + "\n ETD LIVE TIER 0 (GATEKEEPER) INPUT & FEATURE ANALYSIS\n" + sep60,
      "color: #c62139; font-weight: bold; font-size: 14px;"
    );
    console.log("  [MESSAGE ID]:", messageId);
    console.log("  [SENDER]:    ", sender || "(empty)", "(Domain:", senderDomain + ")");
    console.log("  [SUBJECT]:   ", subject || "(empty)");
    console.log("  [BODY LEN]:  ", emailBody.length, "chars");
    console.log("  [BODY PREVIEW]:", emailBody.slice(0, 300));
    console.log(dash60);
    console.log("  [RAW HEADERS EXTRACTED]:");
    if (Object.keys(headers).length > 0) {
      Object.entries(headers).forEach(([k, v]) => console.log("    -", k, ":", v));
    } else {
      console.log("    (no headers found — Gmail may restrict header access)");
    }
    console.log(dash60);
    console.log("  [SENDING TO LOCAL BACKEND]: /api/analyze (port resolved by the service worker)");
    console.log("  [PAYLOAD KEYS]:", ["messageId", "sender", "subject", "emailBody", "headers"].join(", "));
    console.log(sep60);

    try {
      const response = await safeRuntimeMessage({
        type: "ANALYZE_EMAIL",
        payload: { messageId, sender, subject, emailBody, headers },
      });

      if (response?.success && response.data) {
        console.log(
          "%c" + sep60 + "\n ETD TIER 0 VERDICT RECEIVED\n" + sep60,
          "color: #0f9d76; font-weight: bold; font-size: 13px;"
        );
        console.log("  [SCORE]:   ", response.data.score);
        console.log("  [FLAGGED]: ", response.data.flagged);
        console.log("  [CATEGORY]:", response.data.category || "N/A");
        console.log("  [SAFE SCORE]:", response.data.safeScore);
        if (response.data.tier0) {
          console.log("  [TIER 0 MODEL SCAM CATEGORIES]:", JSON.stringify(response.data.tier0.categories.map((c) => c.category)));
          console.log("  [GATEKEEPER INITIAL SCORE]: " + response.data.score + "/100  (Tier 0 model overall_scam_score: " + response.data.tier0.overall_scam_score + ")");
          console.log("    [PREDICTED CLASS]:", response.data.tier0.predicted_class);
          console.log("  [CATEGORY PROBABILITIES]:");
          for (const cat of response.data.tier0.categories) {
            console.log("    - " + cat.category.padEnd(30) + ": " + cat.confidence + "%");
          }
        }
        if (response.data.evidence && response.data.evidence.length > 0) {
          console.log("  [EVIDENCE]:");
          response.data.evidence.forEach((e) => console.log("    -", e.factor, ":", e.explanation, "(contribution:", e.contribution + ")"));
        }
        if (response.data.tier1 && response.data.tier1.length > 0) {
          console.log("  [TIER 1 AI (LoRA ADAPTER CHECKS IN TIER 0 PROBABILITY ORDER)]:");
          console.log(dash60);
          response.data.tier1.forEach((t1, idx) => {
            console.log("  [" + (idx + 1) + "] adapter      :", t1.adapter || "N/A");
            console.log("      confidence   :", t1.confidence);
            console.log("      model        :", t1.model || "N/A");
            if (t1.label_probs) {
              Object.entries(t1.label_probs).forEach(([k, v]) => {
                console.log("      - " + k.padEnd(30) + ": " + v);
              });
            }
            console.log(dash60);
          });
        } else if (response.data.tier1 && response.data.tier1.length === 0) {
          console.log("  [TIER 1 AI]: Skipped (Tier 0 proved scam)");
        }
        console.log(sep60);
        return response.data;
      }
      if (response?.queued) {
        console.log("  [QUEUED]: Position", response.queuePosition || "background");
        return { score: null, flagged: false, queued: true, queuePosition: response.queuePosition };
      }
      if (response === null) {
        console.warn("  [SKIPPED]: Background service worker unavailable — analysis deferred");
        return { score: null, flagged: false, offline: contextDead };
      }
      console.warn("  [NO DATA IN RESPONSE]:", JSON.stringify(response));
    } catch (err) {
      console.warn("  [ANALYZE ERROR]:", err.message);
      return { score: null, flagged: false, error: true };
    }
    return { score: null, flagged: false };
  }

  function findInboxContainer() {
    const candidates = [
      'div[role="main"] table',
      'div[role="main"]',
      'table[role="grid"]',
      'div.UI table',
      'div[role="main"] > div > div > table',
    ];
    for (const sel of candidates) {
      const el = document.querySelector(sel);
      if (el) return el;
    }
    return document.querySelector('div[role="main"]') || document.body;
  }

  function isEmailRow(element) {
    if (!element || element.nodeType !== Node.ELEMENT_NODE) return false;
    if (element.tagName !== "TR") return false;
    const cells = element.querySelectorAll("td");
    if (cells.length < 3) return false;
    const text = element.textContent || "";
    return text.includes("@") || text.length > 20;
  }

  function getEmailRows(container) {
    if (!container) return [];
    const selectors = [
      'tr[role="row"]',
      'tbody tr',
      'table tr',
      'tr',
    ];
    for (const sel of selectors) {
      const rows = container.querySelectorAll(sel);
      const emailRows = Array.from(rows).filter(isEmailRow);
      if (emailRows.length > 0) return emailRows;
    }
    return [];
  }

  /** The container of an actually-open message, or null in list views.
   *
   *  The selectors here must be ones that exist only in the reading pane.
   *  `.nH` and `div[role="main"]` are present on the inbox list too, and the
   *  old last-resort fallback returned `div[role="main"]` unconditionally — so
   *  this reported an open email while the user was looking at their inbox,
   *  then bailed out further down when no message id could be found. The
   *  result was that the full analysis never ran even once.
   */
  function findOpenEmailContainer() {
    const openMessage = document.querySelector('div[role="main"] [data-message-id]');
    if (openMessage) return openMessage;

    // `.a3s` is the rendered message body; it is absent from list views.
    const body = document.querySelector('div[role="main"] .a3s');
    if (body && body.textContent && body.textContent.trim().length > 30) {
      return body.closest("[data-message-id]") || body;
    }

    const article = document.querySelector('div[role="main"] [role="article"]');
    if (article && article.textContent && article.textContent.trim().length > 30) {
      return article;
    }
    return null;
  }

  function isInInboxArea(node) {
    const container = findInboxContainer();
    if (!container) return false;
    return container.contains(node);
  }

  function observeInboxRows() {
    const container = findInboxContainer();
    if (!container) return;

    // Initial scan
    getEmailRows(container).forEach(processInboxRow);

    const observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        for (const node of mutation.addedNodes) {
          if (node.nodeType !== Node.ELEMENT_NODE) continue;
          if (isEmailRow(node)) {
            processInboxRow(node);
          } else {
            const rows = getEmailRows(node);
            rows.forEach(processInboxRow);
          }
        }
      }
    });

    observer.observe(container, { childList: true, subtree: true });
    return observer;
  }

  async function processInboxRow(row) {
    const metadata = getRowMetadata(row);
    if (!metadata) return;
    if (!metadata.sender || !metadata.sender.trim() || !metadata.subject || !metadata.subject.trim()) {
      return;
    }

    const cached = FULL_VERDICTS.get(contentKey(metadata.sender, metadata.subject))
      || BADGE_CACHE.get(metadata.messageId);
    const existingBadge = row.querySelector(".etd-badge");
    if (cached && existingBadge) return;

    if (cached && !existingBadge) {
      const badgeEl = renderBadge(row, cached);
      const senderEl = row.querySelector('[email], [href*="mailto:"]');
      if (senderEl) {
        let cell = senderEl.closest ? senderEl.closest("td") : null;
        if (!cell) {
          let n = senderEl.parentElement;
          while (n && n.tagName !== "TD") n = n.parentElement;
          cell = n;
        }
        if (cell && cell.nodeType === Node.ELEMENT_NODE) {
          cell.style.whiteSpace = "nowrap";
          cell.appendChild(badgeEl);
        } else {
          row.appendChild(badgeEl);
        }
      } else {
        row.appendChild(badgeEl);
      }
      return;
    }

    console.log("=== ETD INBOX ROW EXTRACTED ===", {
      messageId: metadata.messageId,
      sender: metadata.sender,
      subject: metadata.subject,
      timestamp: new Date().toISOString()
    });

    const verdict = await requestBadgeScore(metadata.messageId, metadata.sender, metadata.subject, metadata.snippet);
    if (!verdict.queued) {
      BADGE_CACHE.set(metadata.messageId, verdict);
    }

    const badgeEl = renderBadge(row, verdict);
    // Insert the badge into the sender's cell so it sits right after the
    // sender name (never in the checkbox cell, never overlapping other text).
    const senderEl = row.querySelector('[email], [href*="mailto:"]');
    let placed = false;
    if (senderEl) {
      let cell = null;
      if (typeof senderEl.closest === "function") {
        cell = senderEl.closest("td");
      }
      if (!cell) {
        let n = senderEl.parentElement;
        while (n && n.tagName !== "TD") n = n.parentElement;
        cell = n;
      }
      if (cell && cell.nodeType === Node.ELEMENT_NODE) {
        cell.style.whiteSpace = "nowrap";
        cell.appendChild(badgeEl);
        placed = true;
      }
    }
    if (!placed) {
      const insertTarget = row.querySelector("td") || row;
      if (insertTarget.tagName === "TD") {
        insertTarget.appendChild(badgeEl);
      } else {
        row.appendChild(badgeEl);
      }
    }
  }

  function observeOpenEmail() {
    const observer = new MutationObserver(() => {
      const emailContainer = findOpenEmailContainer();
      if (!emailContainer) return;

      const messageId = emailContainer.getAttribute("data-message-id") || extractMessageIdFromDom();
      if (!messageId || ANALYZED_EMAILS.has(messageId)) return;

      ANALYZED_EMAILS.add(messageId);
      renderAlertCard(emailContainer, messageId);
    });

    const mainArea = document.querySelector('div[role="main"]') || document.body;
    observer.observe(mainArea, { childList: true, subtree: true });
    return observer;
  }

  function extractMessageIdFromDom() {
    const withAttr = document.querySelector('div[role="main"] [data-message-id]');
    if (withAttr) {
      const id = withAttr.getAttribute("data-message-id");
      if (id) return id.replace(/^#/, "");
    }

    const legacy = document.querySelector('div[role="main"] [data-legacy-message-id]');
    if (legacy) {
      const id = legacy.getAttribute("data-legacy-message-id");
      if (id) return id;
    }

    const metaEl = document.querySelector('meta[name="message-id"]');
    if (metaEl) return metaEl.getAttribute("content");

    // Current Gmail puts the thread id in the hash path (#inbox/FMfcgz...),
    // not in a `th=` query parameter. The old pattern looked only for the
    // query form, and its character class was `[a-f0-]` — missing 1-9, so it
    // could not match a hex id even when one was there.
    const hashMatch = window.location.hash.match(/#[^/]+\/([A-Za-z0-9_-]{8,})$/);
    if (hashMatch) return hashMatch[1];

    const queryMatch = window.location.href.match(/[?&]th=([A-Za-z0-9]+)/);
    if (queryMatch) return queryMatch[1];

    return null;
  }

  async function renderAlertCard(emailContainer, messageId) {
    let sender = "";
    // Gmail puts the address on the header's span.gD; h2[data-name] is only a
    // display name. Matching the inbox row needs the address.
    const senderEl = emailContainer.closest('[role="listitem"], .adn')?.querySelector('span.gD[email], span[email]')
      || document.querySelector('div[role="main"] span.gD[email]')
      || document.querySelector('h2[data-name]');
    if (senderEl) {
      const emailAttr = senderEl.getAttribute("email");
      if (emailAttr && emailAttr.trim()) {
        sender = emailAttr.trim();
      } else {
        sender = senderEl.textContent?.trim() || "";
      }
    }
    const subject = (document.querySelector('h2[data-subject]') || document.querySelector('div[role="main"] h2.hP'))
      ?.textContent?.trim() || "";
    const emailBody = emailContainer.innerText || "";

    const headers = {};
    document.querySelectorAll(".g3, .g4, .g6").forEach((el) => {
      const label = el.textContent.split(":")[0]?.trim();
      if (label) headers[label] = el.textContent.replace(label + ":", "").trim();
    });

    console.log("=== ETD EMAIL EXTRACTED ===", {
      messageId,
      sender,
      subject,
      bodyLength: emailBody.length,
      bodyPreview: emailBody.slice(0, 200),
      headers,
      timestamp: new Date().toISOString()
    });

const verdict = await analyzeEmail(messageId, sender, subject, emailBody, headers);

    const score = verdict.score ?? 50;

    let label, bg, fg, border;
    if (verdict.queued) {
      label = "Catching up…";
      bg = "#fdf4e6"; fg = "#d9660a"; border = "1px solid #f2c28a";
    } else if (verdict.error) {
      label = "Reconnecting…";
      bg = "#fdeaed"; fg = "#c62139"; border = "1px solid #f3b4bf";
    } else {
      ({ label, bg, fg, border } = verdictStyle(verdict));
    }

    const card = document.createElement("div");
    card.className = "etd-alert-card";
    card.style.cssText = `
      position: relative;
      margin-bottom: 16px;
      padding: 14px 18px;
      border-radius: 8px;
      font-family: Arial, sans-serif;
      font-size: 14px;
      line-height: 1.5;
      background: ${bg};
      color: ${fg};
      border: ${border};
    `;
    card.innerHTML = `<strong>${label}</strong> — analyzed locally, no cloud transfer`;

    emailContainer.parentNode.insertBefore(card, emailContainer);

    if (verdict.evidence && verdict.evidence.length > 0) {
      const panelToggle = document.createElement("button");
      panelToggle.textContent = "Show Evidence";
      panelToggle.style.cssText = `
        display: block;
        margin-top: 10px;
        padding: 6px 12px;
        background: white;
        border: 1px solid #c3d8ec;
        border-radius: 4px;
        cursor: pointer;
        font-family: Arial, sans-serif;
        font-size: 12px;
      `;
      card.appendChild(panelToggle);

      const panel = document.createElement("div");
      panel.className = "etd-evidence-panel";
      panel.style.cssText = `
        display: none;
        margin-top: 12px;
        padding: 12px;
        background: white;
        border: 1px solid #dce8f4;
        border-radius: 6px;
        font-family: Arial, sans-serif;
        font-size: 13px;
      `;
      panel.style.setProperty("color", "#1f2933", "important");

      const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => (
        { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
      // Colours are set on every element: the card's white text was inherited
      // by the white panel, so the evidence rendered but could not be seen.
      let html = "<ul style='padding-left: 18px; margin: 0; color: #1f2933;'>";
      for (const factor of verdict.evidence) {
        html += `<li style="color: #1f2933; margin: 2px 0;"><strong style="color: #0a1f3c;">${esc(factor.factor)}:</strong> ${esc(factor.explanation)}</li>`;
      }
      html += "</ul>";
      panel.innerHTML = html;

      card.appendChild(panel);
      panelToggle.addEventListener("click", () => {
        const open = panel.style.display === "block";
        panel.style.display = open ? "none" : "block";
        panelToggle.textContent = open ? "Show Evidence" : "Hide Evidence";
      });
    }

    appendReportLink(card, messageId);
    updateInboxBadgeRetroactively(messageId, verdict);
    if (!verdict.queued && !verdict.error && sender && subject) {
      FULL_VERDICTS.set(contentKey(sender, subject), verdict);
      updateInboxBadgesByContent(sender, subject, verdict);
    }
  }

  // Inbox rows and the opened message carry different ids, so the opened
  // message's full verdict is matched back to its row by sender and subject.
  function contentKey(sender, subject) {
    return `${(sender || "").trim().toLowerCase()}|${(subject || "").split(/\s+/).join(" ").trim().toLowerCase()}`;
  }

  function updateInboxBadgesByContent(sender, subject, verdict) {
    const key = contentKey(sender, subject);
    document.querySelectorAll(".etd-badge").forEach((badge) => {
      const row = badge.closest("tr");
      const metadata = row && getRowMetadata(row);
      if (!metadata || contentKey(metadata.sender, metadata.subject) !== key) return;
      BADGE_CACHE.set(metadata.messageId, verdict);
      badge.replaceWith(renderBadge(row, verdict));
    });
  }

  /**
   * Link the in-Gmail card through to this message's full forensic report on
   * the local engine. The engine's port is discovered at runtime, so the href
   * is filled in once the background reports which one answered.
   */
  function appendReportLink(card, messageId) {
    // A button, not an href="#" link: until the port was known the old link
    // pointed at "#", so a click just changed Gmail's hash and nothing opened.
    // It was also removed outright whenever the status probe timed out, which
    // happened whenever the engine was busy scoring.
    const link = document.createElement("button");
    link.type = "button";
    link.textContent = "Open full forensic report ↗";
    link.style.cssText = `
      display: inline-block;
      margin-top: 10px;
      margin-left: 8px;
      padding: 6px 12px;
      color: #0d5bc4;
      background: #eef7fe;
      border: 1px solid #9ed4fb;
      border-radius: 4px;
      font-family: Arial, sans-serif;
      font-size: 12px;
      font-weight: bold;
      cursor: pointer;
    `;
    card.appendChild(link);

    link.addEventListener("click", async (event) => {
      event.preventDefault();
      event.stopPropagation();
      const original = link.textContent;
      link.textContent = "Opening report…";
      try {
        let status = await safeRuntimeMessage({ type: "GET_ENGINE_STATUS" });
        if (!status || status.state === "offline") {
          status = await safeRuntimeMessage({ type: "GET_ENGINE_STATUS", force: true });
        }
        if (!status || status.state === "offline" || !status.baseUrl) {
          link.textContent = "Engine not reachable — try again";
          setTimeout(() => { link.textContent = original; }, 3000);
          return;
        }
        // Each report gets its own window so several can sit side by side
        // while an investigator compares them.
        const url = `${status.baseUrl}/report/${encodeURIComponent(messageId)}`;
        const opened = await safeRuntimeMessage({ type: "OPEN_REPORT_WINDOW", url }).catch(() => null);
        if (!opened || opened.error) {
          window.open(url, `trt-report-${messageId}`, "width=1040,height=900");
        }
        link.textContent = original;
      } catch (err) {
        link.textContent = "Could not open report";
        setTimeout(() => { link.textContent = original; }, 3000);
      }
    });
  }

  function updateInboxBadgeRetroactively(messageId, verdict) {
    const row = document.querySelector(`[data-legacy-message-id="${messageId}"]`);
    if (row) {
      const existing = row.querySelector(".etd-badge");
      if (existing) {
        const newBadge = renderBadge(row, verdict);
        existing.replaceWith(newBadge);
      }
    }
  }

  function setupLinkInterceptor(emailContainer) {
    const links = emailContainer.querySelectorAll("a[href]");
    links.forEach((link) => {
      link.addEventListener("mouseover", (e) => {
        const href = link.getAttribute("href");
        if (!href || !href.startsWith("http")) return;

        const visibleText = link.textContent.trim();
        const hrefDomain = extractDomain(href);
        const textDomain = extractDomain("http://" + visibleText);

        if (visibleText && textDomain && hrefDomain && textDomain !== hrefDomain) {
          const lookalike = isLookalikeDomain(hrefDomain);
          let tooltip = `Link text says "${visibleText}" but points to ${hrefDomain}`;
          if (lookalike.lookalike) {
            tooltip += ` — lookalike of ${lookalike.target}`;
          }
          link.title = tooltip;
          link.style.textDecoration = "underline wavy #c62139";
        }
      });

      link.addEventListener("mouseout", () => {
        link.title = "";
        link.style.textDecoration = "";
      });
    });
  }

  function setupClickInterceptor(emailContainer) {
    emailContainer.addEventListener("click", (e) => {
      const target = e.target;
      if (target.tagName !== "A") return;
      if (!target.href || !target.href.startsWith("http")) return;

      const hrefDomain = extractDomain(target.href);
      const lookalike = isLookalikeDomain(hrefDomain);
      const visibleText = target.textContent.trim();

      if (lookalike.lookalike) {
        e.preventDefault();
        e.stopPropagation();
        showConfirmationModal(
          `This link appears to go to <strong>${hrefDomain}</strong>, which looks similar to <strong>${lookalike.target}</strong>.<br><br>Do you want to proceed?`,
          () => {
            window.open(target.href, "_blank", "noopener,noreferrer");
          }
        );
        return;
      }

      if (visibleText && extractDomain("http://" + visibleText) !== hrefDomain) {
        e.preventDefault();
        e.stopPropagation();
        showConfirmationModal(
          `The link text says <strong>"${visibleText}"</strong> but the URL is <strong>${hrefDomain}</strong>.<br><br>Do you want to proceed?`,
          () => {
            window.open(target.href, "_blank", "noopener,noreferrer");
          }
        );
      }
    }, true);
  }

  function setupAttachmentInterceptor(emailContainer) {
    emailContainer.addEventListener("click", (e) => {
      const target = e.target;
      const attachmentEl = target.closest('[data-tooltip*="download"], [title*="download"], a[href*="download"], div[role="button"]');
      if (!attachmentEl) return;

      e.preventDefault();
      e.stopPropagation();
      showConfirmationModal(
        "You are about to download an attachment. This extension cannot inspect the file content before download.<br><br>Proceed with caution. Do you want to continue?",
        () => {
          const href = attachmentEl.href || attachmentEl.querySelector("a")?.href;
          if (href) {
            window.open(href, "_blank", "noopener,noreferrer");
          }
        }
      );
    }, true);
  }

  function showConfirmationModal(message, onConfirm) {
    const overlay = document.createElement("div");
    overlay.style.cssText = `
      position: fixed; top: 0; left: 0; right: 0; bottom: 0;
      background: rgba(0,0,0,0.5); z-index: 99999;
      display: flex; align-items: center; justify-content: center;
      font-family: Arial, sans-serif;
    `;

    const modal = document.createElement("div");
    modal.style.cssText = `
      background: white; padding: 24px; border-radius: 8px;
      max-width: 480px; width: 90%; box-shadow: 0 4px 20px rgba(0,0,0,0.3);
    `;

    const content = document.createElement("div");
    content.style.cssText = "font-size: 14px; line-height: 1.6; margin-bottom: 20px;";
    content.innerHTML = message;

    const buttons = document.createElement("div");
    buttons.style.cssText = "display: flex; gap: 10px; justify-content: flex-end;";

    const cancelBtn = document.createElement("button");
    cancelBtn.textContent = "Cancel";
    cancelBtn.style.cssText = `
      padding: 8px 16px; border: 1px solid #c3d8ec; border-radius: 4px;
      background: white; cursor: pointer; font-family: Arial, sans-serif;
    `;

    const proceedBtn = document.createElement("button");
    proceedBtn.textContent = "Proceed";
    proceedBtn.style.cssText = `
      padding: 8px 16px; border: none; border-radius: 4px;
      background: #1479e6; color: white; cursor: pointer; font-family: Arial, sans-serif;
    `;

    cancelBtn.addEventListener("click", () => overlay.remove());
    proceedBtn.addEventListener("click", () => {
      onConfirm();
      overlay.remove();
    });

    buttons.appendChild(cancelBtn);
    buttons.appendChild(proceedBtn);
    modal.appendChild(content);
    modal.appendChild(buttons);
    overlay.appendChild(modal);
    document.body.appendChild(overlay);
  }

  function safeSendMessage(msg) {
    if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.id) {
      chrome.runtime.sendMessage(msg).catch(() => {});
    }
  }

  function setupVisibilityMonitor() {
    document.addEventListener("visibilitychange", () => {
      safeSendMessage({
        type: "VISIBILITY_STATE",
        state: document.visibilityState,
      });
    });

    // Unload listener removed due to CSP restrictions in Gmail
    // window.addEventListener("unload", () => { // not allowed
    //   safeSendMessage({ type: "VISIBILITY_STATE", state: "hidden" });
    // });
  }


  function showCatchUpIndicator(count) {
    const existing = document.querySelector(".etd-catchup-indicator");
    if (existing) existing.remove();

    const indicator = document.createElement("div");
    indicator.className = "etd-catchup-indicator";
    indicator.style.cssText = `
      position: fixed; top: 60px; right: 20px; z-index: 99998;
      background: #fdf4e6; border: 1px solid #f2c28a; border-radius: 6px;
      padding: 10px 16px; font-family: Arial, sans-serif; font-size: 13px;
      box-shadow: 0 2px 8px rgba(0,0,0,0.15);
    `;
    indicator.textContent = `Catching up — processing ${count} background email(s)...`;
    document.body.appendChild(indicator);
  }

  function removeCatchUpIndicator() {
    const existing = document.querySelector(".etd-catchup-indicator");
    if (existing) existing.remove();
  }

  function scanExistingRows() {
    const rows = document.querySelectorAll("[data-legacy-message-id]");
    rows.forEach(processInboxRow);
  }

  function stripTabBarBadges() {
    // Remove any badges that landed on Gmail tab-bar rows (Primary/Promotions/Social).
    document.querySelectorAll('tr[role="tab"] .etd-badge, [role="tab"] .etd-badge, .zA .etd-badge, .zF .etd-badge').forEach((b) => b.remove());
  }

  function init() {
    setupVisibilityMonitor();
    observeInboxRows();
    observeOpenEmail();
    scanExistingRows();

    chrome.runtime.onMessage.addListener((message) => {
      if (message.type === "SHOW_CATCHUP") {
        showCatchUpIndicator(message.count);
      }
      if (message.type === "HIDE_CATCHUP") {
        removeCatchUpIndicator();
      }
      if (message.type === "REFRESH_BADGE" && message.messageId) {
        const row = document.querySelector(`[data-legacy-message-id="${message.messageId}"]`);
        if (row) {
          const metadata = getRowMetadata(row);
          if (metadata) {
            requestBadgeScore(metadata.messageId, metadata.sender, metadata.subject, metadata.snippet).then(
              (verdict) => {
                const existing = row.querySelector(".etd-badge");
                if (existing) {
                  const newBadge = renderBadge(row, verdict);
                  existing.replaceWith(newBadge);
                }
              }
            );
          }
        }
      }
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
