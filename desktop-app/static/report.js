/* Forensic report renderer.
 *
 * The page ships with its case embedded, so it prints correctly even if the
 * engine stops answering between opening and printing.
 */
(function () {
  "use strict";

  const payload = readEmbedded();
  const item = payload.case || {};
  const block = payload.block || null;
  const bands = payload.severityBands || [];
  const campaign = payload.campaign || {};

  function readEmbedded() {
    const node = document.getElementById("embedded-case");
    try {
      return JSON.parse(node.textContent);
    } catch (err) {
      console.warn("Could not parse the embedded case", err);
      return {};
    }
  }

  function escapeHtml(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  function bandFor(severity) {
    return bands.find((b) => b.id === severity) || { label: severity || "unknown", description: "" };
  }

  const ACRONYMS = { bec: "BEC", vec: "VEC", ceo: "CEO", llm: "LLM", mfa: "MFA", ai: "AI" };

  function pretty(value) {
    if (!value) return "Uncategorised";
    return String(value).split(/[_\s]+/).map((word) => {
      const lower = word.toLowerCase();
      return ACRONYMS[lower] || (word.charAt(0).toUpperCase() + word.slice(1));
    }).join(" ");
  }

  function fullTime(value) {
    const time = Date.parse(value || "");
    if (Number.isNaN(time)) return "—";
    return new Date(time).toLocaleString([], {
      year: "numeric", month: "short", day: "2-digit",
      hour: "2-digit", minute: "2-digit", second: "2-digit",
    });
  }

  function yesNo(value) {
    return value ? "Pass" : "Fail";
  }

  function originLabel() {
    if (item.city && item.country) return item.city + ", " + item.country;
    if (item.country) return item.country;
    if ((item.geo || {}).is_private) return "Internal / reserved address space";
    return "Unresolved";
  }

  /* ------------------------------------------------------------- sections */

  function verdictSection() {
    const band = bandFor(item.severity);
    const score = Math.max(0, Math.min(100, Number(item.score) || 0));
    const safe = item.safeScore != null ? item.safeScore : 100 - score;

    return `
      <section class="verdict">
        <div class="verdict-main">
          <span class="sev-tag sev-${escapeHtml(item.severity)}"><i></i>${escapeHtml(band.label)}</span>
          <h1>${escapeHtml(pretty(item.category))}</h1>
          <p class="verdict-line">${escapeHtml(band.description || "")}</p>
          <dl class="verdict-facts">
            <div><dt>From</dt><dd>${escapeHtml(item.sender || "not recorded")}</dd></div>
            <div><dt>Subject</dt><dd>${escapeHtml(item.subject || "not recorded")}</dd></div>
            <div><dt>Message id</dt><dd class="mono">${escapeHtml(item.messageId || "—")}</dd></div>
            <div><dt>Analysed</dt><dd>${escapeHtml(fullTime(item.timestamp))}</dd></div>
            <div><dt>Disposition</dt><dd>${item.flagged ? "Flagged for review" : "Delivered — no action"}</dd></div>
            <div><dt>Origin</dt><dd>${escapeHtml(originLabel())}</dd></div>
          </dl>
        </div>

        <div class="verdict-score">
          <div class="gauge sev-${escapeHtml(item.severity)}" style="--pct:${score}">
            <span class="gauge-num">${item.score != null ? escapeHtml(item.score) : "—"}</span>
            <span class="gauge-cap">threat score</span>
          </div>
          <p class="gauge-safe">Safe score <b>${escapeHtml(safe)}</b>/100</p>
        </div>
      </section>`;
  }

  function evidenceSection() {
    const evidence = item.evidence || [];
    if (!evidence.length) {
      return section("Evidence chain", "<p class=\"empty\">No contributing factors were recorded for this case.</p>");
    }

    const widest = Math.max(...evidence.map((e) => Math.abs(Number(e.contribution) || 0)), 1);
    const rows = evidence.map((entry) => {
      const value = Number(entry.contribution) || 0;
      const negative = value < 0;
      const width = (Math.abs(value) / widest) * 100;
      return `
        <tr>
          <td class="ev-factor">${escapeHtml(entry.factor)}</td>
          <td class="ev-why">${escapeHtml(entry.explanation)}</td>
          <td class="ev-bar">
            <span class="ev-track">
              <i class="${negative ? "neg" : "pos"}" style="width:${width}%"></i>
            </span>
          </td>
          <td class="ev-num ${negative ? "flag-fail" : "flag-pass"}">${value > 0 ? "+" : ""}${value}</td>
        </tr>`;
    }).join("");

    return section("Evidence chain",
      `<p class="sec-note">Each factor is retained separately with the weight it contributed, so the
       verdict can be examined line by line rather than taken as a single opaque number.</p>
       <table class="ev-table">
         <thead><tr><th>Factor</th><th>Finding</th><th>Weight</th><th class="ev-num">Δ</th></tr></thead>
         <tbody>${rows}</tbody>
       </table>`);
  }

  function authenticationSection() {
    const f = item.features || {};
    const checks = [
      ["SPF", f.spf_pass, "Is the sending IP authorised by the domain's SPF record?"],
      ["DKIM", f.dkim_pass, "Is the cryptographic signature present and valid?"],
      ["DMARC", f.dmarc_pass, "Is an alignment policy published, and satisfied?"],
    ];

    const rows = checks.map(([label, pass, why]) => `
      <tr>
        <td><b>${escapeHtml(label)}</b></td>
        <td class="${pass ? "flag-pass" : "flag-fail"}">${yesNo(pass)}</td>
        <td class="ev-why">${escapeHtml(why)}</td>
      </tr>`).join("");

    return section("Sender authentication",
      `<table class="auth-table"><tbody>${rows}</tbody></table>`);
  }

  function infrastructureSection() {
    const f = item.features || {};
    const geo = item.geo || {};
    const cells = [
      ["Sender IP", item.senderIp || geo.ip || "—"],
      ["Origin", originLabel()],
      ["Geo source", geo.source || "unresolved"],
      ["Location precision", geo.precision || "none"],
      ["Hosting / VPN range", f.ip_is_known_vpn_or_hosting ? "Yes" : "No"],
      ["ASN reputation", f.asn_reputation_score != null ? f.asn_reputation_score : "—"],
      ["Domain age", f.domain_age_days != null ? f.domain_age_days + " days" : "—"],
      ["Relay hops", f.relay_hop_count != null ? f.relay_hop_count : "—"],
      ["Header anomaly score", f.header_anomaly_score != null ? f.header_anomaly_score : "—"],
      ["Geo matches expectation", f.geo_matches_expected_countries == null ? "—" : (f.geo_matches_expected_countries ? "Yes" : "No")],
    ];

    return section("Sending infrastructure",
      `<div class="fact-grid">
        ${cells.map(([label, value]) => `
          <div class="fact"><span>${escapeHtml(label)}</span><b>${escapeHtml(value)}</b></div>`).join("")}
       </div>`);
  }

  function modelSection() {
    const tier0 = item.tier0;
    const tier1 = item.tier1 || [];
    let html = "";

    if (tier0) {
      const cats = (tier0.categories || []).map((c) => `
        <tr>
          <td>${escapeHtml(pretty(c.category))}</td>
          <td class="ev-bar"><span class="ev-track"><i class="pos" style="width:${Math.min(100, Number(c.confidence) || 0)}%"></i></span></td>
          <td class="ev-num">${escapeHtml(c.confidence)}%</td>
        </tr>`).join("");

      html += `
        <h3 class="sub">Tier 0 — gatekeeper</h3>
        <p class="sec-note">A LightGBM classifier over header, protocol and IP-trust features. It scores
        every message and ranks which specialist checks are worth running.</p>
        <div class="fact-grid fact-grid-3">
          <div class="fact"><span>Predicted class</span><b>${escapeHtml(pretty(tier0.predicted_class))}</b></div>
          <div class="fact"><span>Overall scam score</span><b>${escapeHtml(tier0.overall_scam_score)}</b></div>
          <div class="fact"><span>Categories ranked</span><b>${(tier0.categories || []).length}</b></div>
        </div>
        ${cats ? `<table class="ev-table ev-table-tight"><tbody>${cats}</tbody></table>` : ""}`;
    }

    if (tier1.length) {
      const rows = tier1.map((r) => `
        <tr>
          <td><b>${escapeHtml(r.adapter || "—")}</b></td>
          <td class="ev-why mono">${escapeHtml(r.model || "—")}</td>
          <td class="ev-bar"><span class="ev-track"><i class="pos" style="width:${Math.min(100, (Number(r.confidence) || 0) * 100)}%"></i></span></td>
          <td class="ev-num">${escapeHtml(r.confidence)}</td>
        </tr>`).join("");

      html += `
        <h3 class="sub">Tier 1 — specialist adapters</h3>
        <p class="sec-note">ModernBERT-base with one independently trained LoRA adapter attached per
        category, checked in the order Tier 0 suggested.</p>
        <table class="ev-table">
          <thead><tr><th>Adapter</th><th>Model</th><th>Confidence</th><th class="ev-num">Score</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>`;
    }

    if (!html) {
      html = "<p class=\"empty\">No per-tier model telemetry was stored for this case. " +
             "The evidence chain above still lists every factor that produced the verdict.</p>";
    }
    return section("Model cascade", html);
  }

  function campaignSection() {
    const siblings = campaign.siblings || [];
    const body = siblings.length
      ? `<p class="sec-note">This message shares a structural template fingerprint with
         ${siblings.length} other message${siblings.length === 1 ? "" : "s"}. Treat them as one operation.</p>
         <table class="ev-table">
           <thead><tr><th>Message</th><th>Analysed</th><th>Score</th><th>Origin</th></tr></thead>
           <tbody>${siblings.map((s) => `
             <tr>
               <td class="mono"><a href="/report/${encodeURIComponent(s.messageId)}">${escapeHtml(s.messageId)}</a></td>
               <td>${escapeHtml(fullTime(s.timestamp))}</td>
               <td class="sev-${escapeHtml(s.severity)}"><b>${escapeHtml(s.score)}</b></td>
               <td>${escapeHtml(s.city && s.country ? s.city + ", " + s.country : (s.country || "Unresolved"))}</td>
             </tr>`).join("")}</tbody>
         </table>`
      : `<p class="empty">No other stored message shares this fingerprint — no campaign correlation.</p>`;

    return section("Campaign correlation",
      `<div class="fact fact-wide">
         <span>Body fingerprint</span><b class="mono break">${escapeHtml(item.fingerprint || "—")}</b>
       </div>${body}`);
  }

  function ledgerSection() {
    if (!block) {
      return section("Evidence ledger",
        `<p class="empty">This case is not sealed into the hash chain. Restart the engine to seal
         pending cases, then re-open this report.</p>`);
    }

    return section("Evidence ledger",
      `<p class="sec-note">The report above was hashed with SHA-256 and written into a chained block the
       moment it was produced. Each block carries the hash of the one before it, so altering a stored
       verdict after the fact breaks this block and every block that follows.</p>
       <div class="chain-card">
         <div class="chain-row"><span>Block</span><b class="mono">#${escapeHtml(block.index)}</b></div>
         <div class="chain-row"><span>Sealed at</span><b>${escapeHtml(fullTime(block.sealedAt))}</b></div>
         <div class="chain-row"><span>Record hash</span><b class="mono break">${escapeHtml(block.recordHash)}</b></div>
         <div class="chain-row"><span>Previous block</span><b class="mono break">${escapeHtml(block.prevHash)}</b></div>
         <div class="chain-row"><span>Block hash</span><b class="mono break">${escapeHtml(block.hash)}</b></div>
       </div>
       <p class="chain-verdict" id="chain-verdict">Verifying chain…</p>`);
  }

  function section(title, inner) {
    return `
      <section class="sec">
        <h2>${escapeHtml(title)}</h2>
        ${inner}
      </section>`;
  }

  /* ----------------------------------------------------------------- boot */

  function render() {
    document.title = `Forensic report · ${item.messageId || "case"} — TrT`;
    document.getElementById("report").innerHTML =
      verdictSection() +
      evidenceSection() +
      authenticationSection() +
      infrastructureSection() +
      modelSection() +
      campaignSection() +
      ledgerSection();
  }

  /** Ask the engine to recompute the whole chain and report on this block. */
  async function verifyChain() {
    const target = document.getElementById("chain-verdict");
    if (!target) return;
    try {
      const response = await fetch("/api/ledger/verify", { cache: "no-store" });
      if (!response.ok) throw new Error("HTTP " + response.status);
      const result = await response.json();
      const mine = (result.blocks || []).find((b) => b.messageId === item.messageId);

      if (mine && mine.valid && result.intact) {
        target.className = "chain-verdict ok";
        target.textContent =
          `Verified — this block and all ${result.height} blocks in the chain recompute correctly. ` +
          `This report is byte-for-byte what the engine sealed.`;
      } else if (mine && mine.valid) {
        target.className = "chain-verdict warn";
        target.textContent =
          "This block verifies, but the chain has a failure elsewhere. " +
          "Check the dashboard's evidence ledger for the affected blocks.";
      } else {
        target.className = "chain-verdict bad";
        target.textContent = mine
          ? "Integrity check failed: " + (mine.issues || []).join("; ")
          : "This case is no longer present in the verified chain.";
      }
    } catch (err) {
      target.className = "chain-verdict warn";
      target.textContent = "Could not reach the engine to verify the chain: " + err.message;
    }
  }

  function summaryText() {
    const band = bandFor(item.severity);
    const lines = [
      `TrT forensic report — ${item.messageId}`,
      `Verdict: ${band.label} (${item.score}/100) — ${pretty(item.category)}`,
      `Analysed: ${fullTime(item.timestamp)}`,
      `Origin: ${originLabel()}`,
      "",
      "Evidence:",
      ...(item.evidence || []).map((e) => `  ${e.contribution > 0 ? "+" : ""}${e.contribution}  ${e.factor} — ${e.explanation}`),
    ];
    if (block) {
      lines.push("", `Sealed in ledger block #${block.index}`, `Block hash: ${block.hash}`);
    }
    return lines.join("\n");
  }

  function bindActions() {
    document.getElementById("print-btn").addEventListener("click", () => window.print());

    const copy = document.getElementById("copy-btn");
    copy.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(summaryText());
        const original = copy.textContent;
        copy.textContent = "Copied";
        setTimeout(() => { copy.textContent = original; }, 1600);
      } catch (err) {
        copy.textContent = "Copy blocked";
      }
    });
  }

  render();
  bindActions();
  verifyChain();
})();
