/* Settings controller.
 *
 * Port changes go through the service worker so the whole extension moves to
 * the new port at once, and the save is verified against a live health check
 * instead of being reported as successful regardless.
 */
(function () {
  "use strict";

  // Categories the Tier 0 LightGBM model actually scores today.
  const CATEGORIES = [
    { id: "bec", label: "Business Email Compromise (BEC)", tier0: true },
    { id: "vec", label: "Vendor Email Compromise (VEC)", tier0: false },
    { id: "fake_invoice", label: "Fake-Invoice Fraud", tier0: true },
    { id: "ceo_fraud", label: "CEO Fraud / Executive Spoofing", tier0: true },
    { id: "payroll_diversion", label: "Payroll Diversion", tier0: false },
    { id: "wire_fraud", label: "Wire Transfer Fraud", tier0: false },
    { id: "advance_fee", label: "Advance-Fee Fraud", tier0: false },
    { id: "phishing_mass", label: "Mass Phishing", tier0: false },
    { id: "phishing_spear", label: "Spear Phishing", tier0: false },
    { id: "whaling", label: "Whaling", tier0: false },
    { id: "clone_phishing", label: "Clone Phishing", tier0: false },
    { id: "angler_phishing", label: "Angler Phishing", tier0: false },
    { id: "lookalike_domain", label: "Lookalike Domain / Typosquatting", tier0: false },
    { id: "sextortion", label: "Sextortion", tier0: false },
    { id: "ransomware", label: "Ransomware Delivery / Extortion", tier0: false },
    { id: "credential_harvest", label: "Credential Harvesting", tier0: true },
    { id: "identity_theft", label: "Identity Theft", tier0: false },
    { id: "fake_tech_support", label: "Fake Tech Support", tier0: false },
    { id: "mfa_fatigue", label: "MFA Fatigue / Prompt Bombing", tier0: false },
    { id: "fake_login", label: "Fake Login Page", tier0: false },
    { id: "romance_scam", label: "Romance Scam", tier0: false },
    { id: "gift_card", label: "Gift Card Scam", tier0: false },
    { id: "lottery", label: "Lottery / Sweepstakes Fraud", tier0: false },
    { id: "overpayment", label: "Overpayment Scam", tier0: false },
    { id: "tax_impersonation", label: "Tax / Government Agency Impersonation", tier0: true },
    { id: "deepfake", label: "Deepfake Audio / Video Fraud", tier0: false },
    { id: "llm_phishing", label: "LLM-Generated Phishing", tier0: false },
    { id: "mystery_shopper", label: "Mystery Shopper", tier0: false },
    { id: "work_from_home", label: "Work-from-Home Fraud", tier0: false },
    { id: "greeting_card", label: "Greeting Card Malware", tier0: false },
  ];

  const TICKS = {
    ready: '<svg class="tick c-ready" viewBox="0 0 16 16"><path d="M3.5 8.4l3 3 6-6.6" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    idle: '<svg class="tick c-idle" viewBox="0 0 16 16"><circle cx="8" cy="8" r="3" fill="currentColor"/></svg>',
    unavailable: '<svg class="tick c-unavailable" viewBox="0 0 16 16"><path d="M4.5 4.5l7 7m0-7l-7 7" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
  };

  const els = {
    port: document.getElementById("port"),
    portStatus: document.getElementById("port-status"),
    savePort: document.getElementById("save-port"),
    detectPort: document.getElementById("detect-port"),
    connPill: document.getElementById("conn-pill"),
    connText: document.getElementById("conn-text"),
    components: document.getElementById("components"),
    grid: document.getElementById("category-grid"),
    counter: document.getElementById("category-counter"),
    categoryStatus: document.getElementById("category-status"),
    saveCategories: document.getElementById("save-categories"),
    selectAll: document.getElementById("select-all"),
    selectNone: document.getElementById("select-none"),
    version: document.getElementById("options-version"),
  };

  let enabledCategories = {};
  let filter = "all";

  try {
    const manifest = chrome.runtime.getManifest();
    if (manifest && manifest.version) els.version.textContent = "v" + manifest.version;
  } catch (err) { /* not fatal */ }

  function sendMessage(message) {
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage(message, (response) => {
          if (chrome.runtime.lastError) {
            resolve({ error: chrome.runtime.lastError.message });
            return;
          }
          resolve(response || { error: "No response from the service worker" });
        });
      } catch (err) {
        resolve({ error: err.message });
      }
    });
  }

  function escapeHtml(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  function setStatus(node, message, kind) {
    node.textContent = message;
    node.className = "status-msg status-" + kind;
  }

  function setConnection(state, text) {
    els.connPill.dataset.state = state;
    els.connText.textContent = text;
  }

  function renderComponents(components) {
    els.components.innerHTML = (components || []).map((component) => {
      const tick = TICKS[component.state] || TICKS.idle;
      return `<li>${tick}<b>${escapeHtml(component.label)}</b><em>${escapeHtml(component.detail || "")}</em></li>`;
    }).join("");
  }

  /* ------------------------------------------------------------ connection */

  async function checkConnection(force) {
    setConnection("checking", "Checking…");
    const status = await sendMessage({ type: "GET_ENGINE_STATUS", force: !!force });

    if (!status || status.error || !status.healthy) {
      setConnection("fail", "Not reachable");
      renderComponents([]);
      return status;
    }
    setConnection("ok", `Connected · ${status.port}`);
    renderComponents(status.components);
    if (status.port && !els.port.value) els.port.value = status.port;
    return status;
  }

  els.savePort.addEventListener("click", async () => {
    const port = parseInt(els.port.value, 10);
    if (!port || port < 1 || port > 65535) {
      setStatus(els.portStatus, "Enter a port between 1 and 65535.", "error");
      return;
    }
    setStatus(els.portStatus, "Saving and testing…", "info");
    const status = await sendMessage({ type: "SET_PORT", port });

    if (status && status.healthy) {
      setStatus(els.portStatus,
        `Connected to the engine on 127.0.0.1:${status.port}` +
        (status.version ? ` (v${status.version}).` : "."), "success");
      setConnection("ok", `Connected · ${status.port}`);
      renderComponents(status.components);
      els.port.value = status.port;
    } else {
      setStatus(els.portStatus,
        `Saved, but nothing answered on 127.0.0.1:${port}. Start the engine with run_local.bat, ` +
        "or use Auto-detect.", "error");
      setConnection("fail", "Not reachable");
      renderComponents([]);
    }
  });

  els.detectPort.addEventListener("click", async () => {
    setStatus(els.portStatus, "Probing common ports…", "info");
    const status = await checkConnection(true);
    if (status && status.healthy) {
      els.port.value = status.port;
      setStatus(els.portStatus, `Found the engine on 127.0.0.1:${status.port}.`, "success");
    } else {
      const tried = (status && status.checkedPorts) ? status.checkedPorts.join(", ") : "the usual ports";
      setStatus(els.portStatus, `No engine answered on ${tried}. Is run_local.bat running?`, "error");
    }
  });

  /* ------------------------------------------------------------ categories */

  function liveCategories() {
    return CATEGORIES.filter((category) => category.tier0);
  }

  function renderCategories() {
    const visible = CATEGORIES.filter((category) => {
      if (filter === "live") return category.tier0;
      if (filter === "soon") return !category.tier0;
      return true;
    });

    els.grid.innerHTML = visible.map((category) => {
      const on = enabledCategories[category.id] !== false;
      const soon = !category.tier0;
      return `
        <div class="category-item${soon ? " is-soon" : ""}${!soon && on ? " is-on" : ""}">
          <input type="checkbox" id="cat-${category.id}" ${on ? "checked" : ""} ${soon ? "disabled" : ""}>
          <label for="cat-${category.id}">${escapeHtml(category.label)}</label>
          ${soon ? '<span class="tag-soon">Soon</span>' : '<span class="tag-live">Live</span>'}
        </div>`;
    }).join("");

    const live = liveCategories();
    const enabledLive = live.filter((category) => enabledCategories[category.id] !== false).length;
    els.counter.textContent = `${enabledLive}/${live.length} live categories on`;
  }

  function readCheckboxes() {
    for (const category of CATEGORIES) {
      const input = document.getElementById("cat-" + category.id);
      if (input && !input.disabled) enabledCategories[category.id] = input.checked;
    }
  }

  els.grid.addEventListener("change", (event) => {
    if (event.target.matches('input[type="checkbox"]')) {
      readCheckboxes();
      renderCategories();
    }
  });

  document.querySelectorAll("[data-filter]").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll("[data-filter]").forEach((b) => b.classList.remove("is-active"));
      button.classList.add("is-active");
      filter = button.dataset.filter;
      renderCategories();
    });
  });

  function setLive(value) {
    for (const category of liveCategories()) enabledCategories[category.id] = value;
    renderCategories();
  }
  els.selectAll.addEventListener("click", () => setLive(true));
  els.selectNone.addEventListener("click", () => setLive(false));

  els.saveCategories.addEventListener("click", async () => {
    readCheckboxes();
    try {
      await chrome.storage.local.set({ enabledCategories });
    } catch (err) {
      setStatus(els.categoryStatus, "Could not save locally: " + err.message, "error");
      return;
    }

    // The engine accepts the wrapped shape; the bare map used to 422 silently.
    const response = await sendMessage({
      type: "PROXY_TO_LOCAL",
      payload: { path: "/api/categories", method: "POST", body: { enabledCategories } },
    });

    if (response && response.success) {
      const data = response.data || {};
      setStatus(els.categoryStatus,
        `Saved. The engine is now scoring ${data.enabled ?? "the selected"} of ${data.total ?? CATEGORIES.length} categories.`,
        "success");
    } else {
      setStatus(els.categoryStatus,
        "Saved in the browser, but the engine did not confirm" +
        (response && response.error ? ` (${response.error})` : "") +
        ". It will pick these up next time it is reachable.", "error");
    }
  });

  /* ------------------------------------------------------------------ boot */

  chrome.storage.local.get(["localPort", "enabledCategories"], (stored) => {
    if (stored.localPort) els.port.value = stored.localPort;
    if (stored.enabledCategories && typeof stored.enabledCategories === "object") {
      enabledCategories = stored.enabledCategories;
    } else {
      CATEGORIES.forEach((category) => { enabledCategories[category.id] = true; });
    }
    renderCategories();
    checkConnection(true);
  });
})();
