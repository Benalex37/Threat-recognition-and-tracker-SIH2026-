/* Popup controller.
 *
 * Engine state comes from the service worker, which owns port discovery. The
 * popup never guesses a port and never fetches before that resolves, which is
 * what used to make a healthy engine show as "Engine offline".
 */
(function () {
  "use strict";

  const els = {
    card: document.getElementById("status-card"),
    state: document.getElementById("engine-state"),
    detail: document.getElementById("engine-detail"),
    components: document.getElementById("components"),
    actions: document.getElementById("status-actions"),
    retry: document.getElementById("retry-btn"),
    offlineHint: document.getElementById("offline-hint"),
    version: document.getElementById("version-display"),
    profile: document.getElementById("profile-val"),
    adapters: document.getElementById("adapters-val"),
    port: document.getElementById("port-val"),
    geo: document.getElementById("geo-val"),
    analyzed: document.getElementById("analyzed-val"),
    flagged: document.getElementById("flagged-val"),
    safe: document.getElementById("safe-val"),
    dashboard: document.getElementById("launch-dashboard"),
    options: document.getElementById("open-options"),
  };

  const STATE_COPY = {
    checking: { title: "Checking engine…", detail: "Looking for the local engine" },
    loaded: { title: "Engine loaded", detail: "Analysing on this device" },
    degraded: { title: "Engine starting…", detail: "Reachable, still warming up" },
    offline: { title: "Engine offline", detail: "No response on 127.0.0.1" },
  };

  const TICKS = {
    ready: '<svg class="tick c-ready" viewBox="0 0 16 16"><path d="M3.5 8.4l3 3 6-6.6" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    idle: '<svg class="tick c-idle" viewBox="0 0 16 16"><circle cx="8" cy="8" r="3" fill="currentColor"/></svg>',
    unavailable: '<svg class="tick c-unavailable" viewBox="0 0 16 16"><path d="M4.5 4.5l7 7m0-7l-7 7" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
  };

  let baseUrl = null;

  try {
    const manifest = chrome.runtime.getManifest();
    if (manifest && manifest.version) els.version.textContent = "v" + manifest.version;
  } catch (err) { /* manifest is always present in practice */ }

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

  function setState(state, titleOverride, detailOverride) {
    const copy = STATE_COPY[state] || STATE_COPY.offline;
    els.card.dataset.state = state;
    els.state.textContent = titleOverride || copy.title;
    els.detail.textContent = detailOverride || copy.detail;
    els.actions.hidden = state !== "offline";
    els.dashboard.disabled = state === "offline" || state === "checking";
  }

  function renderComponents(components) {
    if (!components || !components.length) {
      els.components.innerHTML = "";
      return;
    }
    els.components.innerHTML = components.map((component) => {
      const tick = TICKS[component.state] || TICKS.idle;
      return `<li>${tick}<b>${escapeHtml(component.label)}</b><em>${escapeHtml(component.detail || "")}</em></li>`;
    }).join("");
  }

  function escapeHtml(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  function clearMetrics(placeholder) {
    els.analyzed.textContent = placeholder;
    els.flagged.textContent = placeholder;
    els.safe.textContent = placeholder;
    els.profile.textContent = placeholder;
    els.adapters.textContent = placeholder;
    els.geo.textContent = placeholder;
  }

  async function loadEngineDetails(status) {
    if (status.today) {
      els.analyzed.textContent = status.today.analyzed ?? 0;
      els.flagged.textContent = status.today.flagged ?? 0;
      els.safe.textContent = status.today.safe ?? 0;
    }
    if (status.profile) els.profile.textContent = status.profile;

    const geoComponent = (status.components || []).find((c) => c.id === "geo");
    if (geoComponent) {
      els.geo.textContent = geoComponent.detail.replace(/\s*\(.*\)/, "");
      els.geo.title = geoComponent.detail;
    }

    // /api/config carries the adapter count and profile for older builds too.
    try {
      const response = await sendMessage({
        type: "PROXY_TO_LOCAL",
        payload: { path: "/api/config", method: "GET" },
      });
      if (response && response.success && response.data) {
        els.profile.textContent = response.data.profile || els.profile.textContent;
        els.adapters.textContent = response.data.activeAdapters ?? "—";
      }
    } catch (err) { /* details are optional */ }
  }

  async function refresh(force) {
    const status = await sendMessage({ type: "GET_ENGINE_STATUS", force: !!force });

    if (!status || status.error) {
      setState("offline", "Engine offline", status && status.error
        ? "Extension error: " + status.error
        : "No response on 127.0.0.1");
      renderComponents([]);
      clearMetrics("—");
      return;
    }

    baseUrl = status.baseUrl || null;
    els.port.textContent = status.port ? "127.0.0.1:" + status.port : "—";

    if (!status.healthy) {
      setState("offline", "Engine offline",
        "Checked ports " + (status.checkedPorts || []).join(", "));
      renderComponents([]);
      clearMetrics("—");
      return;
    }

    setState(status.state === "loaded" ? "loaded" : "degraded",
      null,
      status.version ? `v${status.version} · port ${status.port}` : `port ${status.port}`);
    renderComponents(status.components);
    await loadEngineDetails(status);
  }

  els.retry.addEventListener("click", () => {
    setState("checking");
    refresh(true);
  });

  els.dashboard.addEventListener("click", () => {
    if (!baseUrl) return;
    chrome.tabs.create({ url: baseUrl + "/dashboard" });
  });

  els.options.addEventListener("click", () => chrome.runtime.openOptionsPage());

  setState("checking");
  refresh(true);
  const timer = setInterval(() => refresh(false), 8000);
  window.addEventListener("unload", () => clearInterval(timer));
})();
