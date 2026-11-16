/* Service worker: owns the connection to the local engine.
 *
 * The popup used to report "Engine offline" while the engine was running fine.
 * Two causes, both fixed here:
 *   1. The worker defaulted to port 8001 and the popup to 8000, so whichever
 *      the engine was not on reported a failure.
 *   2. Both read the saved port asynchronously but ran their first health
 *      check immediately, racing the read and probing the wrong port.
 *
 * Now there is one owner of the port: this worker resolves it once (probing a
 * short candidate list if the saved one does not answer), caches it, and the
 * popup asks for status rather than fetching on its own.
 */

const DEFAULT_PORT = 8001;
// Ports the engine realistically listens on: the saved one first, then the
// defaults that run.py and config.json have shipped with.
const CANDIDATE_PORTS = [8001, 8000, 8010, 8080];
const PROBE_TIMEOUT_MS = 1500;
const STATUS_TTL_MS = 4000;
const RETRY_BACKOFF_MS = [2000, 5000, 15000];
const RETRY_STEADY_MS = 30000;

let localPort = DEFAULT_PORT;
let offlineRetryQueue = [];
let retryAttempts = 0;
let retryTimer = null;
let isGmailTabActive = false;
let lastStatus = null;
let lastStatusAt = 0;
let inFlightStatus = null;

/** Resolves once the saved settings have been read. Everything awaits this. */
const ready = (async () => {
  try {
    const stored = await chrome.storage.local.get(["localPort", "offlineQueue"]);
    if (stored.localPort) localPort = stored.localPort;
    if (Array.isArray(stored.offlineQueue)) offlineRetryQueue = stored.offlineQueue;
  } catch (err) {
    console.warn("ETD: could not read stored settings:", err.message);
  }
})();

function saveOfflineQueue() {
  chrome.storage.local.set({ offlineQueue: offlineRetryQueue }).catch(() => {});
}

function baseUrlFor(port) {
  return `http://127.0.0.1:${port}`;
}

function getLocalBaseUrl() {
  return baseUrlFor(localPort);
}

/** fetch with a hard timeout — a hung socket must not stall the popup. */
async function fetchWithTimeout(url, options = {}, timeoutMs = PROBE_TIMEOUT_MS) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...options, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

async function fetchLocal(path, options = {}, timeoutMs = 20000) {
  await ready;
  const response = await fetchWithTimeout(`${getLocalBaseUrl()}${path}`, {
    ...options,
    headers: { "Content-Type": "application/json", ...options.headers },
  }, timeoutMs);
  if (!response.ok) {
    throw new Error(`Local API responded with ${response.status}: ${response.statusText}`);
  }
  return response.json();
}

/* ------------------------------------------------------------ discovery */

async function probePort(port) {
  try {
    const response = await fetchWithTimeout(`${baseUrlFor(port)}/health`, { method: "GET" });
    if (!response.ok) return null;
    const body = await response.json();
    return body && body.status === "ok" ? body : null;
  } catch (err) {
    return null;
  }
}

/**
 * Find the port the engine is actually on, saved port first.
 * Returns { port, health } or null when nothing answers.
 */
async function discoverEngine() {
  await ready;
  const tried = new Set();
  const order = [localPort, ...CANDIDATE_PORTS].filter((port) => {
    if (!port || tried.has(port)) return false;
    tried.add(port);
    return true;
  });

  for (const port of order) {
    const health = await probePort(port);
    if (!health) continue;
    if (port !== localPort) {
      console.info(`ETD: engine found on port ${port} (was probing ${localPort})`);
      localPort = port;
      chrome.storage.local.set({ localPort: port }).catch(() => {});
    }
    return { port, health };
  }
  return null;
}

/**
 * Full engine status for the popup: reachability plus what has finished
 * loading, so a running engine is never shown as offline.
 */
async function getEngineStatus(force = false) {
  if (!force && lastStatus && Date.now() - lastStatusAt < STATUS_TTL_MS) return lastStatus;
  if (inFlightStatus) return inFlightStatus;

  inFlightStatus = (async () => {
    const found = await discoverEngine();
    if (!found) {
      lastStatus = {
        healthy: false,
        state: "offline",
        port: localPort,
        baseUrl: getLocalBaseUrl(),
        message: "No engine responded on 127.0.0.1",
        checkedPorts: [localPort, ...CANDIDATE_PORTS.filter((p) => p !== localPort)],
      };
      lastStatusAt = Date.now();
      return lastStatus;
    }

    const status = {
      healthy: true,
      state: "loaded",
      port: found.port,
      baseUrl: baseUrlFor(found.port),
      version: found.health.version || null,
      uptimeSeconds: found.health.uptimeSeconds ?? null,
      components: [],
      today: null,
      profile: null,
      offlineMode: null,
    };

    // Detail endpoint; an older engine build will not have it, and that is
    // fine — reachable still means loaded.
    try {
      const detail = await fetchLocal("/api/engine/status", { method: "GET" }, 4000);
      status.state = detail.state === "loaded" ? "loaded" : "degraded";
      status.components = detail.components || [];
      status.today = detail.today || null;
      status.profile = detail.profile || null;
      status.offlineMode = detail.offlineMode ?? null;
      status.version = detail.version || status.version;
    } catch (err) {
      status.components = [{
        id: "api", label: "Local API", state: "ready",
        detail: `127.0.0.1:${found.port}`,
      }];
    }

    retryAttempts = 0;
    if (offlineRetryQueue.length) drainOfflineQueue();

    lastStatus = status;
    lastStatusAt = Date.now();
    return status;
  })();

  try {
    return await inFlightStatus;
  } finally {
    inFlightStatus = null;
  }
}

async function healthCheck() {
  const status = await getEngineStatus();
  return status.healthy;
}

/* ---------------------------------------------------------- offline queue */

async function drainOfflineQueue() {
  if (!offlineRetryQueue.length) return;
  const queue = [...offlineRetryQueue];
  offlineRetryQueue = [];
  saveOfflineQueue();

  for (const item of queue) {
    try {
      const result = await sendToLocal(item.type, item.payload);
      chrome.tabs.sendMessage(item.tabId, {
        type: "ANALYSIS_RESULT",
        requestId: item.requestId,
        result,
      }).catch(() => {});
    } catch (err) {
      offlineRetryQueue.push(item);
    }
  }
  saveOfflineQueue();
}

function scheduleRetry() {
  if (retryTimer) return;
  const delay = retryAttempts < RETRY_BACKOFF_MS.length
    ? RETRY_BACKOFF_MS[retryAttempts]
    : RETRY_STEADY_MS;
  retryTimer = setTimeout(async () => {
    retryTimer = null;
    retryAttempts++;
    const healthy = await healthCheck();
    if (healthy) await drainOfflineQueue();
    else scheduleRetry();
  }, delay);
}

function queueItemFrom(message, tabId) {
  return {
    type: message.type,
    payload: message.payload,
    tabId,
    requestId: message.requestId,
    timestamp: Date.now(),
  };
}

async function sendToLocal(type, payload) {
  const endpoint = type === "ANALYZE_EMAIL" ? "/api/analyze" : "/api/badge-score";
  return fetchLocal(endpoint, { method: "POST", body: JSON.stringify(payload) }, 60000);
}

/* -------------------------------------------------------------- messaging */

async function handleMessage(message, sender) {
  if (message.type === "GET_ENGINE_STATUS") {
    return getEngineStatus(message.force === true);
  }

  if (message.type === "SET_PORT") {
    const port = parseInt(message.port, 10);
    if (!port || port < 1 || port > 65535) return { error: "Invalid port" };
    localPort = port;
    await chrome.storage.local.set({ localPort: port });
    lastStatus = null;
    return getEngineStatus(true);
  }

  if (message.type === "OPEN_REPORT_WINDOW") {
    // Reports open as their own window rather than a tab, so an investigator
    // can hold several side by side against the inbox.
    const url = String(message.url || "");
    if (!url.startsWith(baseUrlFor(localPort)) && !/^http:\/\/(127\.0\.0\.1|localhost):\d+\//.test(url)) {
      return { error: "Refusing to open a non-local URL" };
    }
    const win = await chrome.windows.create({
      url,
      type: "popup",
      width: 1040,
      height: 920,
    });
    return { success: true, windowId: win.id };
  }

  if (message.type === "PROXY_TO_LOCAL") {
    // Handled before the tab guard below: the popup and the options page are
    // extension pages, not tabs, so `sender.tab` is undefined for them. This
    // used to sit after the guard and always answered "No tab context", which
    // is why the popup showed "—" for the adapter count and profile.
    try {
      // fetchLocal already returns parsed JSON — calling .json() on it threw.
      const data = await fetchLocal(message.payload.path, {
        method: message.payload.method || "GET",
        body: message.payload.body ? JSON.stringify(message.payload.body) : undefined,
      });
      return { success: true, data };
    } catch (err) {
      return { error: err.message };
    }
  }

  if (!sender.tab) return { error: "No tab context" };
  const tabId = sender.tab.id;

  if (message.type === "ANALYZE_EMAIL" || message.type === "BADGE_SCORE") {
    const isGmail = sender.tab.url && sender.tab.url.includes("mail.google.com");
    if (!isGmail) {
      offlineRetryQueue.push(queueItemFrom(message, tabId));
      saveOfflineQueue();
      return { queued: true, queuePosition: offlineRetryQueue.length };
    }
    try {
      const result = await sendToLocal(message.type, message.payload);
      return { success: true, data: result };
    } catch (err) {
      offlineRetryQueue.push(queueItemFrom(message, tabId));
      saveOfflineQueue();
      lastStatus = null;
      scheduleRetry();
      return { queued: true, error: err.message };
    }
  }

  return { error: "Unknown message type" };
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender)
    .then(sendResponse)
    .catch((err) => sendResponse({ error: err.message }));
  return true;
});

/* ------------------------------------------------------------- tab events */

function updateGmailTabState(tab) {
  const wasActive = isGmailTabActive;
  isGmailTabActive = !!(tab.url && tab.url.includes("mail.google.com"));
  if (!wasActive && isGmailTabActive && offlineRetryQueue.length) drainOfflineQueue();
}

chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    updateGmailTabState(await chrome.tabs.get(activeInfo.tabId));
  } catch (err) {
    isGmailTabActive = false;
  }
});

chrome.windows.onFocusChanged.addListener(async (windowId) => {
  if (windowId === chrome.windows.WINDOW_ID_NONE) {
    isGmailTabActive = false;
    return;
  }
  try {
    const [tab] = await chrome.tabs.query({ active: true, windowId });
    if (tab) updateGmailTabState(tab);
  } catch (err) {
    isGmailTabActive = false;
  }
});

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local" && changes.localPort) {
    localPort = changes.localPort.newValue || DEFAULT_PORT;
    lastStatus = null;
  }
});

chrome.runtime.onInstalled.addListener(async () => {
  const stored = await chrome.storage.local.get(["localPort"]);
  if (!stored.localPort) await chrome.storage.local.set({ localPort: DEFAULT_PORT });
  getEngineStatus(true);
});

chrome.runtime.onStartup.addListener(() => { getEngineStatus(true); });
