/* SecOps dashboard controller.
 *
 * Reads the payload the template embedded, renders every panel from it, then
 * keeps itself current from /api/cases. No external libraries — the engine is
 * expected to run on machines with little or no connectivity.
 */
(function () {
  "use strict";

  const SEVERITY_ORDER = ["critical", "high", "elevated", "low", "safe"];
  const REFRESH_MS = 15000;
  const ACTIVE_WINDOW_MS = 6 * 60 * 60 * 1000;   // "still active" pulse window

  const state = {
    cases: [],
    campaigns: [],
    bands: [],
    totals: {},
    byCategory: [],
    byCountry: [],
    search: "",
    severityFilter: new Set(),
    mapFilter: "all",
    sortKey: "timestamp",
    sortDir: -1,
    selectedId: null,
    markers: [],
    markerByCase: new Map(),
  };

  const el = (id) => document.getElementById(id);

  /* ------------------------------------------------------------- helpers */

  function readEmbedded(id, fallback) {
    const node = el(id);
    if (!node) return fallback;
    try {
      return JSON.parse(node.textContent);
    } catch (err) {
      console.warn("Could not parse embedded payload", id, err);
      return fallback;
    }
  }

  function escapeHtml(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
  }

  function bandFor(severity) {
    return state.bands.find((b) => b.id === severity) || { color: "#8aa2bc", label: severity };
  }

  const ACRONYMS = { bec: "BEC", vec: "VEC", ceo: "CEO", llm: "LLM", mfa: "MFA", ai: "AI" };

  function prettyCategory(value) {
    if (!value) return "Uncategorised";
    return String(value).split(/[_\s]+/).map((word) => {
      const lower = word.toLowerCase();
      return ACRONYMS[lower] || (word.charAt(0).toUpperCase() + word.slice(1));
    }).join(" ");
  }

  function parseTime(value) {
    const time = Date.parse(value || "");
    return Number.isNaN(time) ? 0 : time;
  }

  function relativeTime(value) {
    const time = parseTime(value);
    if (!time) return "—";
    const delta = Date.now() - time;
    if (delta < 60000) return "just now";
    const minutes = Math.floor(delta / 60000);
    if (minutes < 60) return minutes + "m ago";
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return hours + "h ago";
    const days = Math.floor(hours / 24);
    return days + "d ago";
  }

  function reportUrl(messageId) {
    return "/report/" + String(messageId || "").split("/").map(encodeURIComponent).join("/");
  }

  /** One window per case, named after it — clicking the same case twice
   *  refocuses its window instead of stacking duplicates. */
  function openReportWindow(url) {
    if (!url) return;
    const name = "trt-report-" + url.split("/").pop();
    const win = window.open(url, name, "width=1040,height=920,menubar=no,toolbar=no");
    if (win) win.focus();
    else window.open(url, "_blank");   // popup blocked — fall back to a tab
  }

  function shortHash(value, size) {
    const hash = String(value || "");
    const keep = size || 8;
    return hash.length > keep * 2 ? hash.slice(0, keep) + "…" + hash.slice(-keep) : hash || "—";
  }

  function originLabel(item) {
    if (item.city && item.country) return item.city + ", " + item.country;
    if (item.country) return item.country;
    const geo = item.geo || {};
    if (geo.is_private) return "Internal / reserved";
    return "Unresolved";
  }

  /* ---------------------------------------------------------------- KPIs */

  function renderKpis() {
    const totals = state.totals;
    const analyzed = totals.analyzed || 0;
    const flagged = totals.flagged || 0;
    const rate = analyzed ? Math.round((flagged / analyzed) * 100) : 0;

    const cards = [
      { label: "Messages analysed", value: analyzed, accent: "var(--low)",
        meta: totals.located + " geolocated", spark: buildSpark(() => true) },
      { label: "Threats flagged", value: flagged, accent: "var(--critical)",
        meta: rate + "% of all traffic", spark: buildSpark((c) => c.flagged) },
      { label: "Cleared as safe", value: totals.safe || 0, accent: "var(--safe)",
        meta: "Delivered without action", spark: buildSpark((c) => !c.flagged) },
      { label: "Active campaigns", value: totals.campaigns || 0, accent: "var(--campaign)",
        meta: "Repeated body fingerprints" },
      { label: "Origin countries", value: totals.countries || 0, accent: "var(--high)",
        meta: topCountryLabel() },
      { label: "Detection rate", value: rate, suffix: "%", accent: "var(--elevated)",
        meta: "Flagged ÷ analysed" },
    ];

    el("kpis").innerHTML = cards.map((card) => `
      <article class="kpi" style="--kpi-accent:${card.accent}">
        <div class="kpi-label">${escapeHtml(card.label)}</div>
        <div class="kpi-value">${card.value}${card.suffix ? `<small>${card.suffix}</small>` : ""}</div>
        ${card.spark || ""}
        <div class="kpi-meta">${escapeHtml(card.meta)}</div>
      </article>`).join("");
  }

  function topCountryLabel() {
    if (!state.byCountry.length) return "No origins resolved";
    const [country, count] = state.byCountry[0];
    return `${country} leads with ${count}`;
  }

  /** Twelve two-hour buckets over the last 24h, as a sparkline. */
  function buildSpark(predicate) {
    const buckets = new Array(12).fill(0);
    const now = Date.now();
    for (const item of state.cases) {
      if (!predicate(item)) continue;
      const age = now - parseTime(item.timestamp);
      if (age < 0 || age > 24 * 3600 * 1000) continue;
      const index = 11 - Math.floor(age / (2 * 3600 * 1000));
      if (index >= 0 && index < 12) buckets[index]++;
    }
    // With nothing in the last 24h every bar sits at its 2px floor, which reads
    // as a stray dashed rule rather than a chart. Draw nothing instead.
    if (!buckets.some((value) => value > 0)) return "";

    const max = Math.max(...buckets, 1);
    const bars = buckets.map((value, index) => {
      const height = Math.max(2, Math.round((value / max) * 22));
      const hot = index >= 9 && value > 0 ? " class=\"hot\"" : "";
      return `<i${hot} style="height:${height}px"></i>`;
    }).join("");
    return `<div class="kpi-spark" title="Last 24 hours, 2-hour buckets">${bars}</div>`;
  }

  /* -------------------------------------------------------------- legend */

  function renderSeverityLegend() {
    const counts = {};
    for (const item of state.cases) counts[item.severity] = (counts[item.severity] || 0) + 1;

    el("legend-severity").innerHTML = state.bands.map((band) => {
      const count = counts[band.id] || 0;
      return `
        <li class="legend-item${count ? "" : " is-muted"}">
          <span class="lg-swatch"><i class="lg-chip" style="background:${band.color}"></i></span>
          <span class="lg-text">
            <b>${escapeHtml(band.label)} <span class="muted">· score ${band.min}+</span></b>
            <em>${escapeHtml(band.description)}</em>
          </span>
          <span class="lg-count">${count}</span>
        </li>`;
    }).join("");

    const unlocated = state.cases.filter((c) => !c.located);
    const note = el("legend-unlocated");
    if (!unlocated.length) {
      note.textContent = "";
      return;
    }
    const priv = unlocated.filter((c) => (c.geo || {}).is_private).length;
    note.innerHTML = `<b>${unlocated.length} case${unlocated.length === 1 ? "" : "s"} not plotted.</b> ` +
      (priv ? `${priv} came from internal or reserved address space; ` : "") +
      "the rest had no routable sender IP in the headers.";
  }

  /* ----------------------------------------------------------------- map */

  let worldMap = null;

  function markerKey(item) {
    return item.lat.toFixed(2) + "," + item.lon.toFixed(2);
  }

  function buildMarkers() {
    const filtered = state.cases.filter(passesMapFilter);
    const groups = new Map();
    state.markerByCase = new Map();

    for (const item of filtered) {
      if (!item.located) continue;
      const key = markerKey(item);
      let marker = groups.get(key);
      if (!marker) {
        marker = {
          id: key,
          lat: item.lat,
          lon: item.lon,
          cases: [],
          count: 0,
          color: "#8aa2bc",
          severity: "safe",
          approximate: true,
          pulse: false,
          phase: Math.random(),
        };
        groups.set(key, marker);
      }
      marker.cases.push(item);
      marker.count++;
      state.markerByCase.set(item.messageId, key);

      if (SEVERITY_ORDER.indexOf(item.severity) < SEVERITY_ORDER.indexOf(marker.severity)) {
        marker.severity = item.severity;
      }
      if ((item.geo || {}).precision === "city") marker.approximate = false;
      if (item.flagged && Date.now() - parseTime(item.timestamp) < ACTIVE_WINDOW_MS) marker.pulse = true;
    }

    const markers = [...groups.values()];
    for (const marker of markers) {
      marker.color = bandFor(marker.severity).color;
      marker.radius = Math.min(5 + Math.sqrt(marker.count - 1) * 4.2, 15);
      marker.weight = marker.count;
    }
    state.markers = markers;
    return markers;
  }

  function buildLinks() {
    const links = [];
    const seen = new Set();
    for (const campaign of state.campaigns) {
      if (campaign.size < 2) continue;
      const points = [];
      for (const messageId of campaign.members) {
        const key = state.markerByCase.get(messageId);
        if (key && !points.includes(key)) points.push(key);
      }
      for (let i = 0; i < points.length - 1; i++) {
        const pair = points[i] + "|" + points[i + 1];
        if (seen.has(pair)) continue;
        seen.add(pair);
        links.push({ from: points[i], to: points[i + 1], fingerprint: campaign.fingerprint });
      }
    }
    return links;
  }

  function passesMapFilter(item) {
    if (state.mapFilter === "flagged") return !!item.flagged;
    if (state.mapFilter === "campaign") {
      const campaign = state.campaigns.find((c) => c.fingerprint === item.fingerprint);
      return !!campaign && campaign.size > 1;
    }
    return true;
  }

  function refreshMap() {
    if (!worldMap) return;
    const markers = buildMarkers();
    worldMap.setMarkers(markers);
    worldMap.setLinks(buildLinks());
    const plotted = markers.reduce((sum, m) => sum + m.count, 0);
    el("map-sub").textContent =
      `${plotted} case${plotted === 1 ? "" : "s"} across ${markers.length} origin${markers.length === 1 ? "" : "s"} · resolved from local IP databases`;
  }

  function showMapTip(hit) {
    const tip = el("map-tip");
    if (!hit) {
      tip.hidden = true;
      return;
    }
    const marker = hit.marker;
    const top = marker.cases.slice().sort((a, b) => (b.score || 0) - (a.score || 0))[0];
    const geo = top.geo || {};
    const categories = [...new Set(marker.cases.map((c) => prettyCategory(c.category)))].slice(0, 3);

    tip.innerHTML = `
      <b>${escapeHtml(originLabel(top))}</b>
      <div class="tip-row"><span>Cases</span><span>${marker.count}</span></div>
      <div class="tip-row"><span>Worst score</span><span>${top.score ?? "—"}</span></div>
      <div class="tip-row"><span>Severity</span><span style="color:${bandFor(marker.severity).color}">${escapeHtml(bandFor(marker.severity).label)}</span></div>
      <div class="tip-row"><span>Type</span><span>${escapeHtml(categories.join(", "))}</span></div>
      <div class="tip-foot">${escapeHtml(geo.source || "unresolved")}${marker.approximate ? " · country-level fix" : " · city-level fix"}</div>`;
    tip.style.left = hit.x + "px";
    tip.style.top = hit.y + "px";
    tip.hidden = false;
  }

  /* ------------------------------------------------------- campaign graph */

  const graph = { nodes: [], edges: [], alpha: 0, frame: null, hover: null };

  function buildGraph() {
    const nodes = [];
    const edges = [];
    const byId = new Map();

    for (const campaign of state.campaigns) {
      if (campaign.size < 2) continue;
      const members = campaign.members
        .map((id) => state.cases.find((c) => c.messageId === id))
        .filter(Boolean);
      if (members.length < 2) continue;

      const hubId = "fp:" + campaign.fingerprint;
      const hub = {
        id: hubId,
        type: "hub",
        label: prettyCategory(members[0].category),
        fingerprint: campaign.fingerprint,
        size: 9 + Math.min(members.length, 10),
        color: "#6f42c1",
        x: 0, y: 0, vx: 0, vy: 0,
        count: members.length,
      };
      nodes.push(hub);
      byId.set(hubId, hub);

      for (const member of members) {
        const node = {
          id: member.messageId,
          type: "node",
          label: member.messageId,
          size: 5.5,
          color: bandFor(member.severity).color,
          score: member.score,
          category: member.category,
          x: 0, y: 0, vx: 0, vy: 0,
        };
        nodes.push(node);
        byId.set(node.id, node);
        edges.push({ source: hubId, target: node.id });
      }
    }

    // Seed positions on a ring so the layout settles the same way every time.
    nodes.forEach((node, index) => {
      const angle = (index / Math.max(nodes.length, 1)) * Math.PI * 2;
      const spread = node.type === "hub" ? 60 : 130;
      node.x = Math.cos(angle) * spread;
      node.y = Math.sin(angle) * spread;
    });

    graph.nodes = nodes;
    graph.edges = edges;
    graph.byId = byId;
    graph.alpha = 1;

    el("graph-empty").hidden = nodes.length > 0;
    if (nodes.length) startGraph();
    else drawGraph();
  }

  function stepGraph() {
    const nodes = graph.nodes;
    const repulsion = 2600;

    for (let i = 0; i < nodes.length; i++) {
      const a = nodes[i];
      for (let j = i + 1; j < nodes.length; j++) {
        const b = nodes[j];
        let dx = b.x - a.x;
        let dy = b.y - a.y;
        let distanceSq = dx * dx + dy * dy;
        if (distanceSq < 0.01) {
          dx = (Math.random() - 0.5) * 2;
          dy = (Math.random() - 0.5) * 2;
          distanceSq = dx * dx + dy * dy;
        }
        const distance = Math.sqrt(distanceSq);
        const force = repulsion / distanceSq;
        const fx = (dx / distance) * force;
        const fy = (dy / distance) * force;
        a.vx -= fx; a.vy -= fy;
        b.vx += fx; b.vy += fy;
      }
    }

    for (const edge of graph.edges) {
      const source = graph.byId.get(edge.source);
      const target = graph.byId.get(edge.target);
      if (!source || !target) continue;
      const dx = target.x - source.x;
      const dy = target.y - source.y;
      const distance = Math.max(Math.sqrt(dx * dx + dy * dy), 0.01);
      const force = (distance - 78) * 0.045;
      const fx = (dx / distance) * force;
      const fy = (dy / distance) * force;
      source.vx += fx; source.vy += fy;
      target.vx -= fx; target.vy -= fy;
    }

    for (const node of nodes) {
      node.vx -= node.x * 0.011;     // gravity toward centre
      node.vy -= node.y * 0.011;
      node.vx *= 0.82;
      node.vy *= 0.82;
      node.x += node.vx * graph.alpha;
      node.y += node.vy * graph.alpha;
    }
    graph.alpha *= 0.976;
  }

  function startGraph() {
    if (graph.frame) cancelAnimationFrame(graph.frame);
    const tick = () => {
      stepGraph();
      drawGraph();
      if (graph.alpha > 0.02) graph.frame = requestAnimationFrame(tick);
      else graph.frame = null;
    };
    graph.frame = requestAnimationFrame(tick);
  }

  function drawGraph() {
    const canvas = el("graph-canvas");
    const wrap = canvas.parentElement;
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const width = wrap.clientWidth;
    const height = wrap.clientHeight;
    if (!width || !height) return;

    canvas.width = Math.round(width * dpr);
    canvas.height = Math.round(height * dpr);
    canvas.style.width = width + "px";
    canvas.style.height = height + "px";

    const ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, width, height);
    ctx.save();
    ctx.translate(width / 2, height / 2);

    const scale = graphScale(width, height);
    ctx.scale(scale, scale);

    ctx.strokeStyle = "#b7cee6";
    ctx.lineWidth = 1 / scale;
    ctx.setLineDash([4 / scale, 3 / scale]);
    for (const edge of graph.edges) {
      const source = graph.byId.get(edge.source);
      const target = graph.byId.get(edge.target);
      if (!source || !target) continue;
      ctx.beginPath();
      ctx.moveTo(source.x, source.y);
      ctx.lineTo(target.x, target.y);
      ctx.stroke();
    }
    ctx.setLineDash([]);

    for (const node of graph.nodes) {
      const isSelected = node.id === state.selectedId;
      const isHover = graph.hover && graph.hover.id === node.id;

      if (node.type === "hub") {
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.size + 6, 0, Math.PI * 2);
        ctx.fillStyle = "rgba(111, 66, 193, .14)";
        ctx.fill();
      }
      ctx.beginPath();
      ctx.arc(node.x, node.y, node.size, 0, Math.PI * 2);
      ctx.fillStyle = node.color;
      ctx.fill();
      ctx.strokeStyle = "rgba(6, 32, 63, .3)";
      ctx.lineWidth = 1 / scale;
      ctx.stroke();
      if (isSelected || isHover) {
        ctx.strokeStyle = isSelected ? "#06203f" : "#0d5bc4";
        ctx.lineWidth = 2 / scale;
        ctx.stroke();
      }

      if (node.type === "hub") {
        ctx.fillStyle = "#244568";
        ctx.font = `600 ${11 / scale}px ${getComputedStyle(document.body).fontFamily}`;
        ctx.textAlign = "center";
        ctx.textBaseline = "top";
        ctx.fillText(`${node.label} ×${node.count}`, node.x, node.y + node.size + 5);
      }
    }
    ctx.restore();
    graph.scale = scale;
    graph.center = { x: width / 2, y: height / 2 };
  }

  function graphScale(width, height) {
    let extent = 60;
    for (const node of graph.nodes) {
      extent = Math.max(extent, Math.abs(node.x) + node.size + 26, Math.abs(node.y) + node.size + 26);
    }
    return Math.min(width / 2 / extent, height / 2 / extent, 1.6);
  }

  function graphHitTest(event) {
    const canvas = el("graph-canvas");
    const rect = canvas.getBoundingClientRect();
    if (!graph.center || !graph.scale) return null;
    const x = (event.clientX - rect.left - graph.center.x) / graph.scale;
    const y = (event.clientY - rect.top - graph.center.y) / graph.scale;
    for (const node of graph.nodes) {
      const dx = x - node.x;
      const dy = y - node.y;
      if (Math.sqrt(dx * dx + dy * dy) <= node.size + 4) return node;
    }
    return null;
  }

  /* ---------------------------------------------------------------- bars */

  function renderBars() {
    const categories = state.byCategory.slice(0, 9);
    const maxCategory = Math.max(...categories.map((entry) => entry[1]), 1);
    el("category-bars").innerHTML = categories.map(([name, count]) => {
      const flagged = state.cases.filter((c) => (c.category || "uncategorised") === name && c.flagged).length;
      return `
        <div class="bar-row">
          <div class="bar-label" title="${escapeHtml(prettyCategory(name))}">${escapeHtml(prettyCategory(name))}</div>
          <div class="bar-track"><div class="bar-fill" style="width:${(count / maxCategory) * 100}%"></div></div>
          <div class="bar-value">${count}${flagged ? `<span class="flag-tag">⚑${flagged}</span>` : ""}</div>
        </div>`;
    }).join("") || `<div class="empty-state">No cases yet</div>`;

    const countries = state.byCountry.slice(0, 7);
    const maxCountry = Math.max(...countries.map((entry) => entry[1]), 1);
    el("country-bars").innerHTML = countries.map(([code, count]) => `
      <div class="bar-row">
        <div class="bar-label">${escapeHtml(code)}</div>
        <div class="bar-track"><div class="bar-fill" style="width:${(count / maxCountry) * 100}%;background:linear-gradient(90deg,#4db2f7,#0a2c56)"></div></div>
        <div class="bar-value">${count}</div>
      </div>`).join("") || `<div class="empty-state">No origins resolved</div>`;
  }

  /* --------------------------------------------------------------- table */

  function renderChips() {
    el("severity-chips").innerHTML = state.bands.map((band) => {
      const on = state.severityFilter.has(band.id);
      return `<button type="button" class="chip${on ? " is-on" : ""}" data-sev="${band.id}" style="color:${on ? band.color : ""}">
        <i style="background:${band.color}"></i>${escapeHtml(band.label)}</button>`;
    }).join("");
  }

  function visibleCases() {
    const term = state.search.trim().toLowerCase();
    return state.cases.filter((item) => {
      if (state.severityFilter.size && !state.severityFilter.has(item.severity)) return false;
      if (!term) return true;
      return [item.messageId, item.sender, item.senderDomain, item.subject, item.category,
              item.country, item.city, item.fingerprint, item.geoSource]
        .some((field) => String(field || "").toLowerCase().includes(term));
    }).sort((a, b) => {
      const key = state.sortKey;
      let left = a[key];
      let right = b[key];
      if (key === "timestamp") { left = parseTime(left); right = parseTime(right); }
      if (key === "severity") {
        left = SEVERITY_ORDER.indexOf(a.severity);
        right = SEVERITY_ORDER.indexOf(b.severity);
      }
      if (left == null) left = "";
      if (right == null) right = "";
      if (left < right) return -1 * state.sortDir;
      if (left > right) return 1 * state.sortDir;
      return 0;
    });
  }

  function renderTable() {
    const rows = visibleCases();
    el("case-empty").hidden = rows.length > 0;
    el("case-sub").textContent =
      `${rows.length} of ${state.cases.length} case${state.cases.length === 1 ? "" : "s"}`;

    el("case-table").innerHTML = rows.map((item) => {
      const band = bandFor(item.severity);
      const score = Math.max(0, Math.min(100, Number(item.score) || 0));
      return `
        <tr data-id="${escapeHtml(item.messageId)}"${item.messageId === state.selectedId ? ' class="is-selected"' : ""}>
          <td title="${escapeHtml(item.timestamp || "")}">${escapeHtml(relativeTime(item.timestamp))}</td>
          <td><span class="sev-tag sev-${item.severity}"><i></i>${escapeHtml(band.label)}</span></td>
          <td><span class="score-cell sev-${item.severity}">${item.score ?? "—"}
            <span class="score-bar"><i style="width:${score}%"></i></span></span></td>
          <td>${escapeHtml(prettyCategory(item.category))}</td>
          <td class="col-sender" title="${escapeHtml(item.sender || item.messageId)}">
            ${item.sender
              ? `<b>${escapeHtml(item.sender)}</b>`
              : `<span class="mono">${escapeHtml(item.messageId)}</span>
                 <span class="flag-tag flag-tag-quiet">sender not logged</span>`}
          </td>
          <td class="col-subject" title="${escapeHtml(item.subject || "")}">
            ${item.subject ? escapeHtml(item.subject) : '<span class="muted">—</span>'}
          </td>
          <td>${escapeHtml(originLabel(item))}${item.hosting ? ' <span class="flag-tag">hosting</span>' : ""}</td>
          <td class="${item.authPass ? "flag-pass" : "flag-fail"}">${item.authPass ? "SPF+DKIM" : "fail"}</td>
          <td class="col-report">
            <a class="report-link" href="${reportUrl(item.messageId)}" data-report="1">Report</a>
          </td>
        </tr>`;
    }).join("");
  }

  /* -------------------------------------------------------------- drawer */

  function openDrawer(messageId) {
    const item = state.cases.find((c) => c.messageId === messageId);
    if (!item) return;
    state.selectedId = messageId;

    const band = bandFor(item.severity);
    el("drawer-sev").className = "sev-tag sev-" + item.severity;
    el("drawer-sev").innerHTML = `<i></i>${escapeHtml(band.label)} · ${item.score ?? "—"}/100`;
    el("drawer-title").textContent = item.subject || item.messageId;
    el("drawer-sub").textContent =
      (item.sender ? `From ${item.sender} · ` : "") +
      `${prettyCategory(item.category)} · ${relativeTime(item.timestamp)} · ${originLabel(item)}`;
    el("drawer-report").href = reportUrl(item.messageId);

    const geo = item.geo || {};
    const features = item.features || {};
    const campaign = state.campaigns.find((c) => c.fingerprint === item.fingerprint);

    const cells = [
      ["Score", (item.score ?? "—") + "/100"],
      ["Safe score", (item.safeScore ?? "—") + "/100"],
      ["Sender IP", item.senderIp || "—"],
      ["Origin", originLabel(item)],
      ["Geo source", geo.source || "unresolved"],
      ["Precision", geo.precision || "none"],
      ["SPF", features.spf_pass ? "pass" : "fail"],
      ["DKIM", features.dkim_pass ? "pass" : "fail"],
      ["DMARC", features.dmarc_pass ? "pass" : "fail"],
      ["Domain age", features.domain_age_days != null ? features.domain_age_days + "d" : "—"],
      ["Relay hops", features.relay_hop_count ?? "—"],
      ["ASN reputation", features.asn_reputation_score ?? "—"],
    ];

    const evidence = (item.evidence || []).map((entry) => `
      <div class="ev-row ${(entry.contribution || 0) < 0 ? "neg" : "pos"}">
        <div>
          <b>${escapeHtml(entry.factor)}</b>
          <p>${escapeHtml(entry.explanation)}</p>
        </div>
        <span class="ev-delta ${(entry.contribution || 0) < 0 ? "flag-fail" : "flag-pass"}">
          ${(entry.contribution || 0) > 0 ? "+" : ""}${entry.contribution ?? 0}</span>
      </div>`).join("") || `<p class="muted">No evidence recorded for this case.</p>`;

    el("drawer-body").innerHTML = `
      <div class="d-section">
        <h3>Message</h3>
        <div class="d-cell"><span>From</span><b>${escapeHtml(item.sender || "not recorded")}</b></div>
        <div class="d-cell" style="margin-top:6px"><span>Subject</span><b>${escapeHtml(item.subject || "not recorded")}</b></div>
        <div class="d-cell" style="margin-top:6px"><span>Message id</span><b>${escapeHtml(item.messageId)}</b></div>
      </div>
      <div class="d-section">
        <h3>Verdict signals</h3>
        ${evidence}
      </div>
      <div class="d-section">
        <h3>Forensics</h3>
        <div class="d-grid">
          ${cells.map(([label, value]) => `
            <div class="d-cell"><span>${escapeHtml(label)}</span><b>${escapeHtml(value)}</b></div>`).join("")}
        </div>
      </div>
      <div class="d-section">
        <h3>Campaign</h3>
        <div class="d-cell">
          <span>Body fingerprint</span>
          <b style="word-break:break-all;font-size:11px">${escapeHtml(item.fingerprint || "—")}</b>
        </div>
        <p class="muted" style="margin:8px 0 0;font-size:11.5px">
          ${campaign && campaign.size > 1
            ? `Seen in ${campaign.size} messages — treated as one campaign.`
            : "No other message shares this fingerprint."}
        </p>
      </div>`;

    el("drawer").hidden = false;
    el("drawer-scrim").hidden = false;

    if (worldMap) worldMap.setSelected(state.markerByCase.get(messageId) || null);
    renderTable();
    drawGraph();
  }

  function closeDrawer() {
    state.selectedId = null;
    el("drawer").hidden = true;
    el("drawer-scrim").hidden = true;
    if (worldMap) worldMap.setSelected(null);
    renderTable();
    drawGraph();
  }

  /* --------------------------------------------------------------- ledger */

  /** Recompute the evidence chain server-side and render the verdict.
   *  `announce` is set when a human pressed Verify, so the button can report
   *  back even when the result is unchanged. */
  async function verifyChain(announce) {
    const stateEl = el("chain-state");
    const textEl = el("chain-state-text");
    const button = el("verify-btn");
    if (announce) {
      button.disabled = true;
      textEl.textContent = "Recomputing…";
    }

    try {
      const response = await fetch("/api/ledger/verify", { cache: "no-store" });
      if (!response.ok) throw new Error("HTTP " + response.status);
      const result = await response.json();
      renderLedger(result);
    } catch (err) {
      stateEl.className = "chain-state is-broken";
      textEl.textContent = "Chain unreadable";
      el("ledger-note").textContent = "Could not reach the ledger: " + err.message;
    } finally {
      button.disabled = false;
    }
  }

  function renderLedger(result) {
    const stateEl = el("chain-state");
    const textEl = el("chain-state-text");
    const intact = !!result.intact;

    stateEl.className = "chain-state " + (intact ? "is-intact" : "is-broken");
    textEl.textContent = intact
      ? "Chain verified"
      : `Chain broken · ${result.broken.length} block${result.broken.length === 1 ? "" : "s"}`;

    const verifiedAt = result.verifiedAt ? new Date(result.verifiedAt) : new Date();
    el("ledger-stats").innerHTML = [
      ["Chain height", result.height + " block" + (result.height === 1 ? "" : "s")],
      ["Head hash", shortHash(result.headHash, 7)],
      ["Algorithm", result.algorithm || "SHA-256"],
      ["Last verified", verifiedAt.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })],
    ].map(([label, value]) => `
      <div class="ledger-stat"><span>${escapeHtml(label)}</span><b>${escapeHtml(value)}</b></div>`).join("");

    const blocks = (result.blocks || []).slice(-14);
    const lastIndex = (result.blocks || []).length - 1;
    const strip = el("chain-strip");
    strip.innerHTML = blocks.map((block, position) => {
      const isHead = block.index === lastIndex;
      const classes = ["chain-block"];
      if (isHead) classes.push("is-head");
      if (!block.valid) classes.push("is-broken");
      const joint = position ? '<span class="chain-joint" aria-hidden="true"></span>' : "";
      return joint + `
        <a class="${classes.join(" ")}" href="${reportUrl(block.messageId)}"
           title="${escapeHtml(block.issues && block.issues.length ? block.issues.join(" · ") : "Block verified")}">
          <span class="cb-index">#${block.index}${isHead ? " · head" : ""}</span>
          <span class="cb-hash">${escapeHtml(shortHash(block.hash, 6))}</span>
          <span class="cb-meta">${escapeHtml(block.messageId || "—")}</span>
          <span class="cb-meta">${escapeHtml(relativeTime(block.sealedAt))}</span>
        </a>`;
    }).join("");

    // Blocks read oldest-to-newest; the head is the interesting end, so park
    // the scroll there rather than on ancient history.
    strip.scrollLeft = strip.scrollWidth;

    const note = el("ledger-note");
    if (intact) {
      note.className = "ledger-note";
      note.textContent =
        `Every stored case hashes back to the genesis block. Recomputing the chain reproduces ` +
        `head ${shortHash(result.headHash, 7)}, so no verdict has been altered since it was sealed.`;
    } else {
      note.className = "ledger-note is-broken";
      const first = result.broken[0];
      const unsealed = (result.unsealed || []).length;
      note.textContent =
        (first ? `Block #${first.index} (${first.messageId}) failed: ${first.issues.join("; ")}. ` : "") +
        (unsealed ? `${unsealed} case(s) are not sealed into the chain. ` : "") +
        "Treat every block after the first failure as unverified.";
    }

    const foot = el("foot-chain");
    if (foot) foot.textContent = "Evidence ledger: " + (intact ? `${result.height} blocks verified` : "chain broken");
  }

  /* --------------------------------------------------------------- wiring */

  function applyPayload(payload) {
    state.cases = payload.cases || [];
    state.campaigns = payload.campaigns || [];
    state.bands = payload.severityBands || [];
    state.totals = payload.totals || {};
    state.byCategory = payload.byCategory || [];
    state.byCountry = payload.byCountry || [];

    renderKpis();
    renderSeverityLegend();
    renderChips();
    renderBars();
    renderTable();
    refreshMap();
    buildGraph();

    const stamp = payload.generatedAt ? new Date(payload.generatedAt) : new Date();
    el("pill-updated-text").textContent = "Updated " + stamp.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  }

  function applyGeoStatus(status) {
    const provider = status.activeProvider || "none";
    el("pill-geo-text").textContent = provider.replace(/\s*\(.*\)/, "");
    el("pill-geo").title =
      `IP intelligence: ${provider}\n` +
      (status.providers || []).map((p) => `· ${p.name} — ${p.detail}`).join("\n");
    el("foot-geo").textContent = "IP intelligence: " + provider + " (offline)";
  }

  function setEnginePill(ok, detail) {
    const pill = el("pill-engine");
    pill.className = "pill " + (ok ? "pill-live" : "pill-down");
    el("pill-engine-text").textContent = ok ? "Engine loaded" : "Engine unreachable";
    pill.title = detail || "";
  }

  async function refresh() {
    try {
      const response = await fetch("/api/cases", { cache: "no-store" });
      if (!response.ok) throw new Error("HTTP " + response.status);
      applyPayload(await response.json());
      setEnginePill(true, "Local engine responding");
    } catch (err) {
      setEnginePill(false, "Could not reach the local engine: " + err.message);
    }
  }

  async function pollEngine() {
    try {
      const response = await fetch("/api/engine/status", { cache: "no-store" });
      if (!response.ok) throw new Error("HTTP " + response.status);
      const status = await response.json();
      const ready = status.state === "loaded";
      setEnginePill(true, status.components.map((c) => `${c.label}: ${c.state} (${c.detail})`).join("\n"));
      el("pill-engine-text").textContent = ready ? "Engine loaded" : "Engine degraded";
    } catch (err) {
      setEnginePill(false, err.message);
    }
  }

  function bindEvents() {
    el("refresh-btn").addEventListener("click", () => { refresh(); pollEngine(); });
    el("map-reset").addEventListener("click", () => worldMap && worldMap.resetView());

    document.querySelectorAll("[data-mapfilter]").forEach((button) => {
      button.addEventListener("click", () => {
        document.querySelectorAll("[data-mapfilter]").forEach((b) => b.classList.remove("is-active"));
        button.classList.add("is-active");
        state.mapFilter = button.dataset.mapfilter;
        refreshMap();
      });
    });

    el("severity-chips").addEventListener("click", (event) => {
      const chip = event.target.closest(".chip");
      if (!chip) return;
      const severity = chip.dataset.sev;
      if (state.severityFilter.has(severity)) state.severityFilter.delete(severity);
      else state.severityFilter.add(severity);
      renderChips();
      renderTable();
    });

    let searchTimer = null;
    el("case-search").addEventListener("input", (event) => {
      clearTimeout(searchTimer);
      const value = event.target.value;
      searchTimer = setTimeout(() => {
        state.search = value;
        renderTable();
      }, 120);
    });

    document.querySelectorAll("th.sortable").forEach((header) => {
      header.addEventListener("click", () => {
        const key = header.dataset.sort;
        if (state.sortKey === key) state.sortDir *= -1;
        else { state.sortKey = key; state.sortDir = key === "timestamp" ? -1 : 1; }
        document.querySelectorAll("th.sortable").forEach((h) => h.classList.remove("is-sorted-asc", "is-sorted-desc"));
        header.classList.add(state.sortDir === 1 ? "is-sorted-asc" : "is-sorted-desc");
        renderTable();
      });
    });

    el("case-table").addEventListener("click", (event) => {
      // The per-row Report link opens its own window; it must not also open
      // the drawer behind it.
      const report = event.target.closest("[data-report]");
      if (report) {
        event.preventDefault();
        openReportWindow(report.getAttribute("href"));
        return;
      }
      const row = event.target.closest("tr[data-id]");
      if (row) openDrawer(row.dataset.id);
    });

    el("drawer-report").addEventListener("click", (event) => {
      event.preventDefault();
      openReportWindow(el("drawer-report").getAttribute("href"));
    });

    el("chain-strip").addEventListener("click", (event) => {
      const block = event.target.closest(".chain-block");
      if (!block) return;
      event.preventDefault();
      openReportWindow(block.getAttribute("href"));
    });

    el("verify-btn").addEventListener("click", () => verifyChain(true));

    el("drawer-close").addEventListener("click", closeDrawer);
    el("drawer-scrim").addEventListener("click", closeDrawer);
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") closeDrawer();
    });

    const graphCanvas = el("graph-canvas");
    graphCanvas.addEventListener("mousemove", (event) => {
      const node = graphHitTest(event);
      graph.hover = node;
      graphCanvas.style.cursor = node ? "pointer" : "default";
      const tip = el("graph-tip");
      if (node) {
        const rect = graphCanvas.getBoundingClientRect();
        tip.innerHTML = node.type === "hub"
          ? `<b>${escapeHtml(node.label)} campaign</b>
             <div class="tip-row"><span>Messages</span><span>${node.count}</span></div>
             <div class="tip-foot">${escapeHtml(node.fingerprint)}</div>`
          : `<b>${escapeHtml(node.label)}</b>
             <div class="tip-row"><span>Score</span><span>${node.score ?? "—"}</span></div>
             <div class="tip-foot">${escapeHtml(prettyCategory(node.category))}</div>`;
        tip.style.left = (event.clientX - rect.left) + "px";
        tip.style.top = (event.clientY - rect.top) + "px";
        tip.hidden = false;
      } else {
        tip.hidden = true;
      }
      drawGraph();
    });
    graphCanvas.addEventListener("mouseleave", () => {
      graph.hover = null;
      el("graph-tip").hidden = true;
      drawGraph();
    });
    graphCanvas.addEventListener("click", (event) => {
      const node = graphHitTest(event);
      if (node && node.type === "node") openDrawer(node.id);
    });

    window.addEventListener("resize", () => drawGraph());
  }

  /* ----------------------------------------------------------------- boot */

  function init() {
    worldMap = new WorldMap(el("map-canvas"), {
      onHover: showMapTip,
      onSelect: (marker) => {
        if (!marker) return;
        const worst = marker.cases.slice().sort((a, b) => (b.score || 0) - (a.score || 0))[0];
        if (worst) openDrawer(worst.messageId);
      },
    });
    worldMap.loadGrid("/static/world_grid.json");

    bindEvents();
    applyPayload(readEmbedded("embedded-payload", { cases: [] }));
    applyGeoStatus(readEmbedded("embedded-geo", {}));
    pollEngine();
    verifyChain(false);

    setInterval(refresh, REFRESH_MS);
    setInterval(pollEngine, REFRESH_MS * 2);
    setInterval(() => verifyChain(false), REFRESH_MS * 4);
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
