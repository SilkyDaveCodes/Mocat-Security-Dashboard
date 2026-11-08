/* MoCat HomeSOC UI (CLAUDE.md §6.6, §6.7).
 *
 * Talks only to the local agent at API_BASE (127.0.0.1:8765). No external resources.
 *
 * The file has two halves:
 *   1. Pure helpers (escaping, rendering, API client with an injectable fetch, state updates).
 *      They don't touch the DOM, so tests/js/test_app.mjs runs them under Node.
 *   2. Browser wiring (only when `document` exists): screens, buttons, WebSocket with backoff.
 */
"use strict";

// Keep in sync with app/main.py API_BASE_URL / WS_URL (tests/test_app_ui.py checks it).
const API_BASE = "http://127.0.0.1:8765";
const WS_URL = "ws://127.0.0.1:8765/ws";

const MODES = ["off", "notify", "auto"];
const MODE_LABELS = {
  off: "Off — watch only",
  notify: "Notify — alert me, don't block",
  auto: "Auto-protect — alert and contain",
};
const MODE_NAMES = { off: "Off", notify: "Notify", auto: "Auto-protect" };
const SEVERITIES = ["low", "medium", "high", "critical"];
const BACKOFF_BASE_MS = 1000;
const BACKOFF_MAX_MS = 30000;
const APPS_RESYNC_MS = 30000;
const STATUS_REFRESH_MS = 10000;

/* ---------------------------------------------------------------- escaping / formatting */

const HTML_ESCAPES = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "`": "&#96;" };

function escapeHtml(value) {
  if (value === null || value === undefined) return "";
  return String(value).replace(/[&<>"'`]/g, (ch) => HTML_ESCAPES[ch]);
}

function formatBytes(n) {
  const v = Number(n) || 0;
  if (v < 1024) return `${v} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let x = v / 1024;
  let i = 0;
  while (x >= 1024 && i < units.length - 1) {
    x /= 1024;
    i += 1;
  }
  return `${x.toFixed(1)} ${units[i]}`;
}

function formatTime(tsMs) {
  if (!tsMs) return "";
  return new Date(Number(tsMs)).toLocaleString();
}

function formatDuration(seconds) {
  let s = Math.max(0, Math.floor(Number(seconds) || 0));
  const h = Math.floor(s / 3600);
  s -= h * 3600;
  const m = Math.floor(s / 60);
  s -= m * 60;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${s}s`;
  return `${s}s`;
}

function shortId(id) {
  return String(id || "").slice(0, 8);
}

/* ---------------------------------------------------------------- API client */

class ApiError extends Error {
  constructor(status, detail) {
    super(detail || `HTTP ${status}`);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

function apiUrl(path) {
  if (typeof path !== "string" || !path.startsWith("/")) {
    throw new Error(`API path must start with '/': ${path}`);
  }
  return API_BASE + path;
}

function defaultFetch() {
  if (typeof fetch !== "function") throw new Error("fetch is not available");
  return fetch;
}

async function apiRequest(path, options, fetchFn) {
  const doFetch = fetchFn || defaultFetch();
  const opts = options || {};
  const init = { method: opts.method || "GET", headers: {} };
  if (opts.body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(opts.body);
  }
  let resp;
  try {
    resp = await doFetch(apiUrl(path), init);
  } catch (err) {
    throw new ApiError(0, "The MoCat agent is not reachable. Is it running?");
  }
  let data = null;
  try {
    data = await resp.json();
  } catch (err) {
    data = null;
  }
  if (!resp.ok) {
    let detail = data && data.detail;
    if (Array.isArray(detail)) detail = detail.map((d) => d.msg || String(d)).join("; ");
    throw new ApiError(resp.status, detail ? String(detail) : `HTTP ${resp.status}`);
  }
  return data;
}

const enc = encodeURIComponent;

function getStatus(fetchFn) {
  return apiRequest("/status", {}, fetchFn);
}

function getApps(fetchFn) {
  return apiRequest("/apps", {}, fetchFn);
}

function getAlerts(limit, fetchFn) {
  const n = Number.isInteger(limit) && limit > 0 ? limit : 100;
  return apiRequest(`/alerts?limit=${n}`, {}, fetchFn);
}

function undoAction(actionId, fetchFn) {
  if (!actionId) return Promise.reject(new Error("No action id"));
  return apiRequest(`/actions/${enc(actionId)}/undo`, { method: "POST" }, fetchFn);
}

function undoAll(fetchFn) {
  return apiRequest("/undo-all", { method: "POST" }, fetchFn);
}

function setMode(mode, fetchFn) {
  if (!MODES.includes(mode)) {
    return Promise.reject(new Error(`Unknown mode ${JSON.stringify(mode)}; use off, notify or auto`));
  }
  return apiRequest("/mode", { method: "POST", body: { mode } }, fetchFn);
}

function quarantineAlert(alertId, fetchFn) {
  if (!alertId) return Promise.reject(new Error("No alert id"));
  return apiRequest(`/alerts/${enc(alertId)}/quarantine`, { method: "POST" }, fetchFn);
}

function exportEvidence(alertId, fetchFn) {
  if (!alertId) return Promise.reject(new Error("No alert id"));
  return apiRequest(`/alerts/${enc(alertId)}/evidence`, {}, fetchFn);
}

/** A short, user-facing message for an API failure. */
function errorMessage(err) {
  if (!err) return "Something went wrong.";
  if (err instanceof ApiError || err.name === "ApiError") {
    const why = err.detail ? ` ${err.detail}` : "";
    switch (err.status) {
      case 0: return err.detail;
      case 400: return `Not allowed:${why}`;
      case 404: return `Not found:${why}`;
      case 409: return `Can't do that right now:${why}`;
      case 422: return `Invalid request:${why}`;
      case 502: return `The Windows Firewall change failed; nothing was changed.${why}`;
      default: return `Error ${err.status}:${why}`;
    }
  }
  return err.message || String(err);
}

/** Reconnect delay for the n-th failed attempt (0-based): 1 s, 2 s, 4 s ... capped at 30 s. */
function nextBackoff(attempt) {
  const n = Math.max(0, Number(attempt) || 0);
  return Math.min(BACKOFF_BASE_MS * 2 ** n, BACKOFF_MAX_MS);
}

/* ---------------------------------------------------------------- rendering */

function severityClass(sev) {
  return SEVERITIES.includes(sev) ? `sev-${sev}` : "sev-low";
}

function actionLabel(action) {
  if (!action) return "";
  const target = action.target || "";
  const name = target.split(/[\\/]/).pop();
  switch (action.kind) {
    case "quarantine_app": return `quarantine of ${name}`;
    case "block_ip": return `block of ${target}`;
    case "kill_process": return `stop of ${target}`;
    default: return action.kind || "action";
  }
}

/** One Undo button (or an "undone" chip) per action id of an alert. */
function renderActionButtons(alert, actionsById) {
  const known = actionsById || {};
  return (alert.action_ids || [])
    .map((id) => {
      const action = known[id];
      const label = action ? actionLabel(action) : `action ${shortId(id)}`;
      if (action && action.undone) {
        return `<span class="chip chip-muted">Undone: ${escapeHtml(label)}</span>`;
      }
      return `<button class="btn btn-secondary" data-op="undo" data-id="${escapeHtml(id)}">`
        + `Undo ${escapeHtml(label)}</button>`;
    })
    .join("");
}

function renderSignals(signals) {
  const items = (signals || []).flatMap((s) => {
    const mitre = s.mitre ? ` <span class="mitre">${escapeHtml(s.mitre)}</span>` : "";
    const reasons = (s.reasons && s.reasons.length) ? s.reasons : [s.target];
    return reasons.map((r) => `<li><span class="detector">${escapeHtml(s.detector)}</span> `
      + `${escapeHtml(r)}${mitre}</li>`);
  });
  if (!items.length) return "";
  return `<details class="signals"><summary>Evidence (${items.length})</summary>`
    + `<ul>${items.join("")}</ul></details>`;
}

/** An Alert (as JSON from GET /alerts or WS /ws) as an HTML card. All text is escaped. */
function renderAlertCard(alert, actionsById) {
  const a = alert || {};
  const id = escapeHtml(a.id);
  const sev = SEVERITIES.includes(a.severity) ? a.severity : "low";
  const risk = Math.round((Number(a.risk) || 0) * 100);
  const canQuarantine = Boolean(a.exe_path);
  const quarantineTitle = canQuarantine ? "Block this app's network access"
    : "The program's location is unknown, so it can't be quarantined";
  return `<article class="card alert-card ${severityClass(sev)}" data-alert-id="${id}">
  <header class="alert-head">
    <span class="badge ${severityClass(sev)}">${escapeHtml(sev)}</span>
    <h3 class="alert-title">${escapeHtml(a.title || "Alert")}</h3>
    <span class="alert-meta">${escapeHtml(formatTime(a.ts_ms))}</span>
  </header>
  <div class="alert-proc">
    <span class="proc-name">${escapeHtml(a.process)}</span>
    <span class="proc-path">${escapeHtml(a.exe_path || "location unknown")}</span>
    <span class="risk">risk ${risk}%</span>
  </div>
  <section class="alert-section what-happened">
    <h4>What happened</h4>
    <p>${escapeHtml(a.what_happened)}</p>
  </section>
  <section class="alert-section what-we-did">
    <h4>What we did</h4>
    <p>${escapeHtml(a.what_we_did)}</p>
  </section>
  <section class="alert-section what-you-should-do">
    <h4>What you should do</h4>
    <p>${escapeHtml(a.what_you_should_do)}</p>
  </section>
  ${renderSignals(a.signals)}
  <footer class="alert-actions">
    ${renderActionButtons(a, actionsById)}
    <button class="btn btn-danger" data-op="quarantine" data-id="${id}"${canQuarantine ? "" : " disabled"} title="${escapeHtml(quarantineTitle)}">Quarantine app</button>
    <button class="btn btn-secondary" data-op="evidence" data-id="${id}">Export evidence</button>
  </footer>
</article>`;
}

function renderAlertList(alerts, actionsById) {
  if (!alerts || !alerts.length) {
    return `<p class="empty">No alerts. MoCat hasn't seen anything suspicious.</p>`;
  }
  return alerts.map((a) => renderAlertCard(a, actionsById)).join("\n");
}

function appTotal(app) {
  return (Number(app.bytes_out) || 0) + (Number(app.bytes_in) || 0);
}

function renderAppsTable(apps) {
  if (!apps || !apps.length) {
    return `<p class="empty">No network traffic seen yet.</p>`;
  }
  const rows = apps.map((app) => {
    const dests = (app.destinations || []).slice(0, 3)
      .map((d) => `<span class="dest" title="${escapeHtml(d.ip)}">${escapeHtml(d.hostname || d.ip)}</span>`)
      .join("");
    const more = (app.destinations || []).length > 3
      ? `<span class="dest-more">+${app.destinations.length - 3}</span>` : "";
    return `<tr>
  <td><span class="proc-name">${escapeHtml(app.process)}</span>`
      + `<span class="proc-path">${escapeHtml(app.exe_path || "")}</span></td>
  <td class="num">${escapeHtml((app.pids || []).join(", "))}</td>
  <td class="num">${escapeHtml(app.flows)}</td>
  <td class="num">${escapeHtml(formatBytes(app.bytes_out))}</td>
  <td class="num">${escapeHtml(formatBytes(app.bytes_in))}</td>
  <td>${dests}${more}</td>
</tr>`;
  });
  return `<table class="table">
<thead><tr><th>App</th><th>PID</th><th>Connections</th><th>Sent</th><th>Received</th><th>Talking to</th></tr></thead>
<tbody>${rows.join("\n")}</tbody>
</table>`;
}

/** Dashboard tiles: a big headline alert count, then the smaller status tiles. */
function renderStatusTiles(status) {
  const s = status || {};
  const alerts = Number(s.alerts) || 0;
  const blocks = Number(s.active_actions) || 0;
  const note = alerts
    ? `<span class="tile-note bad">${escapeHtml(blocks)} active block${blocks === 1 ? "" : "s"}</span>`
    : `<span class="tile-note ok">All clear</span>`;
  const hero = `<div class="tile tile-hero"><span class="tile-label">Alerts</span>`
    + `<span class="tile-value">${escapeHtml(alerts)}</span>${note}</div>`;
  const tiles = [
    ["Protection", s.status === "running" ? "Running" : "Offline"],
    ["Mode", MODE_NAMES[s.mode] || "unknown"],
    ["Active blocks", blocks],
    ["Apps online", s.apps ?? 0],
  ];
  return hero + tiles.map(([label, value]) => `<div class="tile"><span class="tile-label">${escapeHtml(label)}</span>`
    + `<span class="tile-value">${escapeHtml(value)}</span></div>`).join("");
}

/** The side panel's Status rows: mode, protection, blocks, uptime. */
function renderSideStatus(status) {
  const s = status || {};
  const mode = MODES.includes(s.mode) ? s.mode : "unknown";
  const rows = [
    ["Mode", `<span class="pill pill-${escapeHtml(mode)}">${escapeHtml(MODE_NAMES[mode] || mode)}</span>`],
    ["Protection", escapeHtml(s.status === "running" ? "Running" : "Offline")],
    ["Active blocks", escapeHtml(s.active_actions ?? 0)],
    ["Uptime", escapeHtml(s.uptime_s ? formatDuration(s.uptime_s) : "—")],
  ];
  return rows.map(([label, value]) => `<div class="side-row"><span>${escapeHtml(label)}</span><span>${value}</span></div>`)
    .join("");
}

/* ---------------------------------------------------------------- state updates */

function createState() {
  return { status: null, alerts: [], actionsById: {}, apps: [], connected: false };
}

/** Insert or replace an alert by id; newest first. Returns a new array. */
function upsertAlert(alerts, alert) {
  const rest = (alerts || []).filter((a) => a.id !== alert.id);
  rest.push(alert);
  return rest.sort((x, y) => (Number(y.ts_ms) || 0) - (Number(x.ts_ms) || 0));
}

/** Fold one WS /ws flow summary into the GET /apps list (same shape). Returns a new array. */
function mergeFlow(apps, flow) {
  const list = (apps || []).map((a) => ({ ...a, destinations: [...(a.destinations || [])] }));
  const name = flow.process || "unknown";
  let app = list.find((a) => a.process === name);
  if (!app) {
    app = { process: name, pids: [], exe_path: null, bytes_out: 0, bytes_in: 0, flows: 0, destinations: [] };
    list.push(app);
  }
  if (Number(flow.pid) >= 0 && !(app.pids || []).includes(flow.pid)) {
    app.pids = [...(app.pids || []), flow.pid].sort((x, y) => x - y);
  }
  const out = Number(flow.bytes_out) || 0;
  const inn = Number(flow.bytes_in) || 0;
  app.bytes_out = (Number(app.bytes_out) || 0) + out;
  app.bytes_in = (Number(app.bytes_in) || 0) + inn;
  app.flows = (Number(app.flows) || 0) + 1;
  const outbound = flow.direction !== "inbound";
  const remote = outbound ? flow.dst_ip : flow.src_ip;
  const i = app.destinations.findIndex((d) => d.ip === remote);
  const prev = i >= 0 ? app.destinations[i] : {
    ip: remote, hostname: null, ports: [], direction: flow.direction || "outbound", bytes_out: 0, bytes_in: 0, flows: 0,
  };
  const ports = [...(prev.ports || [])];
  if (outbound && flow.dst_port !== undefined && !ports.includes(flow.dst_port)) ports.push(flow.dst_port);
  const dest = {
    ...prev,
    hostname: flow.hostname || prev.hostname,
    ports: ports.sort((x, y) => x - y),
    bytes_out: prev.bytes_out + out,
    bytes_in: prev.bytes_in + inn,
    flows: prev.flows + 1,
  };
  if (i >= 0) app.destinations[i] = dest; else app.destinations.push(dest);
  app.destinations.sort((x, y) => appTotal(y) - appTotal(x));
  return list.sort((x, y) => appTotal(y) - appTotal(x));
}

/** Apply one /ws message to the state; returns which screen parts changed. */
function applyWsMessage(state, msg) {
  if (!msg || typeof msg !== "object") return [];
  switch (msg.type) {
    case "alert":
      state.alerts = upsertAlert(state.alerts, msg);
      return ["alerts", "home"];
    case "action":
      state.actionsById = { ...state.actionsById, [msg.id]: msg };
      return ["alerts", "home"];
    case "flow":
      state.apps = mergeFlow(state.apps, msg);
      return ["apps"];
    default:
      return [];
  }
}

/* ---------------------------------------------------------------- browser wiring */

function startUi(doc, win) {
  const state = createState();
  const $ = (sel) => doc.querySelector(sel);
  let noticeTimer = null;

  function notice(text, kind) {
    const el = $("#notice");
    el.textContent = text;
    el.className = `notice notice-${kind || "info"}`;
    el.hidden = false;
    if (noticeTimer) win.clearTimeout(noticeTimer);
    noticeTimer = win.setTimeout(() => { el.hidden = true; }, kind === "error" ? 10000 : 5000);
  }

  function showError(err) {
    notice(errorMessage(err), "error");
  }

  function render(parts) {
    const want = new Set(parts);
    if (want.has("home")) {
      $("#status-tiles").innerHTML = renderStatusTiles(state.status);
      const open = state.alerts.filter((a) => a.severity === "high" || a.severity === "critical");
      const shield = $("#shield");
      shield.className = `shield ${!state.connected ? "shield-off" : open.length ? "shield-red" : state.alerts.length ? "shield-yellow" : "shield-green"}`;
      $("#home-alerts").innerHTML = renderAlertList(state.alerts.slice(0, 3), state.actionsById);
      $("#nav-alert-count").textContent = state.alerts.length ? String(state.alerts.length) : "";
      $("#side-status").innerHTML = renderSideStatus(state.status);
    }
    if (want.has("alerts")) {
      $("#alert-list").innerHTML = renderAlertList(state.alerts, state.actionsById);
    }
    if (want.has("apps")) {
      $("#apps-table").innerHTML = renderAppsTable(state.apps);
    }
    if (want.has("settings")) {
      const mode = state.status && state.status.mode;
      doc.querySelectorAll("input[name=mode]").forEach((input) => { input.checked = input.value === mode; });
    }
  }

  function setConnected(ok) {
    state.connected = ok;
    const el = $("#conn");
    el.textContent = ok ? "Connected to agent" : "Agent offline — reconnecting…";
    el.className = `conn ${ok ? "conn-ok" : "conn-off"}`;
    render(["home"]);
  }

  async function refreshStatus() {
    try {
      state.status = await getStatus();
      render(["home", "settings"]);
    } catch (err) {
      state.status = null;
      render(["home"]);
    }
  }

  async function refreshApps() {
    try {
      const data = await getApps();
      state.apps = data.apps || [];
      render(["apps"]);
    } catch (err) { /* the connection banner already says the agent is offline */ }
  }

  async function refreshAlerts() {
    try {
      const data = await getAlerts(100);
      for (const a of data.alerts || []) state.alerts = upsertAlert(state.alerts, a);
      render(["alerts", "home"]);
    } catch (err) { /* idem */ }
  }

  function refreshAll() {
    refreshStatus();
    refreshApps();
    refreshAlerts();
  }

  function showScreen(name) {
    doc.querySelectorAll(".screen").forEach((s) => { s.hidden = s.id !== `screen-${name}`; });
    doc.querySelectorAll(".nav-item").forEach((b) => b.classList.toggle("active", b.dataset.screen === name));
    if (name === "apps") refreshApps();
    if (name === "settings") refreshStatus();
  }

  async function onAlertButton(ev) {
    const btn = ev.target.closest("button[data-op]");
    if (!btn || btn.disabled) return;
    const id = btn.dataset.id;
    btn.disabled = true;
    try {
      if (btn.dataset.op === "undo") {
        const res = await undoAction(id);
        applyWsMessage(state, res.action);
        applyWsMessage(state, res.undo);
        notice("Undone. The firewall rules were removed.", "ok");
      } else if (btn.dataset.op === "quarantine") {
        if (!win.confirm("Block all network access for this app? You can undo this later.")) return;
        const res = await quarantineAlert(id);
        applyWsMessage(state, res.action);
        applyWsMessage(state, res.alert);
        notice("The app is quarantined: it can no longer use the network.", "ok");
      } else if (btn.dataset.op === "evidence") {
        const res = await exportEvidence(id);
        const where = res && (res.path || res.file);
        notice(where ? `Evidence saved to ${where}` : "Evidence exported.", "ok");
      }
      render(["alerts", "home"]);
      refreshStatus();
    } catch (err) {
      showError(err);
    } finally {
      btn.disabled = false;
      render(["alerts", "home"]);
    }
  }

  async function onModeChange(ev) {
    const mode = ev.target.value;
    try {
      const res = await setMode(mode);
      if (state.status) state.status.mode = res.mode;
      notice(`Mode set to ${MODE_LABELS[res.mode] || res.mode}.`, "ok");
    } catch (err) {
      showError(err);
    }
    refreshStatus();
  }

  async function onUndoAll() {
    if (!win.confirm("Remove every firewall rule MoCat has added?")) return;
    try {
      const res = await undoAll();
      for (const a of Object.values(state.actionsById)) {
        if (a.kind !== "undo") state.actionsById[a.id] = { ...a, undone: true };
      }
      applyWsMessage(state, res.undo);
      notice(`Removed MoCat's firewall rules (${res.undone} action(s) undone).`, "ok");
    } catch (err) {
      showError(err);
    }
    render(["alerts", "home"]);
    refreshStatus();
  }

  function connect(attempt) {
    let ws;
    try {
      ws = new win.WebSocket(WS_URL);
    } catch (err) {
      win.setTimeout(() => connect(attempt + 1), nextBackoff(attempt));
      return;
    }
    let opened = false;
    ws.onopen = () => {
      opened = true;
      setConnected(true);
      refreshAll();
    };
    ws.onmessage = (ev) => {
      let msg;
      try { msg = JSON.parse(ev.data); } catch (err) { return; }
      const parts = applyWsMessage(state, msg);
      if (parts.length) render(parts);
      if (msg.type === "alert" || msg.type === "action") refreshStatus();
    };
    ws.onclose = () => {
      setConnected(false);
      const next = opened ? 0 : attempt + 1;
      win.setTimeout(() => connect(next), nextBackoff(opened ? 0 : attempt));
    };
    ws.onerror = () => { /* onclose follows */ };
  }

  doc.querySelectorAll(".nav-item").forEach((b) => b.addEventListener("click", () => showScreen(b.dataset.screen)));
  $("#alert-list").addEventListener("click", onAlertButton);
  $("#home-alerts").addEventListener("click", onAlertButton);
  doc.querySelectorAll("input[name=mode]").forEach((i) => i.addEventListener("change", onModeChange));
  $("#undo-all").addEventListener("click", onUndoAll);
  $("#view-all-alerts").addEventListener("click", () => showScreen("alerts"));

  showScreen("home");
  setConnected(false);
  refreshAll();
  connect(0);
  win.setInterval(refreshApps, APPS_RESYNC_MS);
  win.setInterval(refreshStatus, STATUS_REFRESH_MS);
}

if (typeof document !== "undefined" && typeof window !== "undefined") {
  document.addEventListener("DOMContentLoaded", () => startUi(document, window));
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    API_BASE, WS_URL, MODES, ApiError,
    escapeHtml, formatBytes, formatDuration, apiUrl, apiRequest, errorMessage, nextBackoff,
    getStatus, getApps, getAlerts, undoAction, undoAll, setMode, quarantineAlert, exportEvidence,
    renderAlertCard, renderAlertList, renderAppsTable, renderStatusTiles, renderSideStatus,
    createState, upsertAlert, mergeFlow, applyWsMessage,
  };
}
