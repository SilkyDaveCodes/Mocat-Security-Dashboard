// Node test harness for app/ui/app.js (run by tests/test_app_ui.py; also `node tests/js/test_app.mjs`).
// Exercises the pure helpers: alert card rendering + escaping, and the API client with a fake fetch.
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import path from "node:path";

const here = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);
const ui = require(path.join(here, "..", "..", "app", "ui", "app.js"));

const tests = [];
const test = (name, fn) => tests.push({ name, fn });

// A recording fake fetch: returns `status` + `body` and remembers every call.
function fakeFetch(status, body) {
  const calls = [];
  const fn = async (url, init) => {
    calls.push({ url, init });
    return { ok: status >= 200 && status < 300, status, json: async () => body };
  };
  fn.calls = calls;
  return fn;
}

const SAMPLE_ALERT = {
  type: "alert",
  id: "al-123",
  ts_ms: 1730000000000,
  severity: "high",
  process: "FreeGameCheats.exe",
  exe_path: "C:\\Users\\demo\\Downloads\\FreeGameCheats.exe",
  risk: 0.91,
  title: "FreeGameCheats.exe is behaving like malware",
  what_happened: "FreeGameCheats.exe checks in with 192.168.56.20 every 5.0 s.",
  what_we_did: "We blocked FreeGameCheats.exe from using the network.",
  what_you_should_do: "Delete FreeGameCheats.exe and run a Defender scan.",
  signals: [{ type: "signal", detector: "beacon", process: "FreeGameCheats.exe", pid: 42,
    target: "192.168.56.20", score: 0.9, reasons: ["checks in with 192.168.56.20 every 5.0 s (±0.2 s)"],
    mitre: "T1071.001", ts_ms: 1 }],
  action_ids: ["act-1"],
};

test("API base and WS URL are the local agent", () => {
  assert.equal(ui.API_BASE, "http://127.0.0.1:8765");
  assert.equal(ui.WS_URL, "ws://127.0.0.1:8765/ws");
});

test("renderAlertCard shows all three sections with the alert's text", () => {
  const html = ui.renderAlertCard(SAMPLE_ALERT, {});
  for (const heading of ["What happened", "What we did", "What you should do"]) {
    assert.ok(html.includes(`<h4>${heading}</h4>`), `missing heading ${heading}`);
  }
  // Each section holds its own text (escaped, so check the escaped forms where relevant).
  const section = (cls) => html.split(`class="alert-section ${cls}"`)[1].split("</section>")[0];
  assert.ok(section("what-happened").includes("checks in with 192.168.56.20 every 5.0 s."));
  assert.ok(section("what-we-did").includes("We blocked FreeGameCheats.exe from using the network."));
  assert.ok(section("what-you-should-do").includes("Delete FreeGameCheats.exe and run a Defender scan."));
  assert.ok(html.includes(ui.escapeHtml(SAMPLE_ALERT.title)));
  assert.ok(html.includes("sev-high"));
  // Undo per action id, plus Quarantine and Export evidence buttons for this alert.
  assert.ok(html.includes('data-op="undo" data-id="act-1"'));
  assert.ok(html.includes('data-op="quarantine" data-id="al-123"'));
  assert.ok(html.includes('data-op="evidence" data-id="al-123"'));
  assert.ok(html.includes("T1071.001"));
});

test("renderAlertCard labels known actions and marks undone ones", () => {
  const live = ui.renderAlertCard(SAMPLE_ALERT, {
    "act-1": { id: "act-1", kind: "quarantine_app", target: SAMPLE_ALERT.exe_path, undone: false },
  });
  assert.ok(live.includes("Undo quarantine of FreeGameCheats.exe"));
  const undone = ui.renderAlertCard(SAMPLE_ALERT, {
    "act-1": { id: "act-1", kind: "quarantine_app", target: SAMPLE_ALERT.exe_path, undone: true },
  });
  assert.ok(!undone.includes('data-op="undo"'));
  assert.ok(undone.includes("Undone: quarantine of FreeGameCheats.exe"));
});

test("renderAlertCard disables Quarantine when the exe path is unknown", () => {
  const html = ui.renderAlertCard({ ...SAMPLE_ALERT, exe_path: null }, {});
  assert.match(html, /data-op="quarantine" data-id="al-123" disabled/);
});

test("renderAlertCard escapes untrusted text (XSS)", () => {
  const evil = {
    ...SAMPLE_ALERT,
    id: 'x" onmouseover="alert(1)',
    process: "<script>alert(1)</script>.exe",
    title: "<img src=x onerror=alert(1)>",
    what_happened: "looked up <b>evil</b>.example & 'friends'",
    action_ids: ['a"><script>'],
    signals: [{ ...SAMPLE_ALERT.signals[0], reasons: ["<script>steal()</script>"], detector: "<i>dga</i>" }],
  };
  const html = ui.renderAlertCard(evil, {});
  assert.ok(!html.includes("<script>"), "raw <script> must not appear");
  assert.ok(!html.includes("<img"), "raw <img> must not appear");
  assert.ok(!html.includes("<b>evil"), "raw <b> must not appear");
  assert.ok(!html.includes("<i>dga"), "raw <i> must not appear");
  assert.ok(html.includes("&lt;script&gt;alert(1)&lt;/script&gt;.exe"));
  assert.ok(html.includes("&lt;img src=x onerror=alert(1)&gt;"));
  assert.ok(html.includes("looked up &lt;b&gt;evil&lt;/b&gt;.example &amp; &#39;friends&#39;"));
  assert.ok(html.includes('data-id="x&quot; onmouseover=&quot;alert(1)"'));
  assert.ok(!html.includes('" onmouseover="'));
  assert.equal(ui.escapeHtml(`<>&"'\``), "&lt;&gt;&amp;&quot;&#39;&#96;");
  assert.equal(ui.escapeHtml(null), "");
});

test("renderAppsTable escapes process names and hostnames", () => {
  const html = ui.renderAppsTable([{ process: "<script>x</script>", pids: [1], exe_path: null,
    bytes_out: 2048, bytes_in: 0, flows: 1,
    destinations: [{ ip: "1.2.3.4", hostname: "<b>h</b>", ports: [443] }] }]);
  assert.ok(!html.includes("<script>x"));
  assert.ok(!html.includes("<b>h"));
  assert.ok(html.includes("2.0 KB"));
});

test("undoAction POSTs to /actions/<id>/undo on the local agent", async () => {
  const body = { action: { id: "act-1", undone: true }, undo: { id: "u1", kind: "undo" } };
  const f = fakeFetch(200, body);
  const res = await ui.undoAction("act-1", f);
  assert.deepEqual(res, body);
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0].url, "http://127.0.0.1:8765/actions/act-1/undo");
  assert.equal(f.calls[0].init.method, "POST");
});

test("undoAction URL-encodes the id", async () => {
  const f = fakeFetch(200, {});
  await ui.undoAction("a/../b?c", f);
  assert.equal(f.calls[0].url, "http://127.0.0.1:8765/actions/a%2F..%2Fb%3Fc/undo");
});

test("setMode POSTs JSON {mode} to /mode", async () => {
  const f = fakeFetch(200, { mode: "auto" });
  const res = await ui.setMode("auto", f);
  assert.deepEqual(res, { mode: "auto" });
  assert.equal(f.calls.length, 1);
  const { url, init } = f.calls[0];
  assert.equal(url, "http://127.0.0.1:8765/mode");
  assert.equal(init.method, "POST");
  assert.equal(init.headers["Content-Type"], "application/json");
  assert.deepEqual(JSON.parse(init.body), { mode: "auto" });
});

test("setMode rejects an invalid mode without calling fetch", async () => {
  for (const bad of ["AUTO", "panic", "", undefined, null]) {
    const f = fakeFetch(200, {});
    await assert.rejects(ui.setMode(bad, f), /Unknown mode/);
    assert.equal(f.calls.length, 0);
  }
});

test("quarantine, evidence, status, apps, alerts and undo-all hit the right endpoints", async () => {
  const cases = [
    [(f) => ui.quarantineAlert("al-1", f), "POST", "/alerts/al-1/quarantine"],
    [(f) => ui.exportEvidence("al-1", f), "GET", "/alerts/al-1/evidence"],
    [(f) => ui.getStatus(f), "GET", "/status"],
    [(f) => ui.getApps(f), "GET", "/apps"],
    [(f) => ui.getAlerts(50, f), "GET", "/alerts?limit=50"],
    [(f) => ui.undoAll(f), "POST", "/undo-all"],
  ];
  for (const [call, method, p] of cases) {
    const f = fakeFetch(200, {});
    await call(f);
    assert.equal(f.calls[0].url, `http://127.0.0.1:8765${p}`);
    assert.equal(f.calls[0].init.method, method);
  }
});

test("API errors (404/409/502) become ApiError with the server's detail", async () => {
  for (const [status, detail, expect] of [
    [404, "No action with id 'x'", /Not found: No action with id 'x'/],
    [409, "Action a1 is already undone", /Can't do that right now: Action a1 is already undone/],
    [502, "Firewall undo failed: boom", /firewall change failed.*Firewall undo failed: boom/i],
  ]) {
    const f = fakeFetch(status, { detail });
    let caught = null;
    try { await ui.undoAction("x", f); } catch (err) { caught = err; }
    assert.ok(caught instanceof ui.ApiError, `status ${status} should throw ApiError`);
    assert.equal(caught.status, status);
    assert.match(ui.errorMessage(caught), expect);
  }
});

test("a network failure says the agent is not reachable", async () => {
  const f = async () => { throw new TypeError("Failed to fetch"); };
  await assert.rejects(ui.getStatus(f), (err) => err.status === 0 && /not reachable/.test(ui.errorMessage(err)));
});

test("WS messages update alerts, actions and apps", () => {
  const state = ui.createState();
  assert.deepEqual(ui.applyWsMessage(state, SAMPLE_ALERT), ["alerts", "home"]);
  assert.equal(state.alerts.length, 1);
  ui.applyWsMessage(state, { ...SAMPLE_ALERT, what_we_did: "updated" });
  assert.equal(state.alerts.length, 1, "same id replaces, not duplicates");
  assert.equal(state.alerts[0].what_we_did, "updated");
  ui.applyWsMessage(state, { type: "action", id: "act-1", kind: "block_ip", target: "1.2.3.4", undone: false });
  assert.equal(state.actionsById["act-1"].kind, "block_ip");
  const flow = { type: "flow", ts_ms: 1, process: "chrome.exe", pid: 7, src_ip: "10.0.0.2",
    dst_ip: "142.250.1.1", dst_port: 443, hostname: "google.com", app_proto: "TLS",
    bytes_out: 100, bytes_in: 900, direction: "outbound" };
  assert.deepEqual(ui.applyWsMessage(state, flow), ["apps"]);
  ui.applyWsMessage(state, { ...flow, bytes_out: 1, bytes_in: 1 });
  assert.equal(state.apps.length, 1);
  const app = state.apps[0];
  assert.equal(app.process, "chrome.exe");
  assert.equal(app.flows, 2);
  assert.equal(app.bytes_out, 101);
  assert.equal(app.bytes_in, 901);
  assert.deepEqual(app.pids, [7]);
  assert.equal(app.destinations[0].hostname, "google.com");
  assert.deepEqual(app.destinations[0].ports, [443]);
  assert.deepEqual(ui.applyWsMessage(state, { type: "signal" }), []);
});

test("reconnect backoff grows and is capped", () => {
  assert.equal(ui.nextBackoff(0), 1000);
  assert.equal(ui.nextBackoff(1), 2000);
  assert.equal(ui.nextBackoff(3), 8000);
  assert.equal(ui.nextBackoff(20), 30000);
});

test("dashboard tiles lead with a big alert count and say when all is clear", () => {
  const busy = ui.renderStatusTiles({ status: "running", mode: "auto", alerts: 7, active_actions: 1, apps: 4 });
  const hero = busy.match(/<div class="tile tile-hero">(.*?)<\/div>/s);
  assert.ok(hero, "the first tile is the headline tile");
  assert.match(hero[1], /<span class="tile-label">Alerts<\/span><span class="tile-value">7<\/span>/);
  assert.match(hero[1], /1 active block</);
  assert.equal((busy.match(/class="tile tile-hero"/g) || []).length, 1);
  assert.match(busy, /Running/);
  assert.match(busy, /Apps online<\/span><span class="tile-value">4</);
  const quiet = ui.renderStatusTiles({ status: "running", mode: "notify", alerts: 0, active_actions: 0 });
  assert.match(quiet, /tile-note ok">All clear</);
  assert.match(ui.renderStatusTiles(null), /tile-value">0</);  // offline: no status yet
});

test("side status shows the mode as a pill and escapes unknown values", () => {
  const html = ui.renderSideStatus({ status: "running", mode: "auto", active_actions: 2, uptime_s: 125 });
  assert.match(html, /<span class="pill pill-auto">Auto-protect<\/span>/);
  assert.match(html, /Active blocks<\/span><span>2</);
  assert.match(html, /Uptime<\/span><span>2m 5s</);
  const odd = ui.renderSideStatus({ mode: "<img onerror=x>", active_actions: "<b>" });
  assert.match(odd, /pill-unknown">unknown</);
  assert.ok(!odd.includes("<b>") && !odd.includes("<img"), "status values are escaped");
  assert.match(odd, /Protection<\/span><span>Offline</);
});

// Optional filter: `node test_app.mjs <substring>` runs only tests whose name contains it.
const filter = process.argv[2] || "";
const selected = tests.filter((t) => t.name.includes(filter));
if (!selected.length) {
  console.log(`no test matches ${JSON.stringify(filter)}`);
  process.exit(2);
}
let failed = 0;
for (const { name, fn } of selected) {
  try {
    await fn();
    console.log(`ok - ${name}`);
  } catch (err) {
    failed += 1;
    console.log(`not ok - ${name}\n${err && err.stack}`);
  }
}
console.log(`${selected.length - failed}/${selected.length} passed`);
process.exit(failed ? 1 : 0);
