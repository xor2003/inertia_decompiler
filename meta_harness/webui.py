from __future__ import annotations

import html
import json
import re
import subprocess
import threading
import webbrowser
from collections import defaultdict
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .config import LlmConfig, RuntimeConfig
from .runtime_records import load_jsonl, parse_usage_metrics, read_json, summarize_session_rows, write_json


HTML_PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Meta Harness</title>
  <style>
    :root {
      --bg: #0e141b;
      --panel: #15202b;
      --panel-alt: #1b2a36;
      --text: #ecf3f8;
      --muted: #9db0bf;
      --accent: #5cc8ff;
      --ok: #64d98b;
      --warn: #ffd166;
      --bad: #ff7b72;
      --border: #284152;
      --mono: "Iosevka Term", "JetBrains Mono", "Fira Code", monospace;
      --sans: "IBM Plex Sans", "Segoe UI", sans-serif;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: var(--sans);
      color: var(--text);
      background:
        radial-gradient(circle at top right, rgba(92, 200, 255, 0.18), transparent 22rem),
        radial-gradient(circle at bottom left, rgba(100, 217, 139, 0.14), transparent 20rem),
        var(--bg);
    }
    .wrap {
      padding: 20px;
      display: grid;
      gap: 16px;
    }
    .hero {
      display: flex;
      justify-content: space-between;
      gap: 16px;
      align-items: end;
      flex-wrap: wrap;
    }
    h1 {
      margin: 0;
      font-size: 28px;
      letter-spacing: 0.02em;
    }
    .sub {
      color: var(--muted);
      margin-top: 6px;
    }
    .grid {
      display: grid;
      gap: 16px;
      grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    }
    .panel {
      background: linear-gradient(180deg, rgba(255,255,255,0.02), rgba(255,255,255,0.01));
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 16px;
      box-shadow: 0 14px 40px rgba(0, 0, 0, 0.25);
    }
    .panel h2 {
      margin: 0 0 12px;
      font-size: 16px;
    }
    .stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
      gap: 10px;
    }
    .stat {
      background: var(--panel-alt);
      border-radius: 12px;
      padding: 12px;
      border: 1px solid rgba(255,255,255,0.04);
    }
    .stat .label {
      color: var(--muted);
      font-size: 12px;
      margin-bottom: 6px;
    }
    .stat .value {
      font-size: 20px;
      font-weight: 700;
    }
    .badge {
      display: inline-flex;
      align-items: center;
      padding: 6px 10px;
      border-radius: 999px;
      font-size: 12px;
      background: rgba(92, 200, 255, 0.16);
      color: var(--text);
      border: 1px solid rgba(92, 200, 255, 0.22);
    }
    .steps {
      display: grid;
      gap: 10px;
    }
    .role-grid {
      display: grid;
      gap: 10px;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
    }
    .step {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      padding: 10px 12px;
      border-radius: 12px;
      background: var(--panel-alt);
      border: 1px solid rgba(255,255,255,0.04);
    }
    .step .meta {
      color: var(--muted);
      font-size: 12px;
      margin-top: 4px;
    }
    .status-running, .status-resources-ok, .status-ready, .status-fresh, .status-resumed { color: var(--accent); }
    .status-done, .status-done-with-failures { color: var(--ok); }
    .status-failed, .status-stalled, .status-terminated, .status-interrupted { color: var(--bad); }
    .status-retrying-after-timeout, .status-retrying-after-error, .status-restarting-fresh-context { color: var(--warn); }
    pre.console {
      margin: 0;
      white-space: pre-wrap;
      font-family: var(--mono);
      font-size: 12px;
      line-height: 1.45;
      max-height: 460px;
      overflow: auto;
      background: #091017;
      border-radius: 12px;
      padding: 14px;
      border: 1px solid rgba(255,255,255,0.04);
    }
    .chat-log {
      display: grid;
      gap: 10px;
      max-height: 360px;
      overflow: auto;
      padding-right: 4px;
    }
    .msg {
      border-radius: 12px;
      padding: 10px 12px;
      background: var(--panel-alt);
      border: 1px solid rgba(255,255,255,0.04);
    }
    .msg.operator { border-left: 3px solid var(--accent); }
    .msg.system { border-left: 3px solid var(--warn); }
    .msg .head {
      display: flex;
      justify-content: space-between;
      gap: 8px;
      color: var(--muted);
      font-size: 12px;
      margin-bottom: 6px;
    }
    .chat-form {
      display: grid;
      gap: 10px;
      margin-top: 12px;
    }
    textarea {
      width: 100%;
      min-height: 110px;
      resize: vertical;
      border-radius: 12px;
      border: 1px solid var(--border);
      background: #091017;
      color: var(--text);
      padding: 12px;
      font: inherit;
    }
    button {
      justify-self: start;
      border: 0;
      border-radius: 999px;
      padding: 10px 16px;
      color: #07131b;
      background: linear-gradient(90deg, #64d98b, #5cc8ff);
      font-weight: 700;
      cursor: pointer;
    }
    .hint {
      color: var(--muted);
      font-size: 12px;
    }
    .error-banner {
      display: none;
      padding: 12px 14px;
      border-radius: 12px;
      border: 1px solid rgba(255, 123, 114, 0.35);
      background: rgba(255, 123, 114, 0.12);
      color: var(--text);
    }
    .error-banner.show {
      display: block;
    }
    @media (max-width: 720px) {
      .wrap { padding: 12px; }
      h1 { font-size: 22px; }
    }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="hero">
      <div>
        <h1>Meta Harness Control Room</h1>
        <div class="sub" id="summary">__SUMMARY__</div>
      </div>
      <div class="badge __BADGE_CLASS__" id="badge">__BADGE_TEXT__</div>
    </div>

    <div class="error-banner __ERROR_CLASS__" id="error-banner">__ERROR_TEXT__</div>

    <div class="panel">
      <h2>Statistics</h2>
      <div class="stats" id="stats">__STATS_HTML__</div>
    </div>

    <div class="grid">
      <div class="panel">
        <h2>Current Progress</h2>
        <div class="steps" id="steps">__STEPS_HTML__</div>
      </div>
      <div class="panel">
        <h2>Active Processes</h2>
        <div class="steps" id="processes">__PROCESSES_HTML__</div>
      </div>
    </div>

    <div class="grid">
      <div class="panel">
        <h2>Task Packet</h2>
        <div class="steps" id="task-packet">__TASK_PACKET_HTML__</div>
      </div>
      <div class="panel">
        <h2>Policy And Green</h2>
        <div class="steps" id="policy">__POLICY_HTML__</div>
      </div>
    </div>

    <div class="grid">
      <div class="panel">
        <h2>Resources</h2>
        <div class="steps" id="resources">__RESOURCES_HTML__</div>
      </div>
      <div class="panel">
        <h2>Usage And Spend</h2>
        <div class="steps" id="usage">__USAGE_HTML__</div>
      </div>
    </div>

    <div class="grid">
      <div class="panel">
        <h2>Preflight</h2>
        <div class="steps" id="preflight">__PREFLIGHT_HTML__</div>
      </div>
      <div class="panel">
        <h2>Session Ledger</h2>
        <div class="steps" id="sessions">__SESSIONS_HTML__</div>
      </div>
    </div>

    <div class="panel">
      <h2>Role Activity</h2>
      <div class="role-grid" id="roles">__ROLES_HTML__</div>
    </div>

    <div class="panel">
      <h2>Recent Events</h2>
      <div class="steps" id="history">__HISTORY_HTML__</div>
    </div>

    <div class="panel">
      <h2>Operator Action History</h2>
      <div class="steps" id="actions">__ACTIONS_HTML__</div>
    </div>

    <div class="grid">
      <div class="panel">
        <h2>Blockers And Recovery</h2>
        <div class="steps" id="blockers">__BLOCKERS_HTML__</div>
      </div>
      <div class="panel">
        <h2>Autonomy And Maintenance</h2>
        <div class="steps" id="autonomy">__AUTONOMY_HTML__</div>
      </div>
    </div>

    <div class="panel">
      <h2>Operator Actions</h2>
      <div class="hint">Bounded control actions for the live harness. These do not guess; they set explicit runtime intent.</div>
      <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:12px">
        <button type="button" onclick="sendAction('pause')">Pause</button>
        <button type="button" onclick="sendAction('resume')">Resume</button>
        <button type="button" onclick="sendAction('force-planner-rewrite')">Force Planner Rewrite</button>
        <button type="button" onclick="sendAction('force-stronger-worker')">Force Stronger Worker</button>
        <button type="button" onclick="sendAction('run-maintenance')">Run Maintenance</button>
      </div>
    </div>

    <div class="grid">
      <div class="panel">
        <h2>Live Console</h2>
        <div class="hint" id="console-meta">__CONSOLE_META__</div>
        <pre class="console" id="console">__CONSOLE_TEXT__</pre>
      </div>
      <div class="panel">
        <h2>Operator Chat</h2>
        <div class="chat-log" id="chat">__CHAT_HTML__</div>
        <form class="chat-form" id="chat-form">
          <textarea id="message" placeholder="Send guidance to the next harness role..."></textarea>
          <button type="submit">Send To Harness</button>
          <div class="hint">Messages go straight into the harness operator comment queue and are archived in chat history.</div>
        </form>
      </div>
    </div>
  </div>
  <script>
    const pollMs = Math.max(500, Number("__POLL_MS__"));
    const bootstrapState = __BOOTSTRAP_STATE__;
    const fetchTimeoutMs = Math.max(3000, pollMs * 2);
    let lastSuccessfulFetchAt = Date.now();
    let pollPromise = null;
    let consolePollPromise = null;
    let autoReloadIssued = false;

    function prettyBytes(bytes) {
      if (bytes === null || bytes === undefined) return "-";
      const units = ["B", "KB", "MB", "GB"];
      let value = bytes;
      let unit = 0;
      while (value >= 1024 && unit < units.length - 1) {
        value /= 1024;
        unit += 1;
      }
      return `${value.toFixed(value >= 10 || unit === 0 ? 0 : 1)} ${units[unit]}`;
    }

    function statusClass(status) {
      return `status-${String(status || "unknown").replace(/[^a-z0-9]+/gi, "-").toLowerCase()}`;
    }

    function setError(message) {
      const node = document.getElementById("error-banner");
      if (!message) {
        node.textContent = "";
        node.className = "error-banner";
        return;
      }
      node.textContent = message;
      node.className = "error-banner show";
    }

    function renderStats(data) {
      const stats = [
        ["Cycle", data.current_cycle || "-"],
        ["Step", data.status.step || "-"],
        ["Status", data.status.status || "-"],
        ["Green", data.current_green_level || "-"],
        ["Last Log", prettyBytes(data.console.size_bytes)],
        ["Pending Msgs", data.pending_comments ? "yes" : "no"],
        ["Worker Logs", `${data.log_stats.worker.count} / ${prettyBytes(data.log_stats.worker.total_bytes)}`],
      ];
      document.getElementById("stats").innerHTML = stats.map(([label, value]) => `
        <div class="stat">
          <div class="label">${label}</div>
          <div class="value">${value}</div>
        </div>
      `).join("");
    }

    function renderSteps(state) {
      const steps = state.step_order.map((name) => {
        const entry = state.cycle_steps[name] || {};
        return `
          <div class="step">
            <div>
              <strong>${name}</strong>
              <div class="meta">${entry.extra || ""}</div>
            </div>
            <div class="${statusClass(entry.status)}">${entry.status || "pending"}</div>
          </div>
        `;
      }).join("");
      document.getElementById("steps").innerHTML = steps || '<div class="hint">No cycle data yet.</div>';
    }

    function renderTaskPacket(packet, status) {
      const rows = [
        ["Item", packet.item_id || "-", packet.objective || ""],
        ["Status", status || "-", ""],
        ["Targets", (packet.target_files || []).join(" ") || "-", (packet.target_refs || []).join(" ") || ""],
        ["Tests", (packet.acceptance_tests || []).join(" | ") || "-", ""],
        ["Done", (packet.done_conditions || []).join(" | ") || "-", ""],
      ];
      document.getElementById("task-packet").innerHTML = rows.map(([label, value, meta]) => `
        <div class="step">
          <div>
            <strong>${label}</strong>
            <div class="meta">${meta}</div>
          </div>
          <div>${value}</div>
        </div>
      `).join("");
    }

    function renderPolicy(policy, greenLevel) {
      const rows = [
        ["Green", greenLevel || "-", ""],
        ["Decision", policy.decision || "-", policy.reason || ""],
        ["Updated", policy.updated_at || "-", ""],
      ];
      document.getElementById("policy").innerHTML = rows.map(([label, value, meta]) => `
        <div class="step">
          <div>
            <strong>${label}</strong>
            <div class="meta">${meta}</div>
          </div>
          <div>${value}</div>
        </div>
      `).join("");
    }

    function renderProcesses(processes) {
      document.getElementById("processes").innerHTML = processes.length ? processes.map((proc) => `
        <div class="step">
          <div>
            <strong>${proc.command}</strong>
            <div class="meta">pid=${proc.pid} started=${proc.started_at}</div>
          </div>
          <div class="status-running">active</div>
        </div>
      `).join("") : '<div class="hint">No registered subprocesses.</div>';
    }

    function renderResources(resources) {
      const rows = [
        ["Free Disk", resources.free_disk_mb == null ? "-" : `${resources.free_disk_mb} MB`, resources.disk_note || ""],
        ["Free RAM", resources.free_ram_mb == null ? "unknown" : `${resources.free_ram_mb} MB`, resources.ram_note || ""],
        ["State Dir", resources.state_dir_mb == null ? "-" : `${resources.state_dir_mb} MB`, resources.state_note || ""],
        ["Active Procs", String(resources.active_process_count || 0), ""],
      ];
      document.getElementById("resources").innerHTML = rows.map(([label, value, meta]) => `
        <div class="step">
          <div>
            <strong>${label}</strong>
            <div class="meta">${meta}</div>
          </div>
          <div>${value}</div>
        </div>
      `).join("");
    }

    function renderUsage(usage) {
      if (!usage.available) {
        document.getElementById("usage").innerHTML = `
          <div class="step">
            <div>
              <strong>Unavailable</strong>
              <div class="meta">${usage.message || "No structured usage telemetry found yet."}</div>
            </div>
            <div class="status-retrying-after-timeout">n/a</div>
          </div>
        `;
        return;
      }
      const rows = [
        ["Prompt Tokens", usage.prompt_tokens ?? "-", `${usage.sources_scanned || 0} logs scanned`],
        ["Completion Tokens", usage.completion_tokens ?? "-", usage.cost_usd == null ? "" : "aggregated from structured telemetry"],
        ["Total Tokens", usage.total_tokens ?? "-", ""],
        ["Spend", usage.cost_usd == null ? "-" : `$${Number(usage.cost_usd).toFixed(4)}`, ""],
      ];
      document.getElementById("usage").innerHTML = rows.map(([label, value, meta]) => `
        <div class="step">
          <div>
            <strong>${label}</strong>
            <div class="meta">${meta}</div>
          </div>
          <div>${value}</div>
        </div>
      `).join("");
    }

    function renderPreflight(preflight) {
      const commands = Object.entries(preflight.commands || {}).map(([name, ok]) => `${name}:${ok ? "ok" : "missing"}`).join(" ");
      const providers = Object.entries(preflight.providers || {}).map(([name, ok]) => `${name}:${ok ? "ok" : "missing"}`).join(" ");
      const rows = [
        ["Ready", preflight.ready ? "yes" : "no", `updated ${preflight.updated_at || "-"}`],
        ["Python", preflight.python_ok ? "ok" : "missing", preflight.python_bin || ""],
        ["Commands", commands || "-", ""],
        ["Providers", providers || "-", ""],
        ["Resources", `disk=${preflight.free_disk_mb ?? "-"}MB ram=${preflight.free_ram_mb ?? "-"}MB state=${preflight.state_dir_mb ?? "-"}MB`, preflight.last_context || ""],
      ];
      document.getElementById("preflight").innerHTML = rows.map(([label, value, meta]) => `
        <div class="step">
          <div>
            <strong>${label}</strong>
            <div class="meta">${meta}</div>
          </div>
          <div>${value}</div>
        </div>
      `).join("");
    }

    function renderSessions(summary) {
      const rows = [
        ["Sessions", summary.total_sessions ?? 0, ""],
        ["Duration", `${summary.total_duration_secs ?? 0}s`, ""],
        ["Tokens", summary.total_tokens ?? "-", ""],
        ["Spend", summary.total_cost_usd == null ? "-" : `$${Number(summary.total_cost_usd).toFixed(4)}`, ""],
        ["By Role", Object.entries(summary.by_role || {}).map(([name, count]) => `${name}:${count}`).join(" ") || "-", ""],
      ];
      document.getElementById("sessions").innerHTML = rows.map(([label, value, meta]) => `
        <div class="step">
          <div>
            <strong>${label}</strong>
            <div class="meta">${meta}</div>
          </div>
          <div>${value}</div>
        </div>
      `).join("");
    }

    function renderRoles(roles) {
      document.getElementById("roles").innerHTML = roles.length ? roles.map((role) => `
        <div class="step">
          <div>
            <strong>${role.name}</strong>
            <div class="meta">${role.provider}/${role.model}</div>
            <div class="meta">log=${role.latest_log || "-"} size=${prettyBytes(role.latest_log_bytes)}</div>
            <div class="meta">${role.extra || ""}${role.remaining_steps ? ` remaining=${role.remaining_steps}` : ""}</div>
          </div>
          <div class="${statusClass(role.status)}">${role.status || "idle"}</div>
        </div>
      `).join("") : '<div class="hint">No role activity yet.</div>';
    }

    function renderHistory(history) {
      document.getElementById("history").innerHTML = history.length ? history.map((event) => `
        <div class="step">
          <div>
            <strong>${event.message || event.event || "event"}</strong>
            <div class="meta">${event.at || ""}</div>
            <div class="meta">${event.event || ""} ${event.status || ""} ${event.failure_class || ""}</div>
            <div class="meta">${event.detail_text || ""}</div>
          </div>
          <div class="${statusClass(event.status || "unknown")}">${event.status || "-"}</div>
        </div>
      `).join("") : '<div class="hint">No recent events yet.</div>';
    }

    function renderActions(actions) {
      document.getElementById("actions").innerHTML = actions.length ? actions.map((event) => `
        <div class="step">
          <div>
            <strong>${event.message || event.event || "action"}</strong>
            <div class="meta">${event.at || ""}</div>
            <div class="meta">${event.detail_text || ""}</div>
          </div>
          <div class="${statusClass(event.status || "unknown")}">${event.status || "-"}</div>
        </div>
      `).join("") : '<div class="hint">No operator actions recorded yet.</div>';
    }

    function renderBlockers(blockers) {
      document.getElementById("blockers").innerHTML = blockers.length ? blockers.map((row) => `
        <div class="step">
          <div>
            <strong>${row.title || "-"}</strong>
            <div class="meta">${row.meta || ""}</div>
          </div>
          <div class="${statusClass(row.status || "unknown")}">${row.status || "-"}</div>
        </div>
      `).join("") : '<div class="hint">No blockers or recovery activity recorded.</div>';
    }

    function renderAutonomy(autonomy) {
      const rows = [
        ["Closeout", autonomy.last_closeout_action || "-", autonomy.auto_commit_enabled ? "auto-commit enabled" : "auto-commit disabled"],
        ["Branch", autonomy.branch_name || "-", autonomy.branch_note || ""],
        ["Maintenance", autonomy.maintenance_updated_at || "-", autonomy.maintenance_note || ""],
        ["Compaction", autonomy.compaction_note || "-", ""],
        ["Recommendation", autonomy.top_recommendation || "-", ""],
      ];
      document.getElementById("autonomy").innerHTML = rows.map(([label, value, meta]) => `
        <div class="step">
          <div>
            <strong>${label}</strong>
            <div class="meta">${meta}</div>
          </div>
          <div>${value}</div>
        </div>
      `).join("");
    }

    function renderChat(chat) {
      const chatNode = document.getElementById("chat");
      chatNode.innerHTML = chat.length ? chat.map((msg) => `
        <div class="msg ${msg.role}">
          <div class="head">
            <span>${msg.role}</span>
            <span>${msg.at || ""}</span>
          </div>
          <div>${String(msg.message || "").replace(/</g, "&lt;").replace(/\n/g, "<br>")}</div>
        </div>
      `).join("") : '<div class="hint">No messages yet.</div>';
    }

    function renderState(data) {
      document.getElementById("summary").textContent =
        `${data.project_name} | updated ${data.status.updated_at || "-"} | ${data.status.extra || "idle"}`;
      const badge = document.getElementById("badge");
      badge.textContent = `${data.status.step || "-"} / ${data.status.status || "-"}`;
      badge.className = `badge ${statusClass(data.status.status)}`;
      renderStats(data);
      renderSteps(data);
      renderProcesses(data.child_processes || []);
      renderTaskPacket(data.current_task_packet || {}, data.current_task_packet_status || "");
      renderPolicy(data.last_policy_decision || {}, data.current_green_level || "");
      renderResources(data.resources || {});
      renderUsage(data.usage || {});
      renderPreflight(data.preflight || {});
      renderSessions(data.session_summary || {});
      renderRoles(data.roles || []);
      renderHistory(data.history || []);
      renderActions(data.actions || []);
      renderBlockers(data.blockers || []);
      renderAutonomy(data.autonomy || {});
      renderChat(data.chat || []);
      updateConsole(data.console || {});
    }

    function updateConsole(consoleData) {
      const node = document.getElementById("console");
      const wasNearBottom = (node.scrollHeight - node.scrollTop - node.clientHeight) < 40;
      node.textContent = consoleData.text || "";
      document.getElementById("console-meta").textContent =
        `${consoleData.path || "-"} | ${prettyBytes(consoleData.size_bytes)} | tailing live`;
      if (wasNearBottom) {
        node.scrollTop = node.scrollHeight;
      }
    }

    async function fetchState() {
      if (pollPromise) {
        return pollPromise;
      }
      const controller = new AbortController();
      const timeoutId = window.setTimeout(() => controller.abort(), fetchTimeoutMs);
      pollPromise = (async () => {
      try {
        const response = await fetch(`/api/state?ts=${Date.now()}`, {
          cache: "no-store",
          signal: controller.signal,
        });
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }
        const data = await response.json();
        renderState(data);
        setError("");
        lastSuccessfulFetchAt = Date.now();
        autoReloadIssued = false;
      } catch (error) {
        setError(`Live update failed: ${error.message}`);
        const staleForMs = Date.now() - lastSuccessfulFetchAt;
        if (!autoReloadIssued && staleForMs >= Math.max(10000, pollMs * 4)) {
          autoReloadIssued = true;
          window.location.reload();
        }
      } finally {
        window.clearTimeout(timeoutId);
        pollPromise = null;
      }
      })();
      return pollPromise;
    }

    async function fetchConsole() {
      if (consolePollPromise) {
        return consolePollPromise;
      }
      const controller = new AbortController();
      const timeoutId = window.setTimeout(() => controller.abort(), fetchTimeoutMs);
      consolePollPromise = (async () => {
      try {
        const response = await fetch(`/api/console?tail_bytes=65536&ts=${Date.now()}`, {
          cache: "no-store",
          signal: controller.signal,
        });
        if (!response.ok) {
          throw new Error(`HTTP ${response.status}`);
        }
        const data = await response.json();
        updateConsole(data);
        lastSuccessfulFetchAt = Date.now();
      } catch (_error) {
      } finally {
        window.clearTimeout(timeoutId);
        consolePollPromise = null;
      }
      })();
      return consolePollPromise;
    }

    async function pollLoop() {
      while (true) {
        await fetchState();
        await new Promise((resolve) => window.setTimeout(resolve, pollMs));
      }
    }

    async function consolePollLoop() {
      const consolePollMs = Math.min(pollMs, 1000);
      while (true) {
        await fetchConsole();
        await new Promise((resolve) => window.setTimeout(resolve, consolePollMs));
      }
    }

    async function sendMessage(message) {
      await fetch("/api/comment", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({message}),
      });
    }

    async function sendAction(action) {
      const response = await fetch("/api/action", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({action}),
      });
      const payload = await response.json();
      if (!response.ok || !payload.ok) {
        setError(`Action failed: ${payload.error || payload.message || response.status}`);
        return;
      }
      setError(`Action applied: ${payload.message || action}`);
      await fetchState();
      await fetchConsole();
    }

    document.getElementById("chat-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const box = document.getElementById("message");
      const message = box.value.trim();
      if (!message) return;
      await sendMessage(message);
      box.value = "";
      await fetchState();
    });

    renderState(bootstrapState);
    fetchState();
    fetchConsole();
    pollLoop();
    consolePollLoop();
    window.addEventListener("focus", () => { fetchState(); });
    document.addEventListener("visibilitychange", () => {
      if (!document.hidden) {
        fetchState();
        fetchConsole();
      }
    });
    window.addEventListener("pageshow", () => {
      fetchState();
      fetchConsole();
    });
  </script>
</body>
</html>
"""


def append_chat_entry(path: Path, role: str, message: str, *, at: str | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"role": role, "message": message, "at": at or datetime.now().astimezone().isoformat(timespec="seconds")}
    with path.open("a", encoding="utf-8") as fp:
        fp.write(json.dumps(payload, sort_keys=True) + "\n")


def _parse_kv_file(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    data: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" not in raw_line:
            continue
        key, value = raw_line.split("=", 1)
        data[key.strip()] = value.strip()
    return data


def _tail_text(path: Path, max_bytes: int = 64 * 1024) -> str:
    if not path.exists():
        return ""
    with path.open("rb") as fp:
        fp.seek(0, 2)
        size = fp.tell()
        fp.seek(max(0, size - max_bytes))
        return fp.read().decode("utf-8", errors="replace")


def _load_json(path: Path) -> dict[str, object] | list[object] | None:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _load_chat(path: Path, limit: int = 50) -> list[dict[str, str]]:
    if not path.exists():
        return []
    messages: list[dict[str, str]] = []
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:]:
        try:
            entry = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        if isinstance(entry, dict):
            messages.append(
                {
                    "role": str(entry.get("role", "system")),
                    "message": str(entry.get("message", "")),
                    "at": str(entry.get("at", "")),
                }
            )
    return messages


def _role_log_stats(log_dir: Path) -> dict[str, dict[str, int]]:
    stats: dict[str, dict[str, int]] = defaultdict(lambda: {"count": 0, "total_bytes": 0, "max_bytes": 0})
    for path in log_dir.glob("*.log"):
        role = path.stem.split("_", 2)[-1]
        size = path.stat().st_size
        stats[role]["count"] += 1
        stats[role]["total_bytes"] += size
        stats[role]["max_bytes"] = max(stats[role]["max_bytes"], size)
    for role in ("checker", "planner", "worker", "reviewer", "crash-reviewer"):
        stats.setdefault(role, {"count": 0, "total_bytes": 0, "max_bytes": 0})
    return dict(stats)


def _free_disk_mb(root_dir: Path) -> int | None:
    try:
        result = subprocess.run(["df", "-Pm", str(root_dir)], capture_output=True, text=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        return None
    lines = result.stdout.splitlines()
    if len(lines) < 2:
        return None
    try:
        return int(lines[1].split()[3])
    except (IndexError, ValueError):
        return None


def _free_ram_mb() -> int | None:
    try:
        for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
            if line.startswith("MemAvailable:"):
                return int(line.split()[1]) // 1024
    except OSError:
        return None
    return None


def _state_dir_mb(state_dir: Path) -> int | None:
    try:
        result = subprocess.run(["du", "-sm", str(state_dir)], capture_output=True, text=True, check=False)
    except OSError:
        return None
    if result.returncode != 0 or not result.stdout.strip():
        return None
    try:
        return int(result.stdout.split()[0])
    except (IndexError, ValueError):
        return None


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace").strip() if path.exists() else ""


def _remaining_steps_for_role(state_dir: Path, role: str) -> str:
    return _read_text(state_dir / f"{role}.remaining")


def _latest_log_for_role(state_dir: Path, role: str) -> Path | None:
    text = _read_text(state_dir / f"{role}.lastlog")
    return Path(text) if text else None


def _role_activity(
    cfg: RuntimeConfig,
    llm_cfg: LlmConfig,
    *,
    status: dict[str, str],
    cycle_steps: dict[str, object],
    log_stats: dict[str, dict[str, int]],
) -> list[dict[str, object]]:
    roles: list[dict[str, object]] = []
    role_to_model = {
        "checker": cfg.checker_model,
        "planner": cfg.planner_model,
        "worker": cfg.worker_model,
        "reviewer": cfg.reviewer_model,
        "crash-reviewer": cfg.crash_reviewer_model,
    }
    active_step = status.get("step", "")
    active_status = status.get("status", "")
    active_extra = status.get("extra", "")
    for role in ("checker", "planner", "worker", "reviewer", "crash-reviewer"):
        latest_log = _latest_log_for_role(cfg.state_dir, role)
        latest_log_bytes = 0
        if latest_log is not None and latest_log.exists():
            latest_log_bytes = latest_log.stat().st_size
        step_state = cycle_steps.get(role, {})
        role_status = "idle"
        role_extra = ""
        if isinstance(step_state, dict) and step_state:
            role_status = str(step_state.get("status", "idle"))
            role_extra = str(step_state.get("extra", ""))
        if role == active_step:
            role_status = active_status or role_status
            role_extra = active_extra or role_extra
        roles.append(
            {
                "name": role,
                "provider": llm_cfg.provider_for_key(role),
                "model": role_to_model[role],
                "status": role_status,
                "extra": role_extra,
                "remaining_steps": _remaining_steps_for_role(cfg.state_dir, role),
                "latest_log": latest_log.name if latest_log is not None else "",
                "latest_log_path": str(latest_log) if latest_log is not None else "",
                "latest_log_bytes": latest_log_bytes,
                "log_count": log_stats.get(role, {}).get("count", 0),
                "log_total_bytes": log_stats.get(role, {}).get("total_bytes", 0),
            }
        )
    return roles


def _usage_summary(log_dir: Path) -> dict[str, object]:
    prompt_tokens = 0
    completion_tokens = 0
    total_tokens = 0
    cost_usd = 0.0
    saw_usage = False
    sources_scanned = 0
    for path in sorted(log_dir.glob("*.log"))[-40:]:
        try:
            text = _tail_text(path, max_bytes=64 * 1024)
        except OSError:
            continue
        sources_scanned += 1
        usage = parse_usage_metrics(text)
        if usage.get("prompt_tokens") is not None:
            prompt_tokens += int(usage["prompt_tokens"])
            saw_usage = True
        if usage.get("completion_tokens") is not None:
            completion_tokens += int(usage["completion_tokens"])
            saw_usage = True
        if usage.get("total_tokens") is not None:
            total_tokens += int(usage["total_tokens"])
            saw_usage = True
        if usage.get("cost_usd") is not None:
            cost_usd += float(usage["cost_usd"])
            saw_usage = True
    if not saw_usage:
        return {
            "available": False,
            "message": "Provider logs do not currently include structured token or cost telemetry.",
            "sources_scanned": sources_scanned,
        }
    if total_tokens == 0:
        total_tokens = prompt_tokens + completion_tokens
    return {
        "available": True,
        "prompt_tokens": prompt_tokens or None,
        "completion_tokens": completion_tokens or None,
        "total_tokens": total_tokens or None,
        "cost_usd": round(cost_usd, 6) if cost_usd else None,
        "sources_scanned": sources_scanned,
    }


def _html_escape(value: object) -> str:
    return html.escape("" if value is None else str(value))


def _status_class(status: object) -> str:
    text = str(status or "unknown").lower()
    cleaned = re.sub(r"[^a-z0-9]+", "-", text).strip("-")
    return f"status-{cleaned or 'unknown'}"


def _pretty_bytes(bytes_value: object) -> str:
    if bytes_value is None:
        return "-"
    try:
        value = float(bytes_value)
    except (TypeError, ValueError):
        return "-"
    units = ["B", "KB", "MB", "GB"]
    unit = 0
    while value >= 1024 and unit < len(units) - 1:
        value /= 1024
        unit += 1
    if value >= 10 or unit == 0:
        return f"{value:.0f} {units[unit]}"
    return f"{value:.1f} {units[unit]}"


def _render_stat_cards(data: dict[str, object]) -> str:
    log_stats = data.get("log_stats", {})
    worker_stats = log_stats.get("worker", {}) if isinstance(log_stats, dict) else {}
    stats = [
        ("Cycle", data.get("current_cycle") or "-"),
        ("Step", data.get("status", {}).get("step", "-") if isinstance(data.get("status"), dict) else "-"),
        ("Status", data.get("status", {}).get("status", "-") if isinstance(data.get("status"), dict) else "-"),
        ("Green", data.get("current_green_level") or "-"),
        ("Last Log", _pretty_bytes(data.get("console", {}).get("size_bytes")) if isinstance(data.get("console"), dict) else "-"),
        ("Pending Msgs", "yes" if data.get("pending_comments") else "no"),
        ("Worker Logs", f"{worker_stats.get('count', 0)} / {_pretty_bytes(worker_stats.get('total_bytes'))}"),
    ]
    return "".join(
        f'<div class="stat"><div class="label">{_html_escape(label)}</div><div class="value">{_html_escape(value)}</div></div>'
        for label, value in stats
    )


def _render_task_packet_html(packet: dict[str, object], packet_status: str) -> str:
    rows = [
        ("Item", packet.get("item_id", "-"), packet.get("objective", "")),
        ("Status", packet_status or "-", ""),
        ("Targets", " ".join(packet.get("target_files", [])) if isinstance(packet.get("target_files"), list) else "-", " ".join(packet.get("target_refs", [])) if isinstance(packet.get("target_refs"), list) else ""),
        ("Tests", " | ".join(packet.get("acceptance_tests", [])) if isinstance(packet.get("acceptance_tests"), list) else "-", ""),
        ("Done", " | ".join(packet.get("done_conditions", [])) if isinstance(packet.get("done_conditions"), list) else "-", ""),
    ]
    return "".join(
        '<div class="step"><div><strong>'
        + _html_escape(label)
        + '</strong><div class="meta">'
        + _html_escape(meta)
        + '</div></div><div>'
        + _html_escape(value)
        + "</div></div>"
        for label, value, meta in rows
    )


def _render_policy_html(policy: dict[str, object], green_level: str) -> str:
    rows = [
        ("Green", green_level or "-", ""),
        ("Decision", policy.get("decision", "-"), policy.get("reason", "")),
        ("Updated", policy.get("updated_at", "-"), ""),
    ]
    return "".join(
        '<div class="step"><div><strong>'
        + _html_escape(label)
        + '</strong><div class="meta">'
        + _html_escape(meta)
        + '</div></div><div>'
        + _html_escape(value)
        + "</div></div>"
        for label, value, meta in rows
    )


def _render_steps_html(state: dict[str, object]) -> str:
    step_order = state.get("step_order", [])
    cycle_steps = state.get("cycle_steps", {})
    if not isinstance(step_order, list) or not step_order:
        return '<div class="hint">No cycle data yet.</div>'
    items = []
    for name in step_order:
        entry = cycle_steps.get(name, {}) if isinstance(cycle_steps, dict) else {}
        status = entry.get("status", "pending") if isinstance(entry, dict) else "pending"
        extra = entry.get("extra", "") if isinstance(entry, dict) else ""
        items.append(
            '<div class="step"><div><strong>'
            + _html_escape(name)
            + '</strong><div class="meta">'
            + _html_escape(extra)
            + '</div></div><div class="'
            + _status_class(status)
            + '">'
            + _html_escape(status)
            + "</div></div>"
        )
    return "".join(items)


def _render_processes_html(processes: object) -> str:
    if not isinstance(processes, list) or not processes:
        return '<div class="hint">No registered subprocesses.</div>'
    items = []
    for proc in processes:
        if not isinstance(proc, dict):
            continue
        items.append(
            '<div class="step"><div><strong>'
            + _html_escape(proc.get("command", ""))
            + '</strong><div class="meta">pid='
            + _html_escape(proc.get("pid", ""))
            + " started="
            + _html_escape(proc.get("started_at", ""))
            + '</div></div><div class="status-running">active</div></div>'
        )
    return "".join(items) or '<div class="hint">No registered subprocesses.</div>'


def _render_resources_html(resources: dict[str, object]) -> str:
    rows = [
        ("Free Disk", f"{resources.get('free_disk_mb')} MB" if resources.get("free_disk_mb") is not None else "-", resources.get("disk_note", "")),
        ("Free RAM", f"{resources.get('free_ram_mb')} MB" if resources.get("free_ram_mb") is not None else "unknown", resources.get("ram_note", "")),
        ("State Dir", f"{resources.get('state_dir_mb')} MB" if resources.get("state_dir_mb") is not None else "-", resources.get("state_note", "")),
        ("Active Procs", resources.get("active_process_count", 0), ""),
    ]
    return "".join(
        '<div class="step"><div><strong>'
        + _html_escape(label)
        + '</strong><div class="meta">'
        + _html_escape(meta)
        + '</div></div><div>'
        + _html_escape(value)
        + "</div></div>"
        for label, value, meta in rows
    )


def _render_usage_html(usage: dict[str, object]) -> str:
    if not usage.get("available"):
        return (
            '<div class="step"><div><strong>Unavailable</strong><div class="meta">'
            + _html_escape(usage.get("message", "No structured usage telemetry found yet."))
            + '</div></div><div class="status-retrying-after-timeout">n/a</div></div>'
        )
    rows = [
        ("Prompt Tokens", usage.get("prompt_tokens", "-"), f"{usage.get('sources_scanned', 0)} logs scanned"),
        ("Completion Tokens", usage.get("completion_tokens", "-"), "aggregated from structured telemetry" if usage.get("cost_usd") is not None else ""),
        ("Total Tokens", usage.get("total_tokens", "-"), ""),
        ("Spend", f"${float(usage.get('cost_usd')):.4f}" if usage.get("cost_usd") is not None else "-", ""),
    ]
    return "".join(
        '<div class="step"><div><strong>'
        + _html_escape(label)
        + '</strong><div class="meta">'
        + _html_escape(meta)
        + '</div></div><div>'
        + _html_escape(value)
        + "</div></div>"
        for label, value, meta in rows
    )


def _render_preflight_html(preflight: dict[str, object]) -> str:
    commands = preflight.get("commands", {})
    providers = preflight.get("providers", {})
    command_text = " ".join(
        f"{name}:{'ok' if ok else 'missing'}" for name, ok in commands.items()
    ) if isinstance(commands, dict) else "-"
    provider_text = " ".join(
        f"{name}:{'ok' if ok else 'missing'}" for name, ok in providers.items()
    ) if isinstance(providers, dict) else "-"
    rows = [
        ("Ready", "yes" if preflight.get("ready") else "no", f"updated {preflight.get('updated_at', '-') or '-'}"),
        ("Python", "ok" if preflight.get("python_ok") else "missing", preflight.get("python_bin", "")),
        ("Commands", command_text or "-", ""),
        ("Providers", provider_text or "-", ""),
        (
            "Resources",
            f"disk={preflight.get('free_disk_mb', '-')}MB ram={preflight.get('free_ram_mb', '-')}MB state={preflight.get('state_dir_mb', '-')}MB",
            preflight.get("last_context", ""),
        ),
    ]
    return "".join(
        '<div class="step"><div><strong>'
        + _html_escape(label)
        + '</strong><div class="meta">'
        + _html_escape(meta)
        + '</div></div><div>'
        + _html_escape(value)
        + "</div></div>"
        for label, value, meta in rows
    )


def _render_sessions_html(summary: dict[str, object]) -> str:
    by_role = summary.get("by_role", {})
    by_role_text = " ".join(f"{name}:{count}" for name, count in by_role.items()) if isinstance(by_role, dict) else "-"
    rows = [
        ("Sessions", summary.get("total_sessions", 0), ""),
        ("Duration", f"{summary.get('total_duration_secs', 0)}s", ""),
        ("Tokens", summary.get("total_tokens", "-"), ""),
        ("Spend", f"${float(summary.get('total_cost_usd')):.4f}" if summary.get("total_cost_usd") is not None else "-", ""),
        ("By Role", by_role_text or "-", ""),
    ]
    return "".join(
        '<div class="step"><div><strong>'
        + _html_escape(label)
        + '</strong><div class="meta">'
        + _html_escape(meta)
        + '</div></div><div>'
        + _html_escape(value)
        + "</div></div>"
        for label, value, meta in rows
    )


def _render_roles_html(roles: object) -> str:
    if not isinstance(roles, list) or not roles:
        return '<div class="hint">No role activity yet.</div>'
    items = []
    for role in roles:
        if not isinstance(role, dict):
            continue
        meta_tail = str(role.get("extra", "") or "")
        if role.get("remaining_steps"):
            meta_tail += f" remaining={role.get('remaining_steps')}"
        items.append(
            '<div class="step"><div><strong>'
            + _html_escape(role.get("name", ""))
            + '</strong><div class="meta">'
            + _html_escape(f"{role.get('provider', '')}/{role.get('model', '')}")
            + '</div><div class="meta">log='
            + _html_escape(role.get("latest_log", "-") or "-")
            + " size="
            + _html_escape(_pretty_bytes(role.get("latest_log_bytes")))
            + '</div><div class="meta">'
            + _html_escape(meta_tail)
            + '</div></div><div class="'
            + _status_class(role.get("status"))
            + '">'
            + _html_escape(role.get("status", "idle"))
            + "</div></div>"
        )
    return "".join(items) or '<div class="hint">No role activity yet.</div>'


def _render_chat_html(chat: object) -> str:
    if not isinstance(chat, list) or not chat:
        return '<div class="hint">No messages yet.</div>'
    items = []
    for msg in chat:
        if not isinstance(msg, dict):
            continue
        items.append(
            '<div class="msg '
            + _html_escape(msg.get("role", "system"))
            + '"><div class="head"><span>'
            + _html_escape(msg.get("role", "system"))
            + "</span><span>"
            + _html_escape(msg.get("at", ""))
            + "</span></div><div>"
            + _html_escape(msg.get("message", "")).replace("\n", "<br>")
            + "</div></div>"
        )
    return "".join(items) or '<div class="hint">No messages yet.</div>'


def _history_events(path: Path, limit: int = 20) -> list[dict[str, object]]:
    rows = load_jsonl(path, limit=limit)
    events: list[dict[str, object]] = []
    for row in rows:
        detail_text = ""
        details = row.get("details")
        if isinstance(details, dict) and details:
            detail_text = " ".join(f"{name}={value}" for name, value in details.items())
        events.append(
            {
                "schema_version": str(row.get("schema_version", "")),
                "at": str(row.get("at", "")),
                "event": str(row.get("event", row.get("category", ""))),
                "status": str(row.get("status", "")),
                "failure_class": str(row.get("failure_class", "")),
                "message": str(row.get("message", "")),
                "detail_text": detail_text,
            }
        )
    return events


def _render_history_html(history: object) -> str:
    if not isinstance(history, list) or not history:
        return '<div class="hint">No recent events yet.</div>'
    items = []
    for event in history:
        if not isinstance(event, dict):
            continue
        items.append(
            '<div class="step"><div><strong>'
            + _html_escape(event.get("message", "") or event.get("event", "event"))
            + '</strong><div class="meta">'
            + _html_escape(event.get("at", ""))
            + '</div><div class="meta">'
            + _html_escape(
                " ".join(
                    part for part in (
                        str(event.get("event", "") or ""),
                        str(event.get("status", "") or ""),
                        str(event.get("failure_class", "") or ""),
                    ) if part
                )
            )
            + '</div><div class="meta">'
            + _html_escape(event.get("detail_text", ""))
            + '</div></div><div class="'
            + _status_class(event.get("status"))
            + '">'
            + _html_escape(event.get("status", "-"))
            + "</div></div>"
        )
    return "".join(items) or '<div class="hint">No recent events yet.</div>'


def _operator_actions(history: list[dict[str, object]], limit: int = 10) -> list[dict[str, object]]:
    rows = [event for event in history if isinstance(event, dict) and event.get("event") == "operator.action_requested"]
    return rows[-limit:]


def _render_actions_html(actions: object) -> str:
    if not isinstance(actions, list) or not actions:
        return '<div class="hint">No operator actions recorded yet.</div>'
    items = []
    for event in actions:
        if not isinstance(event, dict):
            continue
        items.append(
            '<div class="step"><div><strong>'
            + _html_escape(event.get("message", "") or event.get("event", "action"))
            + '</strong><div class="meta">'
            + _html_escape(event.get("at", ""))
            + '</div><div class="meta">'
            + _html_escape(event.get("detail_text", ""))
            + '</div></div><div class="'
            + _status_class(event.get("status"))
            + '">'
            + _html_escape(event.get("status", "-"))
            + "</div></div>"
        )
    return "".join(items) or '<div class="hint">No operator actions recorded yet.</div>'


def _render_blockers_html(blockers: object) -> str:
    if not isinstance(blockers, list) or not blockers:
        return '<div class="hint">No blockers or recovery activity recorded.</div>'
    items = []
    for row in blockers:
        if not isinstance(row, dict):
            continue
        items.append(
            '<div class="step"><div><strong>'
            + _html_escape(row.get("title", "-"))
            + '</strong><div class="meta">'
            + _html_escape(row.get("meta", ""))
            + '</div></div><div class="'
            + _status_class(row.get("status"))
            + '">'
            + _html_escape(row.get("status", "-"))
            + "</div></div>"
        )
    return "".join(items) or '<div class="hint">No blockers or recovery activity recorded.</div>'


def _render_autonomy_html(autonomy: dict[str, object]) -> str:
    rows = [
        ("Closeout", autonomy.get("last_closeout_action", "-"), "auto-commit enabled" if autonomy.get("auto_commit_enabled") else "auto-commit disabled"),
        ("Branch", autonomy.get("branch_name", "-"), autonomy.get("branch_note", "")),
        ("Maintenance", autonomy.get("maintenance_updated_at", "-"), autonomy.get("maintenance_note", "")),
        ("Compaction", autonomy.get("compaction_note", "-"), ""),
        ("Recommendation", autonomy.get("top_recommendation", "-"), ""),
    ]
    return "".join(
        '<div class="step"><div><strong>'
        + _html_escape(label)
        + '</strong><div class="meta">'
        + _html_escape(meta)
        + '</div></div><div>'
        + _html_escape(value)
        + "</div></div>"
        for label, value, meta in rows
    )


def _current_blockers(history: list[dict[str, object]]) -> list[dict[str, object]]:
    blockers: list[dict[str, object]] = []
    for event in reversed(history):
        if not isinstance(event, dict):
            continue
        failure_class = str(event.get("failure_class", "") or "")
        status = str(event.get("status", "") or "")
        if failure_class or status in {"failed", "retrying", "blocked", "warning"}:
            blockers.append(
                {
                    "title": str(event.get("message", "") or event.get("event", "event")),
                    "meta": " ".join(
                        part
                        for part in (
                            str(event.get("event", "") or ""),
                            failure_class,
                            str(event.get("detail_text", "") or ""),
                        )
                        if part
                    ),
                    "status": status,
                }
            )
        if len(blockers) >= 6:
            break
    return list(reversed(blockers))


def _safe_bootstrap_json(payload: dict[str, object]) -> str:
    return (
        json.dumps(payload, sort_keys=True)
        .replace("</", "<\\/")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


class HarnessWebUI:
    def __init__(self, cfg: RuntimeConfig, harness: object | None = None):
        self.cfg = cfg
        self.llm_cfg = LlmConfig.from_env()
        self.harness = harness
        self.server: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None
        self.url = ""
        self._usage_cache: dict[str, object] = {
            "marker": "",
            "payload": {
                "available": False,
                "message": "Usage scan pending.",
                "sources_scanned": 0,
            },
        }

    def _usage_marker(self) -> str:
        try:
            logs = sorted(self.cfg.log_dir.glob("*.log"))
        except OSError:
            return ""
        if not logs:
            return "empty"
        recent = logs[-10:]
        parts = []
        for path in recent:
            try:
                stat = path.stat()
            except OSError:
                continue
            parts.append(f"{path.name}:{stat.st_size}:{int(stat.st_mtime)}")
        return "|".join(parts)

    def _cached_usage_summary(self) -> dict[str, object]:
        session_rows = load_jsonl(self.cfg.session_ledger_file, limit=200)
        if session_rows:
            summary = summarize_session_rows(session_rows)
            return {
                "available": summary.get("total_tokens") is not None or summary.get("total_cost_usd") is not None,
                "prompt_tokens": None,
                "completion_tokens": None,
                "total_tokens": summary.get("total_tokens"),
                "cost_usd": summary.get("total_cost_usd"),
                "sources_scanned": summary.get("total_sessions", 0),
                "message": "Aggregated from structured session ledger.",
            }
        marker = self._usage_marker()
        cached_marker = str(self._usage_cache.get("marker", ""))
        cached_payload = self._usage_cache.get("payload", {})
        if marker == cached_marker and isinstance(cached_payload, dict):
            return cached_payload
        payload = _usage_summary(self.cfg.log_dir)
        self._usage_cache = {"marker": marker, "payload": payload}
        return payload

    def _render_html_page(self, payload: dict[str, object]) -> str:
        status = payload.get("status", {}) if isinstance(payload.get("status"), dict) else {}
        history = payload.get("history", []) if isinstance(payload.get("history"), list) else []
        latest_event = history[-1] if history else {}
        latest_event_text = ""
        if isinstance(latest_event, dict):
            latest_event_text = str(latest_event.get("message", "") or latest_event.get("event", "") or "")
        summary = (
            f"{payload.get('project_name', self.cfg.project_name)} | "
            f"updated {status.get('updated_at', '-') or '-'} | "
            f"{latest_event_text or status.get('extra', 'idle') or 'idle'}"
        )
        badge_text = f"{status.get('step', '-') or '-'} / {status.get('status', '-') or '-'}"
        html_page = HTML_PAGE.replace("__POLL_MS__", str(int(max(0.5, self.cfg.web_ui_poll_secs) * 1000)))
        html_page = html_page.replace("__BOOTSTRAP_STATE__", _safe_bootstrap_json(payload))
        html_page = html_page.replace("__SUMMARY__", _html_escape(summary))
        html_page = html_page.replace("__BADGE_TEXT__", _html_escape(badge_text))
        html_page = html_page.replace("__BADGE_CLASS__", _status_class(status.get("status")))
        html_page = html_page.replace("__ERROR_CLASS__", "")
        html_page = html_page.replace("__ERROR_TEXT__", "")
        html_page = html_page.replace("__STATS_HTML__", _render_stat_cards(payload))
        html_page = html_page.replace("__STEPS_HTML__", _render_steps_html(payload))
        html_page = html_page.replace("__PROCESSES_HTML__", _render_processes_html(payload.get("child_processes")))
        html_page = html_page.replace("__TASK_PACKET_HTML__", _render_task_packet_html(payload.get("current_task_packet", {}), str(payload.get("current_task_packet_status", ""))))
        html_page = html_page.replace("__POLICY_HTML__", _render_policy_html(payload.get("last_policy_decision", {}), str(payload.get("current_green_level", ""))))
        html_page = html_page.replace("__RESOURCES_HTML__", _render_resources_html(payload.get("resources", {})))
        html_page = html_page.replace("__USAGE_HTML__", _render_usage_html(payload.get("usage", {})))
        html_page = html_page.replace("__PREFLIGHT_HTML__", _render_preflight_html(payload.get("preflight", {})))
        html_page = html_page.replace("__SESSIONS_HTML__", _render_sessions_html(payload.get("session_summary", {})))
        html_page = html_page.replace("__ROLES_HTML__", _render_roles_html(payload.get("roles")))
        html_page = html_page.replace("__HISTORY_HTML__", _render_history_html(payload.get("history")))
        html_page = html_page.replace("__ACTIONS_HTML__", _render_actions_html(payload.get("actions")))
        html_page = html_page.replace("__BLOCKERS_HTML__", _render_blockers_html(payload.get("blockers")))
        html_page = html_page.replace("__AUTONOMY_HTML__", _render_autonomy_html(payload.get("autonomy", {})))
        console = payload.get("console", {}) if isinstance(payload.get("console"), dict) else {}
        console_meta = f"{console.get('path', '-') or '-'} | {_pretty_bytes(console.get('size_bytes'))} | tailing live"
        html_page = html_page.replace("__CONSOLE_META__", _html_escape(console_meta))
        html_page = html_page.replace("__CONSOLE_TEXT__", _html_escape(console.get("text", "")))
        html_page = html_page.replace("__CHAT_HTML__", _render_chat_html(payload.get("chat")))
        return html_page

    def _state_payload(self) -> dict[str, object]:
        status = _parse_kv_file(self.cfg.status_file)
        latest_cycle = self.cfg.state_dir / "latest_cycle"
        cycle_dir = latest_cycle.resolve() if latest_cycle.exists() else None
        cycle_state = _load_json(cycle_dir / "cycle.state.json") if cycle_dir is not None else None
        child_processes = _load_json(self.cfg.state_dir / "child_processes.json")
        if not isinstance(child_processes, list):
            child_processes = []
        cycle_steps = {}
        if isinstance(cycle_state, dict):
            raw_steps = cycle_state.get("steps", {})
            if isinstance(raw_steps, dict):
                cycle_steps = raw_steps
        log_stats = _role_log_stats(self.cfg.log_dir)
        session_rows = load_jsonl(self.cfg.session_ledger_file, limit=200)
        preflight = read_json(self.cfg.preflight_state_file)
        maintenance = read_json(self.cfg.maintenance_file)
        history = _history_events(self.cfg.history_log_file)
        actions = _operator_actions(history)
        blockers = _current_blockers(history)
        autonomy: dict[str, object] = {}
        if isinstance(cycle_state, dict):
            freshness = cycle_state.get("branch_freshness", {})
            branch_note = ""
            if isinstance(freshness, dict):
                if freshness.get("stale"):
                    branch_note = f"behind main by {freshness.get('behind', 0)} commit(s)"
                elif freshness.get("main_available"):
                    branch_note = f"ahead={freshness.get('ahead', 0)} behind={freshness.get('behind', 0)}"
            recommendations = maintenance.get("recommendations", []) if isinstance(maintenance, dict) else []
            compaction = maintenance.get("compaction", {}) if isinstance(maintenance, dict) else {}
            compaction_note = ""
            if isinstance(compaction, dict):
                top_failures = compaction.get("top_failure_classes", [])
                if isinstance(top_failures, list) and top_failures:
                    first = top_failures[0]
                    if isinstance(first, dict):
                        compaction_note = f"{first.get('name', '-')}: {first.get('count', 0)}"
            autonomy = {
                "last_closeout_action": cycle_state.get("last_closeout_action", ""),
                "auto_commit_enabled": self.cfg.auto_commit_enabled,
                "branch_name": cycle_state.get("branch_name", ""),
                "branch_note": branch_note,
                "maintenance_updated_at": maintenance.get("updated_at", "") if isinstance(maintenance, dict) else "",
                "maintenance_note": maintenance.get("reason", "") if isinstance(maintenance, dict) else "",
                "compaction_note": compaction_note,
                "top_recommendation": recommendations[0] if isinstance(recommendations, list) and recommendations else "",
            }
        return {
            "project_name": self.cfg.project_name,
            "current_cycle": cycle_dir.name if cycle_dir is not None else "",
            "status": status,
            "step_order": list(("full-sweep", "checker", "planner", "worker", "reviewer")),
            "cycle_steps": cycle_steps,
            "current_task_packet": cycle_state.get("current_task_packet", {}) if isinstance(cycle_state, dict) else {},
            "current_task_packet_status": cycle_state.get("current_task_packet_status", "") if isinstance(cycle_state, dict) else "",
            "current_green_level": cycle_state.get("current_green_level", "") if isinstance(cycle_state, dict) else "",
            "last_policy_decision": cycle_state.get("last_policy_decision", {}) if isinstance(cycle_state, dict) else {},
            "console": {
                "path": str(self.cfg.last_log_file),
                "size_bytes": self.cfg.last_log_file.stat().st_size if self.cfg.last_log_file.exists() else 0,
                "text": _tail_text(self.cfg.last_log_file),
            },
            "pending_comments": self.cfg.operator_comments_file.read_text(encoding="utf-8", errors="replace").strip()
            if self.cfg.operator_comments_file.exists()
            else "",
            "chat": _load_chat(self.cfg.chat_log_file),
            "child_processes": child_processes,
            "log_stats": log_stats,
            "resources": {
                "free_disk_mb": _free_disk_mb(self.cfg.root_dir),
                "free_ram_mb": _free_ram_mb(),
                "state_dir_mb": _state_dir_mb(self.cfg.state_dir),
                "active_process_count": len(child_processes),
                "disk_note": f"minimum target {self.cfg.min_free_disk_mb} MB",
                "ram_note": f"minimum target {self.cfg.min_free_ram_mb} MB",
                "state_note": f"budget {self.cfg.max_state_dir_mb} MB",
            },
            "roles": _role_activity(
                self.cfg,
                self.llm_cfg,
                status=status,
                cycle_steps=cycle_steps,
                log_stats=log_stats,
            ),
            "preflight": preflight,
            "history": history,
            "actions": actions,
            "blockers": blockers,
            "autonomy": autonomy,
            "sessions": session_rows,
            "session_summary": summarize_session_rows(session_rows),
            "usage": self._cached_usage_summary(),
        }

    def _write_operator_comment(self, message: str) -> None:
        existing = ""
        if self.cfg.operator_comments_file.exists():
            existing = self.cfg.operator_comments_file.read_text(encoding="utf-8", errors="replace").strip()
        new_text = f"{existing}\n\n{message}".strip() if existing else message
        self.cfg.operator_comments_file.write_text(new_text + "\n", encoding="utf-8")
        append_chat_entry(self.cfg.chat_log_file, "operator", message)

    def _apply_action(self, action: str) -> dict[str, object]:
        harness = self.harness
        if action == "pause":
            if harness is not None and hasattr(harness, "pause_requested_by_operator"):
                return harness.pause_requested_by_operator()
            self.cfg.stop_file.write_text("paused by web ui\n", encoding="utf-8")
            return {"ok": True, "action": action, "message": "pause requested"}
        if action == "resume":
            if harness is not None and hasattr(harness, "resume_requested_by_operator"):
                return harness.resume_requested_by_operator()
            self.cfg.stop_file.unlink(missing_ok=True)
            return {"ok": True, "action": action, "message": "resume requested"}
        if action == "force-planner-rewrite":
            if harness is not None and hasattr(harness, "request_planner_rewrite"):
                return harness.request_planner_rewrite()
            latest_cycle = self.cfg.state_dir / "latest_cycle"
            cycle_dir = latest_cycle.resolve() if latest_cycle.exists() else None
            state_path = cycle_dir / "cycle.state.json" if cycle_dir is not None else None
            payload = read_json(state_path) if state_path is not None else {}
            if not payload:
                return {"ok": False, "error": "no-active-cycle", "message": "no active cycle state to rewrite"}
            payload["next_cycle_start_step"] = "planner"
            payload["plan_rewrite_target"] = str(payload.get("current_plan_item", "") or "")
            payload["last_closeout_action"] = "rewrite"
            if state_path is not None:
                write_json(state_path, payload)
            return {"ok": True, "action": action, "message": "planner rewrite queued"}
        if action == "force-stronger-worker":
            if harness is not None and hasattr(harness, "request_stronger_worker"):
                return harness.request_stronger_worker()
            latest_cycle = self.cfg.state_dir / "latest_cycle"
            cycle_dir = latest_cycle.resolve() if latest_cycle.exists() else None
            state_path = cycle_dir / "cycle.state.json" if cycle_dir is not None else None
            payload = read_json(state_path) if state_path is not None else {}
            if not payload:
                return {"ok": False, "error": "no-active-cycle", "message": "no active cycle state for worker override"}
            payload["manual_worker_model_override"] = self.cfg.worker_stall_model
            payload["manual_worker_failure_limit_override"] = self.cfg.worker_stall_failure_limit
            if state_path is not None:
                write_json(state_path, payload)
            return {"ok": True, "action": action, "message": "stronger worker queued"}
        if action == "run-maintenance":
            if harness is not None and hasattr(harness, "run_background_maintenance"):
                return harness.run_background_maintenance()
            return {"ok": False, "error": "maintenance-unavailable", "message": "live maintenance requires active harness"}
        return {"ok": False, "error": "unknown-action", "message": f"unknown action: {action}"}

    def _build_handler(self):
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, _format: str, *_args: object) -> None:
                return

            def _send_json(self, payload: dict[str, object], status: HTTPStatus = HTTPStatus.OK) -> None:
                body = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Cache-Control", "no-store, max-age=0")
                self.send_header("Pragma", "no-cache")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _send_html(self, body: str) -> None:
                data = body.encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Cache-Control", "no-store, max-age=0")
                self.send_header("Pragma", "no-cache")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self) -> None:
                parsed = urlparse(self.path)
                if parsed.path == "/":
                    self._send_html(outer._render_html_page(outer._state_payload()))
                    return
                if parsed.path == "/api/state":
                    self._send_json(outer._state_payload())
                    return
                if parsed.path == "/api/console":
                    query = parse_qs(parsed.query)
                    max_bytes = int(query.get("tail_bytes", ["65536"])[0])
                    self._send_json(
                        {
                            "path": str(outer.cfg.last_log_file),
                            "size_bytes": outer.cfg.last_log_file.stat().st_size if outer.cfg.last_log_file.exists() else 0,
                            "text": _tail_text(outer.cfg.last_log_file, max_bytes=max_bytes),
                        }
                    )
                    return
                self.send_error(HTTPStatus.NOT_FOUND, "Not found")

            def do_POST(self) -> None:
                content_length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(content_length).decode("utf-8", errors="replace")
                try:
                    payload = json.loads(raw) if raw else {}
                except json.JSONDecodeError:
                    self._send_json({"ok": False, "error": "invalid-json"}, status=HTTPStatus.BAD_REQUEST)
                    return
                if self.path == "/api/comment":
                    message = str(payload.get("message", "")).strip()
                    if not message:
                        self._send_json({"ok": False, "error": "empty-message"}, status=HTTPStatus.BAD_REQUEST)
                        return
                    outer._write_operator_comment(message)
                    self._send_json({"ok": True})
                    return
                if self.path == "/api/action":
                    action = str(payload.get("action", "")).strip()
                    if not action:
                        self._send_json({"ok": False, "error": "empty-action"}, status=HTTPStatus.BAD_REQUEST)
                        return
                    result = outer._apply_action(action)
                    self._send_json(result, status=HTTPStatus.OK if result.get("ok") else HTTPStatus.BAD_REQUEST)
                    return
                self.send_error(HTTPStatus.NOT_FOUND, "Not found")

        return Handler

    def start(self) -> str:
        host = self.cfg.web_ui_host
        port = self.cfg.web_ui_port
        try:
            self.server = ThreadingHTTPServer((host, port), self._build_handler())
        except OSError:
            self.server = ThreadingHTTPServer((host, 0), self._build_handler())
        actual_host, actual_port = self.server.server_address[:2]
        self.url = f"http://{actual_host}:{actual_port}/"
        self.thread = threading.Thread(target=self.server.serve_forever, name="meta-harness-webui", daemon=True)
        self.thread.start()
        if self.cfg.web_ui_auto_open:
            try:
                webbrowser.open(self.url)
            except Exception:
                pass
        return self.url

    def stop(self) -> None:
        if self.server is None:
            return
        self.server.shutdown()
        self.server.server_close()
        if self.thread is not None:
            self.thread.join(timeout=2)


def launch_web_ui(cfg: RuntimeConfig, harness: object | None = None) -> HarnessWebUI | None:
    if not cfg.web_ui_enabled:
        return None
    ui = HarnessWebUI(cfg, harness=harness)
    ui.start()
    return ui
