"use strict";

const byId = (id) => document.getElementById(id);
const refreshEveryMs = 15000;
let refreshTimer = null;

const statusVocabulary = new Set([
  "completed", "running", "awaiting_approval", "refused", "error",
  "cancelled", "recursion", "corrupt", "configured", "blocked", "not_configured"
]);

function statusClass(value) {
  return statusVocabulary.has(value) ? value.replaceAll("_", "-") : "unknown";
}

function money(value) {
  const amount = Number(value || 0);
  return amount < 0.01 ? `$${amount.toFixed(4)}` : `$${amount.toFixed(2)}`;
}

function compactNumber(value) {
  return new Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 }).format(value || 0);
}

function countLabel(value, singular, plural = `${singular}s`) {
  return `${value} ${value === 1 ? singular : plural}`;
}

function elapsed(iso) {
  if (!iso) return "—";
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function shortId(value, size = 8) {
  if (!value) return "—";
  return value.length > size ? `${value.slice(0, size)}…` : value;
}

function setText(id, value) {
  const node = byId(id);
  if (node) node.textContent = value;
}

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function renderOverview(data) {
  const overview = data.overview;
  setText("runs-today", compactNumber(overview.runs_today));
  setText("active-runs", compactNumber(overview.active_runs));
  setText("success-rate", overview.success_rate === null ? "No runs" : `${overview.success_rate}%`);
  setText("cost-today", money(overview.cost_today_usd));
  setText("budget-caption", `of ${money(overview.daily_budget_usd)}`);
  const budgetPercent = overview.daily_budget_usd > 0
    ? Math.min(100, overview.cost_today_usd / overview.daily_budget_usd * 100)
    : 0;
  byId("budget-used").style.width = `${budgetPercent}%`;
  setText("audit-health", compactNumber(overview.audit_verified));
  setText("audit-failed", overview.audit_failed);
  setText("path-intent", `${overview.runs_today} today`);
  setText("path-audit", `${overview.audit_verified} chains verified`);
}

function renderActivity(days) {
  const chart = byId("activity-chart");
  chart.replaceChildren();
  const maxRuns = Math.max(1, ...days.map((day) => day.runs));
  const maxCost = Math.max(0.000001, ...days.map((day) => day.cost_usd));
  days.forEach((day) => {
    const column = element("div", "activity-day");
    const bars = element("div", "bar-pair");
    const runBar = element("i", "run-bar");
    const costBar = element("i", "cost-bar");
    runBar.style.height = `${Math.max(day.runs ? 8 : 2, day.runs / maxRuns * 100)}%`;
    costBar.style.height = `${Math.max(day.cost_usd ? 8 : 2, day.cost_usd / maxCost * 100)}%`;
    runBar.title = `${day.runs} runs`;
    costBar.title = money(day.cost_usd);
    bars.append(runBar, costBar);
    const date = new Date(`${day.date}T00:00:00Z`);
    column.append(bars, element("span", "", date.toLocaleDateString("en", { weekday: "short", timeZone: "UTC" })));
    chart.append(column);
  });
}

function renderPolicy(data) {
  setText("policy-decisions", compactNumber(data.policy.decisions));
  setText("policy-executions", compactNumber(data.policy.executions));
  setText("policy-denials", compactNumber(data.policy.denials));
  setText("policy-escalations", compactNumber(data.policy.escalations));
  setText("path-policy", countLabel(data.policy.decisions, "decision"));
  setText("path-executions", countLabel(data.policy.executions, "command"));

  const rail = byId("event-rail");
  rail.replaceChildren();
  if (!data.latest_timeline.length) {
    rail.append(element("li", "empty-state", "No audit events have landed yet."));
    return;
  }
  [...data.latest_timeline].reverse().slice(0, 9).forEach((event) => {
    const item = element("li", `rail-event event-${event.type}`);
    const marker = element("span", "rail-marker");
    const body = element("div", "rail-body");
    const heading = element("div", "rail-heading");
    heading.append(
      element("strong", "", event.type.replaceAll("_", " ")),
      element("time", "", elapsed(event.ts))
    );
    const detail = event.effect
      ? `${event.effect} · ${event.rule_id || "policy rule"}`
      : event.tool
        ? `${event.tool}${event.exit_code !== null ? ` · exit ${event.exit_code}` : ""}`
        : shortId(event.event_id, 12);
    body.append(heading, element("p", "", detail));
    item.append(marker, body);
    rail.append(item);
  });
}

function renderStatusSummary(counts) {
  const container = byId("status-summary");
  container.replaceChildren();
  if (!Object.keys(counts).length) {
    container.append(element("span", "summary-chip", "No persisted runs"));
    return;
  }
  Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 4).forEach(([status, count]) => {
    const chip = element("span", `summary-chip ${statusClass(status)}`);
    chip.append(element("i"), document.createTextNode(`${status.replaceAll("_", " ")} ${count}`));
    container.append(chip);
  });
}

function renderRuns(runs) {
  const body = byId("run-rows");
  body.replaceChildren();
  if (!runs.length) {
    const row = document.createElement("tr");
    const cell = element("td", "empty-state", "No audit runs yet. Start an agent run to populate the ledger.");
    cell.colSpan = 8;
    row.append(cell);
    body.append(row);
    return;
  }
  runs.forEach((run) => {
    const row = document.createElement("tr");
    const identity = document.createElement("td");
    identity.append(
      element("strong", "run-id", shortId(run.run_id, 10)),
      element("small", "", `${run.events} chained events`)
    );
    const state = document.createElement("td");
    state.append(element("span", `status-pill ${statusClass(run.status)}`, run.status.replaceAll("_", " ")));
    const principal = document.createElement("td");
    principal.append(element("strong", "", run.principal), element("small", "", run.interface));
    const environment = document.createElement("td");
    environment.append(element("span", "environment-pill", run.environment));
    const policy = document.createElement("td");
    policy.append(
      element("strong", "", countLabel(run.decisions, "decision")),
      element("small", run.denials ? "danger-text" : "", `${run.denials} denied`)
    );
    const execution = document.createElement("td");
    execution.append(
      element("strong", "", countLabel(run.executions, "command")),
      element("small", "", `${run.escalations} escalated`)
    );
    const cost = element("td", "cost-cell", money(run.cost_usd));
    const updated = document.createElement("td");
    updated.append(element("strong", "", elapsed(run.updated_at)), element("small", "", run.integrity));
    row.append(identity, state, principal, environment, policy, execution, cost, updated);
    body.append(row);
  });
}

function renderIntegrations(integrations) {
  const grid = byId("integration-grid");
  grid.replaceChildren();
  integrations.forEach((integration) => {
    const card = element("article", "integration-card");
    const state = element("span", `integration-state ${statusClass(integration.state)}`);
    state.append(element("i"), document.createTextNode(integration.state.replaceAll("_", " ")));
    card.append(
      element("strong", "", integration.name),
      state,
      element("p", "", integration.detail)
    );
    grid.append(card);
  });
}

function renderRuntime(runtime) {
  setText("runtime-executor", runtime.executor_mode);
  setText("runtime-model", runtime.model ? runtime.model.split(":").at(-1) : "—");
  setText("runtime-policy", runtime.policy_version ? shortId(runtime.policy_version.replace("sha256:", ""), 10) : "not observed");
}

function renderSnapshot(data) {
  renderOverview(data);
  renderActivity(data.daily);
  renderPolicy(data);
  renderStatusSummary(data.status_counts);
  renderRuns(data.runs);
  renderIntegrations(data.integrations);
  renderRuntime(data.runtime);
  setText("connection-state", "Connected");
  setText("last-refresh", `Updated ${elapsed(data.generated_at)}`);
  setText("snapshot-id", `Snapshot · ${data.generated_at.replace("T", " ").slice(0, 19)} UTC`);
  document.body.classList.remove("connection-error");
}

async function refresh() {
  const button = byId("refresh-button");
  button?.classList.add("is-refreshing");
  if (button) button.disabled = true;
  try {
    const response = await fetch("/dashboard/api/snapshot", {
      credentials: "same-origin",
      headers: { Accept: "application/json" }
    });
    if (response.status === 401) {
      window.location.assign("/dashboard/login");
      return;
    }
    if (!response.ok) throw new Error(`snapshot returned ${response.status}`);
    renderSnapshot(await response.json());
  } catch (error) {
    setText("connection-state", "Snapshot unavailable");
    setText("last-refresh", "Retrying automatically");
    document.body.classList.add("connection-error");
  } finally {
    button?.classList.remove("is-refreshing");
    if (button) button.disabled = false;
  }
}

function scheduleRefresh() {
  window.clearInterval(refreshTimer);
  refreshTimer = window.setInterval(() => {
    if (!document.hidden) refresh();
  }, refreshEveryMs);
}

refresh();
scheduleRefresh();
byId("refresh-button")?.addEventListener("click", refresh);
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) refresh();
});
