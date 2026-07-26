"use strict";

const byId = (id) => document.getElementById(id);
const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || "";
let eventStream = null;
let reconnectTimer = null;
let currentRoles = new Set();

const statusVocabulary = new Set([
  "completed", "running", "awaiting_approval", "refused", "error",
  "cancelled", "recursion", "corrupt", "configured", "blocked", "not_configured",
  "pending", "approved", "active", "rejected", "revoked", "expired"
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
    row.className = "run-row";
    row.tabIndex = 0;
    row.addEventListener("click", () => openRunDetail(run.run_id));
    row.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") openRunDetail(run.run_id);
    });
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
      element("small", "", `${run.model_calls || 0} model calls · ${run.escalations} escalated`)
    );
    const cost = element("td", "cost-cell", money(run.cost_usd));
    const updated = document.createElement("td");
    updated.append(element("strong", "", elapsed(run.updated_at)), element("small", "", run.integrity));
    row.append(identity, state, principal, environment, policy, execution, cost, updated);
    body.append(row);
  });
}

function renderLive(live = {}) {
  const active = live.active_runs || [];
  const approvals = live.pending_approvals || [];
  setText("live-active", compactNumber(active.length));
  setText("live-queue", live.queue_depth ?? "—");
  setText("live-workers", live.worker_active ?? live.workers ?? "—");
  setText("live-errors", live.executor_errors ?? "—");
  setText(
    "live-queue-latency",
    live.queue_latency_ms === null || live.queue_latency_ms === undefined
      ? "—"
      : `${Math.round(live.queue_latency_ms)} ms`
  );
  setText("live-approvals", compactNumber(approvals.length));

  const list = byId("approval-list");
  list.replaceChildren();
  if (!approvals.length) {
    list.append(element("p", "empty-state", "No approvals are waiting."));
    return;
  }
  approvals.forEach((approval) => {
    const item = element("article", "approval-item");
    const copy = element("div");
    copy.append(
      element("strong", "", `${approval.environment} change`),
      element("p", "", `${shortId(approval.run_id, 12)} · requested by ${approval.requester}`)
    );
    const actions = element("div", "row-actions");
    if (currentRoles.has("approver") || currentRoles.has("admin")) {
      const approve = element("button", "small-action primary", "Approve");
      approve.type = "button";
      approve.addEventListener("click", () => resolveApproval(approval.thread_id, "approve"));
      const reject = element("button", "small-action", "Reject");
      reject.type = "button";
      reject.addEventListener("click", () => resolveApproval(approval.thread_id, "reject"));
      actions.append(approve, reject);
    }
    item.append(copy, actions);
    list.append(item);
  });
}

function sliValue(value, suffix, digits = 1) {
  return value === null || value === undefined ? "—" : `${Number(value).toFixed(digits)}${suffix}`;
}

function renderSlis(slis = {}) {
  setText("sli-run-success", sliValue(slis.run_success_percent, "%"));
  setText("sli-queue-latency", sliValue(slis.queue_latency_ms, " ms", 0));
  setText("sli-policy-latency", sliValue(slis.policy_latency_ms, " ms", 1));
  setText("sli-executor-errors", sliValue(slis.executor_error_percent, "%"));
  setText("sli-audit-lag", sliValue(slis.audit_lag_seconds, " s", 0));
  setText("sli-budget-used", sliValue(slis.budget_utilization_percent, "%"));
}

function renderProposals(control = {}) {
  const revision = control.revision || "—";
  setText("control-revision", `revision ${shortId(revision.replace("sha256:", ""), 10)}`);
  const list = byId("proposal-list");
  list.replaceChildren();
  const proposals = control.proposals || control.items || [];
  if (!proposals.length) {
    list.append(element("p", "empty-state", "No capability changes have been proposed."));
    return;
  }
  proposals.forEach((proposal) => {
    const card = element("article", "proposal-item");
    const heading = element("div", "proposal-heading");
    heading.append(
      element("strong", "", proposal.request.capability.replaceAll("_", " ")),
      element("span", `status-pill ${statusClass(proposal.status)}`, proposal.status)
    );
    const request = proposal.request;
    card.append(
      heading,
      element("p", "", `${request.environment} · ${request.targets.join(", ")}`),
      element("small", "", `${request.max_executions} executions · expires ${elapsed(proposal.expires_at)}`)
    );
    const actions = element("div", "row-actions");
    if (proposal.status === "pending" && (currentRoles.has("approver") || currentRoles.has("admin"))) {
      const approve = element("button", "small-action primary", "Approve");
      approve.type = "button";
      approve.addEventListener("click", () => proposalAction(proposal.proposal_id, "approve"));
      actions.append(approve);
    }
    if (proposal.status === "approved" && currentRoles.has("admin")) {
      const activate = element("button", "small-action primary", "Activate");
      activate.type = "button";
      activate.addEventListener("click", () => proposalAction(proposal.proposal_id, "activate"));
      actions.append(activate);
    }
    if (proposal.status === "active" && currentRoles.has("admin")) {
      const revoke = element("button", "small-action danger", "Revoke");
      revoke.type = "button";
      revoke.addEventListener("click", () => proposalAction(proposal.proposal_id, "revoke"));
      actions.append(revoke);
    }
    card.append(actions);
    list.append(card);
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
  if (data.identity?.roles) currentRoles = new Set(data.identity.roles);
  renderOverview(data);
  renderActivity(data.daily);
  renderPolicy(data);
  renderStatusSummary(data.status_counts);
  renderRuns(data.runs);
  renderIntegrations(data.integrations);
  renderRuntime(data.runtime);
  renderSlis(data.slis);
  if (data.live) renderLive(data.live);
  if (data.control_plane) renderProposals(data.control_plane);
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

async function mutation(url, body = {}) {
  const response = await fetch(url, {
    method: "POST",
    credentials: "same-origin",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/json",
      "X-CSRF-Token": csrfToken
    },
    body: JSON.stringify(body)
  });
  if (response.status === 401) {
    window.location.assign("/dashboard/login");
    throw new Error("session expired");
  }
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(payload.detail || `request returned ${response.status}`);
  return payload;
}

async function resolveApproval(threadId, type) {
  try {
    await mutation(`/dashboard/api/approvals/${encodeURIComponent(threadId)}`, {
      decisions: [{ type, message: type === "reject" ? "rejected from dashboard" : undefined }]
    });
    await refresh();
  } catch (error) {
    window.alert(error.message);
  }
}

async function proposalAction(proposalId, action) {
  try {
    await mutation(
      `/dashboard/api/config/proposals/${encodeURIComponent(proposalId)}/${action}`
    );
    await refresh();
  } catch (error) {
    window.alert(error.message);
  }
}

async function openRunDetail(runId) {
  const drawer = byId("run-detail");
  const body = byId("run-detail-body");
  drawer.classList.add("is-open");
  drawer.setAttribute("aria-hidden", "false");
  body.replaceChildren(element("p", "empty-state", "Loading correlated events…"));
  try {
    const response = await fetch(`/dashboard/api/runs/${encodeURIComponent(runId)}`, {
      credentials: "same-origin",
      headers: { Accept: "application/json" }
    });
    if (!response.ok) throw new Error(`run detail returned ${response.status}`);
    const detail = await response.json();
    setText("run-detail-title", shortId(detail.run_id, 18));
    body.replaceChildren();
    const meta = element("dl", "detail-meta");
    [
      ["Status", detail.status],
      ["Thread", detail.thread_id || "—"],
      ["Trace", detail.trace_id || "—"],
      ["Principal", detail.principal],
      ["Integrity", detail.integrity],
      ["Cost", money(detail.cost_usd)]
    ].forEach(([label, value]) => {
      const item = element("div");
      item.append(element("dt", "", label), element("dd", "", value));
      meta.append(item);
    });
    const timeline = element("ol", "detail-timeline");
    detail.events.forEach((event) => {
      const item = element("li");
      const title = event.decision
        ? `${event.decision.effect} · ${event.decision.rule_id}`
        : event.execution
          ? `${event.tool} · ${event.execution.duration_ms} ms · exit ${event.execution.exit_code}`
          : event.type === "model_call"
            ? `model call · ${event.summary?.duration_ms ?? "—"} ms · ${money(event.summary?.cost_delta)}`
          : event.type.replaceAll("_", " ");
      item.append(
        element("strong", "", title),
        element("small", "", `${event.tool_call_id || shortId(event.event_id, 12)} · ${elapsed(event.ts)}`)
      );
      timeline.append(item);
    });
    body.append(meta, timeline);
  } catch (error) {
    body.replaceChildren(element("p", "empty-state danger-text", error.message));
  }
}

function connectEvents() {
  eventStream?.close();
  window.clearTimeout(reconnectTimer);
  eventStream = new EventSource("/dashboard/api/events");
  eventStream.addEventListener("open", () => {
    setText("connection-state", "Live stream");
  });
  eventStream.addEventListener("live", (event) => renderLive(JSON.parse(event.data)));
  eventStream.addEventListener("snapshot", (event) => {
    const data = JSON.parse(event.data);
    renderSnapshot(data);
  });
  eventStream.onerror = () => {
    eventStream.close();
    setText("connection-state", "Reconnecting");
    reconnectTimer = window.setTimeout(connectEvents, 4000);
  };
}

byId("proposal-form")?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const feedback = byId("proposal-feedback");
  const payload = {
    environment: form.get("environment"),
    capability: form.get("capability"),
    targets: String(form.get("targets") || "").split(",").map((item) => item.trim()).filter(Boolean),
    reason: form.get("reason"),
    ttl_s: Number(form.get("ttl_s")),
    max_executions: Number(form.get("max_executions")),
    require_dry_run: true
  };
  try {
    await mutation("/dashboard/api/config/proposals", payload);
    feedback.textContent = "Proposal created and awaiting approval.";
    event.currentTarget.reset();
    await refresh();
  } catch (error) {
    feedback.textContent = error.message;
  }
});

byId("sign-out-button")?.addEventListener("click", async () => {
  await mutation("/dashboard/logout");
  window.location.assign("/dashboard/login");
});
byId("close-run-detail")?.addEventListener("click", () => {
  byId("run-detail").classList.remove("is-open");
  byId("run-detail").setAttribute("aria-hidden", "true");
});
byId("refresh-button")?.addEventListener("click", refresh);
document.addEventListener("visibilitychange", () => {
  if (!document.hidden && eventStream?.readyState === EventSource.CLOSED) connectEvents();
});

refresh();
connectEvents();
