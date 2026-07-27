"use strict";

type NullableNumber = number | null | undefined;
type ChatThreadStatus = "idle" | "running" | "awaiting_approval";
type ChatRole = "user" | "assistant" | "activity" | "system";
type ApprovalDecision = "approve" | "reject";
type ProposalAction = "approve" | "activate" | "revoke";

interface DashboardOverview {
  runs_today: number;
  active_runs: number;
  success_rate: number | null;
  cost_today_usd: number;
  daily_budget_usd: number;
  audit_verified: number;
  audit_failed: number;
}

interface DailyActivity {
  date: string;
  runs: number;
  cost_usd: number;
}

interface PolicySummary {
  decisions: number;
  executions: number;
  denials: number;
  escalations: number;
}

interface TimelineEvent {
  event_id: string;
  type: string;
  ts: string;
  effect: string | null;
  rule_id: string | null;
  tool: string | null;
  exit_code: number | null;
}

interface RunSummary {
  run_id: string;
  status: string;
  events: number;
  principal: string;
  interface: string;
  environment: string;
  decisions: number;
  denials: number;
  executions: number;
  model_calls: number;
  escalations: number;
  cost_usd: number;
  updated_at: string | null;
  integrity: string;
}

interface PendingApproval {
  thread_id: string;
  run_id: string;
  environment: string;
  requester: string;
}

interface LiveSnapshot {
  active_runs?: Array<Record<string, unknown>>;
  pending_approvals?: PendingApproval[];
  queue_depth?: number;
  worker_active?: number;
  workers?: number;
  executor_errors?: number;
  queue_latency_ms?: number | null;
}

interface ServiceIndicators {
  run_success_percent?: NullableNumber;
  queue_latency_ms?: NullableNumber;
  policy_latency_ms?: NullableNumber;
  executor_error_percent?: NullableNumber;
  audit_lag_seconds?: NullableNumber;
  budget_utilization_percent?: NullableNumber;
}

interface CapabilityRequest {
  capability: string;
  environment: string;
  targets: string[];
  reason?: string;
  ttl_s?: number | null;
  max_executions: number;
  max_executions_per_run?: number;
  max_identical_per_run?: number;
  max_consecutive_failures?: number;
  cooldown_s?: number;
  require_dry_run?: boolean;
}

interface ActionIdentity {
  kind?: string;
  principal?: string;
  issuer?: string;
  subject?: string;
  email?: string | null;
  name?: string | null;
}

interface CapabilityProposal {
  proposal_id: string;
  status: string;
  expires_at: string;
  created_at?: string;
  request: CapabilityRequest;
  requester?: ActionIdentity;
  approver?: ActionIdentity | null;
  activated_by?: ActionIdentity | null;
  executions_used?: number;
}

type GrantWizardStep = "propose" | "approve" | "activate";

let grantWizardStep: GrantWizardStep = "propose";
let cachedProposals: CapabilityProposal[] = [];

interface ControlPlaneSnapshot {
  revision?: string;
  proposals?: CapabilityProposal[];
  items?: CapabilityProposal[];
}

interface Integration {
  name: string;
  state: string;
  detail: string;
}

interface RuntimeSummary {
  executor_mode: string;
  model: string | null;
  policy_version: string | null;
}

interface DashboardSnapshot {
  overview: DashboardOverview;
  daily: DailyActivity[];
  policy: PolicySummary;
  latest_timeline: TimelineEvent[];
  status_counts: Record<string, number>;
  runs: RunSummary[];
  integrations: Integration[];
  runtime: RuntimeSummary;
  slis: ServiceIndicators;
  generated_at: string;
  identity?: { roles?: string[] };
  live?: LiveSnapshot;
  control_plane?: ControlPlaneSnapshot;
}

interface ChatThread {
  thread_id: string;
  title: string;
  environment: "staging" | "prod";
  status: ChatThreadStatus;
  updated_at: string;
  last_run_id: string | null;
  message_count: number;
}

interface ChatMessage {
  role: ChatRole;
  content: string;
  created_at: string;
}

interface ChatThreadListResponse {
  items: ChatThread[];
}

interface ChatThreadResponse {
  thread: ChatThread;
  messages: ChatMessage[];
}

interface ChatSsePayload {
  text?: string;
  detail?: string;
  final_text?: string;
  run_id?: string;
  status?: string;
  cost_usd?: number;
}

interface RunDetailEvent {
  event_id: string;
  type: string;
  ts: string;
  tool_call_id: string | null;
  tool: string | null;
  decision: { effect: string; rule_id: string } | null;
  execution: { duration_ms: number; exit_code: number } | null;
  summary: { duration_ms?: number; cost_delta?: number } | null;
}

interface RunDetail {
  run_id: string;
  status: string;
  thread_id: string | null;
  trace_id: string | null;
  principal: string;
  integrity: string;
  cost_usd: number;
  events: RunDetailEvent[];
}

interface ApiError {
  detail?: string;
}

interface AppendChatOptions {
  live?: boolean;
}

interface LoadChatOptions {
  selectFirst?: boolean;
}

interface ParsedSseEvent {
  event: string;
  data: ChatSsePayload;
}

function byId<T extends HTMLElement = HTMLElement>(id: string): T {
  const node = document.getElementById(id);
  if (node === null) throw new Error(`required dashboard element #${id} is missing`);
  return node as T;
}

function metaContent(name: string): string {
  return document.querySelector<HTMLMetaElement>(`meta[name="${name}"]`)?.content ?? "";
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "The request could not be completed.";
}

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}

const csrfToken = metaContent("csrf-token");
const chatEnabled = metaContent("chat-enabled") === "true";
let eventStream: EventSource | null = null;
let reconnectTimer: number | undefined;
let currentRoles = new Set<string>();
let chatThreads: ChatThread[] = [];
let activeChatThread: ChatThread | null = null;
let activeChatController: AbortController | null = null;
let liveAssistantEntry: HTMLElement | null = null;
let chatSyncing = false;

const statusVocabulary = new Set<string>([
  "completed", "running", "awaiting_approval", "refused", "error",
  "cancelled", "recursion", "corrupt", "configured", "blocked", "not_configured",
  "pending", "approved", "active", "rejected", "revoked", "expired", "idle"
]);

function statusClass(value: string): string {
  return statusVocabulary.has(value) ? value.replaceAll("_", "-") : "unknown";
}

function money(value: NullableNumber): string {
  const amount = Number(value || 0);
  return amount < 0.01 ? `$${amount.toFixed(4)}` : `$${amount.toFixed(2)}`;
}

function compactNumber(value: number): string {
  return new Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 }).format(value || 0);
}

function countLabel(value: number, singular: string, plural = `${singular}s`): string {
  return `${value} ${value === 1 ? singular : plural}`;
}

function elapsed(iso: string | null | undefined): string {
  if (!iso) return "—";
  const seconds = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

function shortId(value: string | null | undefined, size = 8): string {
  if (!value) return "—";
  return value.length > size ? `${value.slice(0, size)}…` : value;
}

function setText(id: string, value: string | number): void {
  const node = byId(id);
  node.textContent = String(value);
}

function element<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className = "",
  text?: string,
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function renderOverview(data: DashboardSnapshot): void {
  const overview = data.overview;
  setText("runs-today", compactNumber(overview.runs_today));
  setText("active-runs", compactNumber(overview.active_runs));
  setText("success-rate", overview.success_rate === null ? "No runs" : `${overview.success_rate}%`);
  setText("cost-today", money(overview.cost_today_usd));
  setText("budget-caption", `of ${money(overview.daily_budget_usd)}`);
  const budgetPercent = overview.daily_budget_usd > 0
    ? Math.min(100, overview.cost_today_usd / overview.daily_budget_usd * 100)
    : 0;
  byId<HTMLElement>("budget-used").style.width = `${budgetPercent}%`;
  setText("audit-health", compactNumber(overview.audit_verified));
  setText("audit-failed", overview.audit_failed);
  setText("path-intent", `${overview.runs_today} today`);
  setText("path-audit", `${overview.audit_verified} chains verified`);
}

function renderActivity(days: DailyActivity[]): void {
  const chart = byId<HTMLElement>("activity-chart");
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

function renderPolicy(data: DashboardSnapshot): void {
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

function renderStatusSummary(counts: Record<string, number>): void {
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

function renderRuns(runs: RunSummary[]): void {
  const body = byId<HTMLTableSectionElement>("run-rows");
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
    row.addEventListener("keydown", (event: KeyboardEvent) => {
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

function renderLive(live: LiveSnapshot = {}): void {
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

function sliValue(value: NullableNumber, suffix: string, digits = 1): string {
  return value === null || value === undefined ? "—" : `${Number(value).toFixed(digits)}${suffix}`;
}

function renderSlis(slis: ServiceIndicators = {}): void {
  setText("sli-run-success", sliValue(slis.run_success_percent, "%"));
  setText("sli-queue-latency", sliValue(slis.queue_latency_ms, " ms", 0));
  setText("sli-policy-latency", sliValue(slis.policy_latency_ms, " ms", 1));
  setText("sli-executor-errors", sliValue(slis.executor_error_percent, "%"));
  setText("sli-audit-lag", sliValue(slis.audit_lag_seconds, " s", 0));
  setText("sli-budget-used", sliValue(slis.budget_utilization_percent, "%"));
}

function identityLabel(identity: ActionIdentity | null | undefined): string {
  if (!identity) return "—";
  return identity.email || identity.name || identity.principal || identity.subject || "—";
}

function setGrantWizardStep(step: GrantWizardStep): void {
  grantWizardStep = step;
  document.querySelectorAll<HTMLButtonElement>(".grant-step").forEach((button) => {
    button.classList.toggle("is-active", button.dataset["step"] === step);
  });
  const form = byId<HTMLFormElement>("proposal-form");
  form.classList.toggle("is-hidden-step", step !== "propose");
  const canPropose = currentRoles.has("operator") || currentRoles.has("admin");
  byId<HTMLButtonElement>("propose-submit").disabled = !canPropose;
  const titles: Record<GrantWizardStep, [string, string]> = {
    propose: ["All proposals", "Newest first — draft a grant on the left"],
    approve: ["Awaiting approval", "Pending proposals ready for an independent approver"],
    activate: ["Ready to activate", "Approved grants waiting for admin activation, plus active ones"],
  };
  const [title, hint] = titles[step];
  setText("proposal-board-title", title);
  setText("proposal-board-hint", hint);
  renderProposals();
}

function proposalsForStep(proposals: CapabilityProposal[]): CapabilityProposal[] {
  if (grantWizardStep === "approve") {
    return proposals.filter((item) => item.status === "pending");
  }
  if (grantWizardStep === "activate") {
    return proposals.filter((item) => item.status === "approved" || item.status === "active");
  }
  return proposals;
}

function renderProposals(control: ControlPlaneSnapshot = {}): void {
  if (control.revision) {
    const revision = control.revision;
    setText("control-revision", `revision ${shortId(revision.replace("sha256:", ""), 10)}`);
  }
  if (control.proposals || control.items) {
    cachedProposals = control.proposals || control.items || [];
  }
  const list = byId("proposal-list");
  list.replaceChildren();
  const proposals = proposalsForStep(cachedProposals);
  if (!proposals.length) {
    const empty =
      grantWizardStep === "approve"
        ? "No proposals awaiting approval."
        : grantWizardStep === "activate"
          ? "No approved or active grants."
          : "No capability changes have been proposed.";
    list.append(element("p", "empty-state", empty));
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
    const meta = element("div", "proposal-meta");
    meta.append(
      element("p", "", `${request.environment} · ${request.targets.join(", ")}`),
      element("p", "proposal-reason", request.reason || "No reason provided"),
      element(
        "small",
        "",
        [
          `id ${shortId(proposal.proposal_id, 10)}`,
          `${request.max_executions} executions`,
          request.max_executions_per_run != null
            ? `${request.max_executions_per_run}/run`
            : null,
          request.require_dry_run === false ? "dry-run optional" : "dry-run required",
          `expires ${elapsed(proposal.expires_at)}`,
          `by ${identityLabel(proposal.requester)}`,
        ]
          .filter(Boolean)
          .join(" · ")
      )
    );
    if (proposal.approver) {
      meta.append(element("small", "", `approved by ${identityLabel(proposal.approver)}`));
    }
    if (proposal.activated_by) {
      meta.append(element("small", "", `activated by ${identityLabel(proposal.activated_by)}`));
    }
    card.append(heading, meta);
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

function renderIntegrations(integrations: Integration[]): void {
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

function renderRuntime(runtime: RuntimeSummary): void {
  setText("runtime-executor", runtime.executor_mode);
  setText("runtime-model", runtime.model ? (runtime.model.split(":").at(-1) ?? "—") : "—");
  setText("runtime-policy", runtime.policy_version ? shortId(runtime.policy_version.replace("sha256:", ""), 10) : "not observed");
}

function renderSnapshot(data: DashboardSnapshot): void {
  if (data.identity?.roles) currentRoles = new Set(data.identity.roles);
  configureChatAccess();
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
  else renderProposals();
  setGrantWizardStep(grantWizardStep);
  setText("connection-state", "Connected");
  setText("last-refresh", `Updated ${elapsed(data.generated_at)}`);
  setText("snapshot-id", `Snapshot · ${data.generated_at.replace("T", " ").slice(0, 19)} UTC`);
  document.body.classList.remove("connection-error");
}

async function refresh(): Promise<void> {
  const button = byId<HTMLButtonElement>("refresh-button");
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
    renderSnapshot(await response.json() as DashboardSnapshot);
  } catch (error) {
    setText("connection-state", "Snapshot unavailable");
    setText("last-refresh", "Retrying automatically");
    document.body.classList.add("connection-error");
  } finally {
    button?.classList.remove("is-refreshing");
    if (button) button.disabled = false;
  }
}

async function mutation<T = Record<string, unknown>>(
  url: string,
  body: unknown = {},
): Promise<T> {
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
  const payload = await response.json().catch(() => ({})) as T & ApiError;
  if (!response.ok) throw new Error(payload.detail || `request returned ${response.status}`);
  return payload;
}

function canUseChat(): boolean {
  return chatEnabled && (currentRoles.has("operator") || currentRoles.has("admin"));
}

function configureChatAccess(): void {
  const allowed = canUseChat();
  setText("chat-access-note", allowed ? "OIDC attributed" : "Operator access required");
  byId<HTMLButtonElement>("new-chat-button").disabled = !allowed;
  byId<HTMLSelectElement>("chat-environment").disabled = !allowed;
  updateChatControls();
  if (!allowed) {
    byId("chat-thread-list").replaceChildren(
      element("p", "chat-list-empty", "Your role can observe runs, but cannot start agent turns.")
    );
  }
}

function updateChatControls(): void {
  const allowed = canUseChat();
  const busy = Boolean(activeChatController) || activeChatThread?.status === "running";
  const awaiting = activeChatThread?.status === "awaiting_approval";
  const input = byId<HTMLTextAreaElement>("chat-input");
  const send = byId<HTMLButtonElement>("send-chat-button");
  const stop = byId<HTMLButtonElement>("stop-chat-button");
  input.disabled = !allowed || busy || awaiting;
  send.disabled = !allowed || busy || awaiting;
  stop.classList.toggle("is-hidden", !busy);
  stop.disabled = !busy;
  setText(
    "chat-thread-status",
    activeChatThread?.status?.replaceAll("_", " ") || "idle"
  );
  const status = byId("chat-thread-status");
  status.className = `status-pill ${statusClass(activeChatThread?.status || "idle")}`;
}

function chatTime(value: string | null | undefined): string {
  if (!value) return "now";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? "now"
    : date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function appendChatEntry(
  message: ChatMessage,
  { live = false }: AppendChatOptions = {},
): HTMLElement {
  const transcript = byId("chat-transcript");
  transcript.querySelector(".chat-empty-state")?.remove();
  const entry = element("article", `chat-entry ${message.role}`);
  if (live) entry.dataset["liveAssistant"] = "true";
  const marker = element(
    "span",
    "chat-entry-marker",
    message.role === "assistant" ? "OD" : message.role === "user" ? "YOU" : ""
  );
  marker.setAttribute("aria-hidden", "true");
  const body = element("div", "chat-entry-body");
  const label = element("div", "chat-entry-label");
  const roleLabel = message.role === "assistant"
    ? "Agent response"
    : message.role === "user"
      ? "Your request"
      : message.role === "system"
        ? "Run notice"
        : "Control plane";
  label.append(
    element("strong", "", roleLabel),
    element("time", "", chatTime(message.created_at))
  );
  const content = element("p", "chat-entry-content", message.content);
  body.append(label, content);
  entry.append(marker, body);
  transcript.append(entry);
  transcript.scrollTop = transcript.scrollHeight;
  return entry;
}

function wireStarterPrompts(): void {
  document.querySelectorAll<HTMLButtonElement>("[data-chat-prompt]").forEach((button) => {
    button.addEventListener("click", () => {
      const input = byId<HTMLTextAreaElement>("chat-input");
      input.value = button.dataset["chatPrompt"] ?? "";
      input.focus();
    });
  });
}

function renderChatWelcome(): void {
  const empty = element("div", "chat-empty-state");
  const mark = element("span", "chat-signal-mark", "OD");
  mark.setAttribute("aria-hidden", "true");
  const copy = element("div");
  copy.append(
    element("h3", "", "Start with an operational question"),
    element(
      "p",
      "",
      "The agent can inspect configured cloud, Kubernetes, GitHub, and SSH targets. " +
      "Tool arguments and raw output stay out of this view."
    )
  );
  const prompts = element("div", "starter-prompts");
  prompts.setAttribute("aria-label", "Suggested prompts");
  const suggestions: Array<readonly [string, string]> = [
    ["Summarize infrastructure health", "Summarize the health of my infrastructure and highlight anything requiring attention."],
    ["Trace recent production changes", "What changed recently in production, and are there related failures?"],
    ["Investigate the top incident", "Find the likely cause of the highest-impact active incident."]
  ];
  suggestions.forEach(([label, prompt]) => {
    const button = element("button", "", label);
    button.type = "button";
    button.dataset["chatPrompt"] = prompt;
    prompts.append(button);
  });
  empty.append(mark, copy, prompts);
  byId("chat-transcript").replaceChildren(empty);
  wireStarterPrompts();
}

function renderChatThreads(): void {
  const list = byId("chat-thread-list");
  list.replaceChildren();
  if (!chatThreads.length) {
    list.append(
      element("p", "chat-list-empty", "No investigations yet. Start one from this command channel.")
    );
    return;
  }
  chatThreads.forEach((thread) => {
    const button = element(
      "button",
      `chat-thread-item${thread.thread_id === activeChatThread?.thread_id ? " is-active" : ""}`
    );
    button.type = "button";
    const meta = element("span");
    meta.append(
      element("small", "", thread.environment),
      element("small", "", elapsed(thread.updated_at))
    );
    button.append(element("strong", "", thread.title), meta);
    button.addEventListener("click", () => loadChatThread(thread.thread_id));
    list.append(button);
  });
}

function renderActiveChat(thread: ChatThread, messages: ChatMessage[]): void {
  activeChatThread = thread;
  liveAssistantEntry = null;
  setText("chat-thread-title", thread.title);
  setText(
    "chat-thread-meta",
    `${thread.environment} · ${shortId(thread.thread_id, 12)} · ${thread.message_count} transcript events`
  );
  const transcript = byId("chat-transcript");
  transcript.replaceChildren();
  if (messages.length) {
    messages.forEach((message) => appendChatEntry(message));
  } else {
    renderChatWelcome();
  }
  renderChatThreads();
  updateChatControls();
}

async function chatJson<T>(url: string): Promise<T> {
  const response = await fetch(url, {
    credentials: "same-origin",
    headers: { Accept: "application/json" }
  });
  if (response.status === 401) {
    window.location.assign("/dashboard/login");
    throw new Error("session expired");
  }
  const payload = await response.json().catch(() => ({})) as T & ApiError;
  if (!response.ok) throw new Error(payload.detail || `request returned ${response.status}`);
  return payload;
}

async function loadChatThread(threadId: string): Promise<void> {
  if (!canUseChat()) return;
  try {
    const payload = await chatJson<ChatThreadResponse>(
      `/dashboard/api/chat/threads/${encodeURIComponent(threadId)}`
    );
    renderActiveChat(payload.thread, payload.messages);
  } catch (error) {
    setText("chat-feedback", errorMessage(error));
  }
}

async function loadChatThreads(
  { selectFirst = true }: LoadChatOptions = {},
): Promise<void> {
  if (!canUseChat()) return;
  try {
    const payload = await chatJson<ChatThreadListResponse>("/dashboard/api/chat/threads");
    chatThreads = payload.items || [];
    const current = chatThreads.find(
      (thread) => thread.thread_id === activeChatThread?.thread_id
    );
    const first = chatThreads[0];
    if (current) activeChatThread = current;
    renderChatThreads();
    if (current) {
      await loadChatThread(current.thread_id);
    } else if (selectFirst && first !== undefined) {
      await loadChatThread(first.thread_id);
    } else if (!chatThreads.length) {
      activeChatThread = null;
      setText("chat-thread-title", "New investigation");
      setText("chat-thread-meta", "Choose an environment and send a question.");
      renderChatWelcome();
      updateChatControls();
    }
  } catch (error) {
    byId("chat-thread-list").replaceChildren(
      element("p", "chat-list-empty danger-text", errorMessage(error))
    );
  }
}

async function createChatThread(): Promise<ChatThread> {
  const environment = byId<HTMLSelectElement>("chat-environment").value;
  const thread = await mutation<ChatThread>("/dashboard/api/chat/threads", { environment });
  chatThreads = [thread, ...chatThreads.filter((item) => item.thread_id !== thread.thread_id)];
  renderActiveChat(thread, []);
  return thread;
}

function parseSseBlock(block: string): ParsedSseEvent | null {
  let eventName = "message";
  const data: string[] = [];
  block.split(/\r?\n/).forEach((line) => {
    if (line.startsWith("event:")) eventName = line.slice(6).trim();
    if (line.startsWith("data:")) data.push(line.slice(5).trimStart());
  });
  if (!data.length) return null;
  return { event: eventName, data: JSON.parse(data.join("\n")) as ChatSsePayload };
}

async function consumeSse(
  response: Response,
  onEvent: (eventName: string, data: ChatSsePayload) => void,
): Promise<void> {
  if (!response.ok) {
    const payload = await response.json().catch(() => ({})) as ApiError;
    throw new Error(payload.detail || `chat returned ${response.status}`);
  }
  if (!response.body) throw new Error("chat stream was not available");
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  while (true) {
    const { value, done } = await reader.read();
    buffer += decoder.decode(value || new Uint8Array(), { stream: !done });
    const blocks = buffer.split(/\r?\n\r?\n/);
    buffer = blocks.pop() || "";
    blocks.forEach((block) => {
      const parsed = parseSseBlock(block);
      if (parsed) onEvent(parsed.event, parsed.data);
    });
    if (done) break;
  }
  if (buffer.trim()) {
    const parsed = parseSseBlock(buffer);
    if (parsed) onEvent(parsed.event, parsed.data);
  }
}

function handleChatEvent(eventName: string, data: ChatSsePayload): void {
  if (eventName === "assistant") {
    if (!liveAssistantEntry) {
      liveAssistantEntry = appendChatEntry(
        {
          role: "assistant",
          content: data.text ?? "",
          created_at: new Date().toISOString(),
        },
        { live: true }
      );
    } else {
      const content = liveAssistantEntry.querySelector<HTMLElement>(".chat-entry-content");
      if (content !== null) content.textContent = data.text ?? "";
    }
  } else if (eventName === "activity") {
    appendChatEntry({
      role: "activity",
      content: data.text ?? "Tool activity updated.",
      created_at: new Date().toISOString()
    });
  } else if (eventName === "approval") {
    appendChatEntry({
      role: "activity",
      content: data.text ?? "Approval required.",
      created_at: new Date().toISOString()
    });
    setText("chat-feedback", "Waiting for an approver in Live control.");
  } else if (eventName === "done") {
    if (data.final_text) {
      if (!liveAssistantEntry) {
        liveAssistantEntry = appendChatEntry({
          role: "assistant",
          content: data.final_text,
          created_at: new Date().toISOString()
        });
      } else {
        const content = liveAssistantEntry.querySelector<HTMLElement>(".chat-entry-content");
        if (content !== null) content.textContent = data.final_text;
      }
    }
    if (activeChatThread !== null) {
      activeChatThread.status = data.status === "awaiting_approval"
        ? "awaiting_approval"
        : "idle";
    }
    setText(
      "chat-feedback",
      data.status === "awaiting_approval"
        ? "Waiting for an independent approver in Live control."
        : `Run ${shortId(data.run_id, 10)} completed · ${money(data.cost_usd)}`
    );
  } else if (eventName === "error") {
    throw new Error(data.detail ?? "The agent run failed.");
  }
}

async function sendChatMessage(message: string): Promise<void> {
  if (!activeChatThread) await createChatThread();
  if (activeChatThread === null) throw new Error("chat thread could not be created");
  const threadId = activeChatThread.thread_id;
  appendChatEntry({
    role: "user",
    content: message,
    created_at: new Date().toISOString()
  });
  activeChatThread.status = "running";
  liveAssistantEntry = null;
  activeChatController = new AbortController();
  updateChatControls();
  setText("chat-feedback", "Agent is inspecting connected systems…");
  try {
    const response = await fetch(
      `/dashboard/api/chat/threads/${encodeURIComponent(threadId)}/messages`,
      {
        method: "POST",
        credentials: "same-origin",
        headers: {
          Accept: "text/event-stream",
          "Content-Type": "application/json",
          "X-CSRF-Token": csrfToken
        },
        body: JSON.stringify({ message }),
        signal: activeChatController.signal
      }
    );
    await consumeSse(response, handleChatEvent);
  } catch (error: unknown) {
    if (!isAbortError(error)) {
      activeChatThread.status = "idle";
      appendChatEntry({
        role: "system",
        content: errorMessage(error),
        created_at: new Date().toISOString()
      });
      setText("chat-feedback", errorMessage(error));
    }
  } finally {
    activeChatController = null;
    updateChatControls();
    await loadChatThreads({ selectFirst: false });
  }
}

async function syncAwaitingChat(): Promise<void> {
  if (chatSyncing || activeChatThread?.status !== "awaiting_approval") return;
  chatSyncing = true;
  try {
    await loadChatThread(activeChatThread.thread_id);
  } finally {
    chatSyncing = false;
  }
}

async function resolveApproval(threadId: string, type: ApprovalDecision): Promise<void> {
  try {
    await mutation(`/dashboard/api/approvals/${encodeURIComponent(threadId)}`, {
      decisions: [{ type, message: type === "reject" ? "rejected from dashboard" : undefined }]
    });
    await refresh();
    if (activeChatThread?.thread_id === threadId) await loadChatThread(threadId);
  } catch (error: unknown) {
    window.alert(errorMessage(error));
  }
}

async function proposalAction(proposalId: string, action: ProposalAction): Promise<void> {
  try {
    await mutation(
      `/dashboard/api/config/proposals/${encodeURIComponent(proposalId)}/${action}`
    );
    if (action === "approve" || action === "activate") setGrantWizardStep("activate");
    await refresh();
  } catch (error: unknown) {
    window.alert(errorMessage(error));
  }
}

async function openRunDetail(runId: string): Promise<void> {
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
    const detail = await response.json() as RunDetail;
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
  } catch (error: unknown) {
    body.replaceChildren(element("p", "empty-state danger-text", errorMessage(error)));
  }
}

function connectEvents(): void {
  eventStream?.close();
  window.clearTimeout(reconnectTimer);
  eventStream = new EventSource("/dashboard/api/events");
  eventStream.addEventListener("open", () => {
    setText("connection-state", "Live stream");
  });
  eventStream.addEventListener("live", (event: MessageEvent<string>) => {
    renderLive(JSON.parse(event.data) as LiveSnapshot);
  });
  eventStream.addEventListener("snapshot", (event: MessageEvent<string>) => {
    const data = JSON.parse(event.data) as DashboardSnapshot;
    renderSnapshot(data);
    void syncAwaitingChat();
  });
  eventStream.onerror = () => {
    eventStream?.close();
    setText("connection-state", "Reconnecting");
    reconnectTimer = window.setTimeout(connectEvents, 4000);
  };
}

byId<HTMLFormElement>("proposal-form").addEventListener("submit", async (event: SubmitEvent) => {
  event.preventDefault();
  const formElement = event.currentTarget as HTMLFormElement;
  const form = new FormData(formElement);
  const feedback = byId<HTMLElement>("proposal-feedback");
  const payload = {
    environment: form.get("environment"),
    capability: form.get("capability"),
    targets: String(form.get("targets") || "").split(",").map((item) => item.trim()).filter(Boolean),
    reason: form.get("reason"),
    ttl_s: Number(form.get("ttl_s")),
    max_executions: Number(form.get("max_executions")),
    max_executions_per_run: Number(form.get("max_executions_per_run")),
    max_identical_per_run: Number(form.get("max_identical_per_run")),
    max_consecutive_failures: Number(form.get("max_consecutive_failures")),
    cooldown_s: Number(form.get("cooldown_s")),
    require_dry_run: form.get("require_dry_run") === "on"
  };
  try {
    await mutation("/dashboard/api/config/proposals", payload);
    feedback.textContent = "Proposal created — continue to Approve.";
    formElement.reset();
    const dryRun = formElement.querySelector<HTMLInputElement>('input[name="require_dry_run"]');
    if (dryRun) dryRun.checked = true;
    setGrantWizardStep("approve");
    await refresh();
  } catch (error: unknown) {
    feedback.textContent = errorMessage(error);
  }
});

document.querySelectorAll<HTMLButtonElement>(".grant-step").forEach((button) => {
  button.addEventListener("click", () => {
    const step = button.dataset["step"] as GrantWizardStep | undefined;
    if (step) setGrantWizardStep(step);
  });
});

byId<HTMLButtonElement>("new-chat-button").addEventListener("click", async () => {
  try {
    await createChatThread();
    byId<HTMLTextAreaElement>("chat-input").focus();
  } catch (error: unknown) {
    setText("chat-feedback", errorMessage(error));
  }
});
byId<HTMLFormElement>("chat-form").addEventListener("submit", async (event: SubmitEvent) => {
  event.preventDefault();
  const input = byId<HTMLTextAreaElement>("chat-input");
  const message = input.value.trim();
  if (!message || input.disabled) return;
  input.value = "";
  await sendChatMessage(message);
});
byId<HTMLTextAreaElement>("chat-input").addEventListener(
  "keydown",
  (event: KeyboardEvent) => {
  if (event.key === "Enter" && (event.metaKey || event.ctrlKey)) {
    event.preventDefault();
    byId<HTMLFormElement>("chat-form").requestSubmit();
  }
  },
);
byId<HTMLButtonElement>("stop-chat-button").addEventListener("click", async () => {
  if (!activeChatThread) return;
  const threadId = activeChatThread.thread_id;
  activeChatController?.abort();
  try {
    await mutation(`/dashboard/api/chat/threads/${encodeURIComponent(threadId)}/cancel`);
    activeChatThread.status = "idle";
    setText("chat-feedback", "Run cancelled.");
  } catch (error: unknown) {
    setText("chat-feedback", errorMessage(error));
  } finally {
    updateChatControls();
    await loadChatThreads({ selectFirst: false });
  }
});
byId<HTMLButtonElement>("sign-out-button").addEventListener("click", async () => {
  await mutation("/dashboard/logout");
  window.location.assign("/dashboard/login");
});
byId<HTMLButtonElement>("close-run-detail").addEventListener("click", () => {
  byId("run-detail").classList.remove("is-open");
  byId("run-detail").setAttribute("aria-hidden", "true");
});
byId<HTMLButtonElement>("refresh-button").addEventListener("click", () => {
  void refresh();
});
document.addEventListener("visibilitychange", () => {
  if (!document.hidden && eventStream?.readyState === EventSource.CLOSED) connectEvents();
});

async function bootstrap(): Promise<void> {
  wireStarterPrompts();
  await refresh();
  await loadChatThreads();
  connectEvents();
}

void bootstrap();
