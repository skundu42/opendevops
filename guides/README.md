# opendevops guides

Start with [getting started](getting-started.md), then read in whatever order your question
demands:

| Guide | Answers |
|---|---|
| [Getting started](getting-started.md) | clone → configured → first live CLI session |
| [Architecture](architecture.md) | how one graph serves every frontend; middleware, tools, gateway seam, boot assertions |
| [Configuration](configuration.md) | every knob in `config.yaml` / `models.yaml` / `budgets.yaml` + the name-not-value convention |
| [Policy](policy.md) | the default-deny engine: pipeline, matchers, effects, packs, hooks, writing your own |
| [Security model](security-model.md) | the layered boundaries, what holds when policy fails, executor split, known limits |
| [Budgets](budgets.md) | every cost/step/time ceiling, who enforces it, and who counts the money |
| [Audit](audit.md) | per-run hash chains, event types, verification, shipping |
| [Interfaces](interfaces.md) | CLI REPL, authenticated dashboard, HTTP + webhooks, Slack chat-ops, scheduler, escalation flows |
| [Deployment](deployment.md) | service-mode stack, dashboard, monitoring, the experimental executor service, go-live gates |
| [Development](development.md) | test tiers, enforced conventions, the pinned-trio upgrade gate, how to extend |
