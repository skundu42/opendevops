# Model-agnostic LLM providers — design

Date: 2026-07-27  
Status: implementing

## Decisions

- `models.yaml` gains optional `providers:` map keyed by provider id
- Each provider: `kind` (`anthropic` | `openai` | `openai_compatible` | `azure_openai` | `google` | `bedrock`) + credential env names + optional `base_url` / Azure / Bedrock fields
- Alias targets remain `provider_id:model_or_deployment`
- `build_chat_model` dispatches on `providers[id].kind` (default kind=id for anthropic/openai when providers omitted)
- Optional extras: `models-openai`, `models-google`, `models-bedrock` (lazy import; clear error if missing)
- Pricing rows still required per resolved model key; cache_* may be 0
- In-graph cost cap remains keyed to main model; gateway authoritative ledger already multi-key

## Out of scope

- Non-LangChain raw HTTP providers

## Follow-up (done)

- Per-call in-graph re-pricing for summarizer — see `2026-07-31-production-hardening-design.md`
  (`price_message` + Haiku summarizer flush into `run_cost_usd` / daily counter)
