# Cloud write packs + dashboard grant wizard — design

Date: 2026-07-27  
Status: approved for implementation

## Cloud write packs

Decisions: broader safe-ops surface (kubectl-mutate style); staging+prod; hybrid dry-run
(allow with `--dry-run`/`--dryrun` when present; escalate when absent).

- Packs: `aws-write.yaml`, `gcloud-write.yaml`, `az-write.yaml` — `channel: rw`
- Creds: `CloudTarget.credential_env_rw`; executor selects by channel; `_RW_BOOT_GATED_FAMILIES`
  includes `aws`, `gcloud`, `az` (gh pattern — RO-only deploys must set rw creds or remove packs)
- Base secret/IAM denies remain; write packs do not allow IAM/secret/datastore destroy
- Grants `aws_deploy` / `gcp_deploy` / `azure_deploy` already map via `capability_for_family`

## Grant wizard

Multi-step Change control panel: Propose → Approve → Activate.

- Expose loop limits (per-run, identical, failures, cooldown)
- Richer proposal cards (reason, actors, id)
- Role-gated step chrome; reuse existing APIs
