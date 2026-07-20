#!/usr/bin/env bash
#
# verify-secrets-denied.sh — assert the generated kubeconfigs enforce the credential-layer
# invariants for every context they contain.
#
#   read-only kubeconfig (AGENT_KUBECONFIG, default ~/.kube/agent-view.yaml):
#     - `auth can-i get secrets` == no   (denied — the view role excludes Secrets)
#     - `auth can-i get pods`    == yes  (allowed — sanity that the view binding took)
#
#   read-write kubeconfig (MUTATE_KUBECONFIG, default ~/.kube/agent-mutate.yaml), checked ONLY
#   if the file exists:
#     - `auth can-i get secrets`                         == no   (mutate role has no Secrets)
#     - `auth can-i patch deployments -n $MUTATE_NAMESPACE` == yes (the mutate binding took)
#
# This enforces the "even a total policy bypass is read-only-no-secrets (ro) / no-secrets,
# no-delete (rw)" invariant (PLAN.md §1) at the credential layer. Run it against every target
# cluster after gen-kubeconfig.sh, and in CI/bootstrap before the first live run. Any deviation
# exits 1 with a loud message.
#
# Usage:
#   ops/k8s/verify-secrets-denied.sh
#   AGENT_KUBECONFIG=/path/to/agent-view.yaml ops/k8s/verify-secrets-denied.sh
#   MUTATE_NAMESPACE=web ops/k8s/verify-secrets-denied.sh          # verify rw kubeconfig too

set -euo pipefail

readonly KCFG="${AGENT_KUBECONFIG:-$HOME/.kube/agent-view.yaml}"
readonly MUTATE_KCFG="${MUTATE_KUBECONFIG:-$HOME/.kube/agent-mutate.yaml}"
readonly MUTATE_NAMESPACE="${MUTATE_NAMESPACE:-target-namespace}"

if [[ ! -f "$KCFG" ]]; then
  echo "ERROR: kubeconfig not found: $KCFG (run gen-kubeconfig.sh first)" >&2
  exit 1
fi

contexts="$(kubectl --kubeconfig "$KCFG" config get-contexts -o name)"
if [[ -z "$contexts" ]]; then
  echo "ERROR: no contexts in $KCFG" >&2
  exit 1
fi

failures=0

echo "== read-only kubeconfig: $KCFG =="
while IFS= read -r ctx; do
  [[ -z "$ctx" ]] && continue
  echo ">> context: $ctx"

  # Secrets MUST be denied.
  secrets_ans="$(kubectl --kubeconfig "$KCFG" --context "$ctx" \
    auth can-i get secrets 2>/dev/null || true)"
  if [[ "$secrets_ans" == "yes" ]]; then
    echo "   !! FAIL: 'get secrets' is ALLOWED for context '$ctx' — invariant violated!" >&2
    failures=$((failures + 1))
  else
    echo "   ok: 'get secrets' denied ($secrets_ans)"
  fi

  # Pods MUST be allowed (sanity that the view role binding is effective).
  pods_ans="$(kubectl --kubeconfig "$KCFG" --context "$ctx" \
    auth can-i get pods 2>/dev/null || true)"
  if [[ "$pods_ans" != "yes" ]]; then
    echo "   !! FAIL: 'get pods' is NOT allowed for context '$ctx' — view binding missing?" >&2
    failures=$((failures + 1))
  else
    echo "   ok: 'get pods' allowed"
  fi
done <<<"$contexts"

# --- read-write kubeconfig (P2): checked only when present ---------------------------------
if [[ -f "$MUTATE_KCFG" ]]; then
  mutate_contexts="$(kubectl --kubeconfig "$MUTATE_KCFG" config get-contexts -o name)"
  if [[ -z "$mutate_contexts" ]]; then
    echo "ERROR: no contexts in $MUTATE_KCFG" >&2
    exit 1
  fi
  echo
  echo "== read-write kubeconfig: $MUTATE_KCFG (ns: $MUTATE_NAMESPACE) =="
  while IFS= read -r ctx; do
    [[ -z "$ctx" ]] && continue
    echo ">> context: $ctx"

    # Secrets MUST be denied even with the mutate identity.
    m_secrets_ans="$(kubectl --kubeconfig "$MUTATE_KCFG" --context "$ctx" \
      auth can-i get secrets 2>/dev/null || true)"
    if [[ "$m_secrets_ans" == "yes" ]]; then
      echo "   !! FAIL: rw 'get secrets' is ALLOWED for context '$ctx' — invariant violated!" >&2
      failures=$((failures + 1))
    else
      echo "   ok: rw 'get secrets' denied ($m_secrets_ans)"
    fi

    # Patching Deployments in the target namespace MUST be allowed (mutate binding took).
    patch_ans="$(kubectl --kubeconfig "$MUTATE_KCFG" --context "$ctx" \
      auth can-i patch deployments -n "$MUTATE_NAMESPACE" 2>/dev/null || true)"
    if [[ "$patch_ans" != "yes" ]]; then
      echo "   !! FAIL: rw 'patch deployments -n $MUTATE_NAMESPACE' NOT allowed for '$ctx' —" >&2
      echo "            mutate Role/RoleBinding missing in that namespace?" >&2
      failures=$((failures + 1))
    else
      echo "   ok: rw 'patch deployments -n $MUTATE_NAMESPACE' allowed"
    fi
  done <<<"$mutate_contexts"
else
  echo
  echo "(no rw kubeconfig at $MUTATE_KCFG — skipping read-write checks)"
fi

echo
if [[ "$failures" -ne 0 ]]; then
  echo "SECRETS-DENIED VERIFICATION FAILED ($failures problem(s)). DO NOT run the agent." >&2
  exit 1
fi
echo "OK: every context denies 'get secrets' (ro allows 'get pods'; rw allows 'patch deployments')."
