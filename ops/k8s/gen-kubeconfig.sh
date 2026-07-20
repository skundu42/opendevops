#!/usr/bin/env bash
#
# gen-kubeconfig.sh — build the agent's scoped kubeconfig containing ONLY the contexts passed
# on the command line, each rewired to authenticate as an OpenDevOps ServiceAccount token from
# that cluster.
#
#   default (read-only): ~/.kube/agent-view.yaml   as `sa-agent-view`
#   --rw (read-write):   ~/.kube/agent-mutate.yaml as `sa-agent-mutate` (staging mutations)
#
# Design invariant (guides/security-model.md): the generated kubeconfig must offer nothing beyond the
# explicitly-allowed contexts — the `--context` allowlist rule cannot fire when `--context`
# is omitted, so the kubeconfig itself is the backstop. This script therefore starts from
# an EMPTY file and only ever adds the contexts named as arguments. This holds for both modes.
#
# Usage:
#   ops/k8s/gen-kubeconfig.sh [--rw] <context> [more contexts...]
#
# Prereqs (per target cluster):
#   read-only: kubectl apply -f ops/k8s/agent-view-rbac.yaml
#   --rw:      kubectl apply -f ops/k8s/agent-mutate-rbac.yaml   (+ per-namespace Role/RoleBinding)
# The current kubeconfig ($KUBECONFIG or ~/.kube/config) must have admin-ish access to the
# named contexts (to read the token Secret and the cluster server/CA).

set -euo pipefail

readonly SA_NAMESPACE="opendevops"

# Mode selection: default read-only; `--rw` (first arg) selects the mutate identity. The
# read-only path keeps the same secret, default output path, and cluster/user entry names in
# both modes, so existing ro workflows are unaffected.
MODE="ro"
if [[ "${1:-}" == "--rw" ]]; then
  MODE="rw"
  shift
fi

if [[ "$MODE" == "rw" ]]; then
  readonly SA_SECRET="sa-agent-mutate-token"
  readonly DEFAULT_OUT="$HOME/.kube/agent-mutate.yaml"
  readonly CLUSTER_PREFIX="agent-mutate"
  readonly USER_PREFIX="sa-agent-mutate"
else
  readonly SA_SECRET="sa-agent-view-token"
  readonly DEFAULT_OUT="$HOME/.kube/agent-view.yaml"
  readonly CLUSTER_PREFIX="agent-view"
  readonly USER_PREFIX="sa-agent-view"
fi
readonly OUT="${AGENT_KUBECONFIG:-$DEFAULT_OUT}"

if [[ $# -lt 1 ]]; then
  echo "usage: $0 [--rw] <context> [more contexts...]" >&2
  echo "  builds $OUT with ONLY the named contexts (${USER_PREFIX} identity)" >&2
  echo "  default: read-only sa-agent-view; --rw: read-write sa-agent-mutate" >&2
  exit 2
fi

# Portable base64 decode (GNU: -d / --decode; BSD/macOS: -D).
b64decode() {
  if base64 --decode </dev/null >/dev/null 2>&1; then
    base64 --decode
  else
    base64 -D
  fi
}

mkdir -p "$(dirname "$OUT")"
# Start from a clean slate so no previously-added context can survive.
rm -f "$OUT"
: >"$OUT"
chmod 600 "$OUT"

TMPDIR_CA="$(mktemp -d)"
cleanup() { rm -rf "$TMPDIR_CA"; }
trap cleanup EXIT

first_context=""

for ctx in "$@"; do
  echo ">> processing context: $ctx"

  # The source context must actually exist; refuse to invent one.
  src_cluster="$(kubectl config view --raw \
    -o "jsonpath={.contexts[?(@.name=='${ctx}')].context.cluster}")"
  if [[ -z "$src_cluster" ]]; then
    echo "ERROR: context '$ctx' not found in the current kubeconfig; refusing." >&2
    exit 1
  fi

  server="$(kubectl config view --raw \
    -o "jsonpath={.clusters[?(@.name=='${src_cluster}')].cluster.server}")"
  if [[ -z "$server" ]]; then
    echo "ERROR: could not determine API server for cluster '$src_cluster'." >&2
    exit 1
  fi

  ca_data="$(kubectl config view --raw \
    -o "jsonpath={.clusters[?(@.name=='${src_cluster}')].cluster.certificate-authority-data}")"
  ca_file_src="$(kubectl config view --raw \
    -o "jsonpath={.clusters[?(@.name=='${src_cluster}')].cluster.certificate-authority}")"

  ca_file=""
  if [[ -n "$ca_data" ]]; then
    ca_file="$TMPDIR_CA/${ctx//\//_}.ca.crt"
    printf '%s' "$ca_data" | b64decode >"$ca_file"
  elif [[ -n "$ca_file_src" ]]; then
    ca_file="$ca_file_src"
  fi

  # Read the long-lived ServiceAccount token from the target cluster.
  token_b64="$(kubectl --context "$ctx" -n "$SA_NAMESPACE" \
    get secret "$SA_SECRET" -o "jsonpath={.data.token}")"
  if [[ -z "$token_b64" ]]; then
    echo "ERROR: token Secret '$SA_SECRET' not populated in ns '$SA_NAMESPACE' for '$ctx'." >&2
    if [[ "$MODE" == "rw" ]]; then
      echo "       Did you apply ops/k8s/agent-mutate-rbac.yaml to this cluster?" >&2
    else
      echo "       Did you apply ops/k8s/agent-view-rbac.yaml to this cluster?" >&2
    fi
    exit 1
  fi
  token="$(printf '%s' "$token_b64" | b64decode)"

  cluster_entry="${CLUSTER_PREFIX}-${ctx}"
  user_entry="${USER_PREFIX}-${ctx}"

  if [[ -n "$ca_file" ]]; then
    kubectl config set-cluster "$cluster_entry" \
      --server="$server" \
      --certificate-authority="$ca_file" \
      --embed-certs=true \
      --kubeconfig="$OUT" >/dev/null
  else
    echo "WARN: no CA for '$src_cluster'; using --insecure-skip-tls-verify." >&2
    kubectl config set-cluster "$cluster_entry" \
      --server="$server" \
      --insecure-skip-tls-verify=true \
      --kubeconfig="$OUT" >/dev/null
  fi

  kubectl config set-credentials "$user_entry" \
    --token="$token" \
    --kubeconfig="$OUT" >/dev/null

  # Preserve the original context NAME so policy's --context allowlist matches on it.
  kubectl config set-context "$ctx" \
    --cluster="$cluster_entry" \
    --user="$user_entry" \
    --kubeconfig="$OUT" >/dev/null

  if [[ -z "$first_context" ]]; then
    first_context="$ctx"
  fi
done

kubectl config use-context "$first_context" --kubeconfig="$OUT" >/dev/null

echo
echo "Wrote $OUT with contexts: $*"
echo "current-context: $first_context"
if [[ "$MODE" == "rw" ]]; then
  echo "Next: MUTATE_NAMESPACE=<ns> ops/k8s/verify-secrets-denied.sh"
else
  echo "Next: ops/k8s/verify-secrets-denied.sh"
fi
