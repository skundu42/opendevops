"""gVisor / hardening manifests (P5d): parse ops/executor/*.yaml and assert every required field.

No live cluster — pure YAML parsing. Enforces the PLAN §3.5 hardening on EVERY executor Deployment
(gVisor runtimeClass, non-root, read-only rootfs, cap-drop ALL, seccomp RuntimeDefault, tmpfs
/work) and the egress NetworkPolicy (Egress policyType + IMDS 169.254.169.254/32 blocked).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

_MANIFEST_DIR = Path(__file__).resolve().parents[2] / "ops" / "executor"


def _load_all() -> list[dict[str, Any]]:
    docs: list[dict[str, Any]] = []
    for path in sorted(_MANIFEST_DIR.glob("*.yaml")):
        for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            if isinstance(doc, dict):
                doc["__file__"] = path.name
                docs.append(doc)
    return docs


def _by_kind(kind: str) -> list[dict[str, Any]]:
    return [d for d in _load_all() if d.get("kind") == kind]


def test_manifest_dir_exists_and_parses() -> None:
    assert _MANIFEST_DIR.is_dir()
    docs = _load_all()
    assert docs, "no YAML documents found under ops/executor/"
    # every file parses as valid YAML (safe_load_all already ran without raising)


def test_expected_deployments_present() -> None:
    names = {d["metadata"]["name"] for d in _by_kind("Deployment")}
    for env in ("staging", "prod"):
        for channel in ("ro", "rw"):
            assert f"opendevops-executor-{env}-{channel}" in names


@pytest.mark.parametrize("dep", _by_kind("Deployment"), ids=lambda d: d["metadata"]["name"])
def test_deployment_hardening_fields(dep: dict[str, Any]) -> None:
    pod = dep["spec"]["template"]["spec"]

    # gVisor sandbox
    assert pod.get("runtimeClassName") == "gvisor", "runtimeClassName must be gvisor"

    containers = pod["containers"]
    assert containers, "at least one container required"
    container = containers[0]
    pod_sc = pod.get("securityContext", {}) or {}
    csc = container.get("securityContext", {}) or {}

    # runAsNonRoot (pod or container level)
    assert pod_sc.get("runAsNonRoot") is True or csc.get("runAsNonRoot") is True

    # read-only root filesystem (container level)
    assert csc.get("readOnlyRootFilesystem") is True

    # cap-drop ALL
    drop = (csc.get("capabilities", {}) or {}).get("drop", [])
    assert "ALL" in drop, "capabilities.drop must include ALL"

    # seccomp RuntimeDefault (pod or container level)
    seccomp_types = {
        (pod_sc.get("seccompProfile", {}) or {}).get("type"),
        (csc.get("seccompProfile", {}) or {}).get("type"),
    }
    assert "RuntimeDefault" in seccomp_types, "seccompProfile must be RuntimeDefault"

    # no privilege escalation (defense in depth)
    assert csc.get("allowPrivilegeEscalation") is False

    # a tmpfs (emptyDir medium: Memory) mounted at /work
    work_mounts = [
        m for m in container.get("volumeMounts", []) if m.get("mountPath") == "/work"
    ]
    assert work_mounts, "a volume must be mounted at /work"
    work_vol_name = work_mounts[0]["name"]
    work_vols = [
        v
        for v in pod.get("volumes", [])
        if v.get("name") == work_vol_name and "emptyDir" in v
    ]
    assert work_vols, "/work must be backed by an emptyDir"
    assert work_vols[0]["emptyDir"].get("medium") == "Memory", "/work emptyDir must be tmpfs"


def test_ingress_networkpolicy_restricts_to_agent_workload() -> None:
    """Defense-in-depth: ingress to /execute is restricted to the agent workload (non-vacuous)."""
    policies = _by_kind("NetworkPolicy")
    assert policies, "a NetworkPolicy is required"
    ingress_policies = [p for p in policies if "Ingress" in p["spec"].get("policyTypes", [])]
    assert ingress_policies, "an Ingress restriction is required"
    policy = ingress_policies[0]
    ingress = policy["spec"].get("ingress", [])
    assert ingress, "ingress rules required (empty ingress + policyType Ingress would deny all)"
    # NON-VACUOUS: at least one rule must carry a from-selector (pod/namespace), NOT `from: []`
    # (which admits all). A rule with no `from` key at all also admits all — reject that too.
    has_restricting_selector = False
    for rule in ingress:
        froms = rule.get("from")
        if not froms:  # missing or empty -> allows all sources; not a restriction
            continue
        for peer in froms:
            if "podSelector" in peer or "namespaceSelector" in peer or "ipBlock" in peer:
                has_restricting_selector = True
    assert has_restricting_selector, "ingress must restrict sources via a pod/namespace/ip selector"


def test_egress_networkpolicy_blocks_imds() -> None:
    policies = _by_kind("NetworkPolicy")
    assert policies, "an egress NetworkPolicy is required"
    policy = next(p for p in policies if "Egress" in p["spec"].get("policyTypes", []))
    assert "Egress" in policy["spec"].get("policyTypes", [])

    # IMDS 169.254.169.254/32 must appear in some egress rule's ipBlock.except allowlist
    excepts: list[str] = []
    for rule in policy["spec"].get("egress", []):
        for to in rule.get("to", []):
            block = to.get("ipBlock", {})
            excepts.extend(block.get("except", []))
    assert "169.254.169.254/32" in excepts, "IMDS endpoint must be in the egress except list"

    # DNS egress is allowed (so name resolution still works under the default-deny)
    dns_ports = [
        p.get("port")
        for rule in policy["spec"].get("egress", [])
        for p in rule.get("ports", [])
    ]
    assert 53 in dns_ports
