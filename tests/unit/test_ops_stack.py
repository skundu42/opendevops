"""docker-compose stack + ops config validation.

Two tiers, per the task brief:

* ``docker compose -f docker-compose.yml config -q`` — run IFF the docker CLI (with the compose v2
  plugin) is present, else skip WITH a reason. This is the real schema validation of the stack.
* Pure YAML/JSON lints that run everywhere (no docker needed): the vector / prometheus / alerts /
  grafana configs parse, the compose bind-mount sources exist on disk, and the metric component ids
  the Prometheus alerts key on match the ids Vector actually defines (config-drift guard).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
COMPOSE = REPO_ROOT / "docker-compose.yml"
OPS = REPO_ROOT / "ops"


def _docker_compose_available() -> bool:
    """True iff the docker CLI AND its compose v2 subcommand are usable."""
    if shutil.which("docker") is None:
        return False
    try:
        result = subprocess.run(
            ["docker", "compose", "version"],
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


# --------------------------------------------------------------------------------------
# docker compose config -q (real schema validation; skips if docker absent)
# --------------------------------------------------------------------------------------


def test_docker_compose_config_validates() -> None:
    if not _docker_compose_available():
        pytest.skip("docker CLI with the compose v2 plugin is not available on this host")
    result = subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE), "config", "-q"],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
        env={
            **os.environ,
            "POSTGRES_PASSWORD": "test-only-postgres-password",
            "GATEWAY_TOKEN": "test-only-gateway-token",
            "GRAFANA_ADMIN_PASSWORD": "test-only-grafana-password",
        },
    )
    assert result.returncode == 0, f"`docker compose config` failed:\n{result.stderr}"


# --------------------------------------------------------------------------------------
# compose file: parse + expected services + bind-mount sources exist
# --------------------------------------------------------------------------------------


def _compose() -> dict:
    return yaml.safe_load(COMPOSE.read_text())


def test_compose_declares_the_expected_service_stack() -> None:
    services = _compose()["services"]
    assert {
        "langgraph-server",
        "postgres",
        "redis",
        "caddy",
        "vector",
        "prometheus",
        "grafana",
    } <= set(services)


def test_langgraph_server_env_wires_postgres_redis_and_config() -> None:
    env = _compose()["services"]["langgraph-server"]["environment"]
    assert "postgres" in env["DATABASE_URI"]
    assert "redis" in env["REDIS_URI"]
    assert "LANGSMITH_API_KEY" in env
    assert env["OPENDEVOPS_CONFIG"].endswith("config.yaml")


def test_compose_bind_mount_sources_exist_on_disk() -> None:
    """Every host-path bind mount the stack references must exist (named volumes are skipped)."""
    for name, svc in _compose()["services"].items():
        for vol in svc.get("volumes", []):
            host = vol.split(":", 1)[0]
            if host.startswith(("./", "../", "/")):
                assert (REPO_ROOT / host).exists(), f"{name}: bind source {host!r} is missing"


def test_caddyfile_gates_on_bearer_token() -> None:
    text = (OPS / "caddy" / "Caddyfile").read_text()
    assert "Bearer {$GATEWAY_TOKEN}" in text
    assert "reverse_proxy langgraph-server:8000" in text
    assert "/webhooks/alertmanager" in text
    assert "/webhooks/github" in text
    assert "/webhooks/run-complete" in text
    assert text.index("@native_webhooks") < text.index("@authorized")


def test_compose_has_no_known_default_service_credentials() -> None:
    text = COMPOSE.read_text()
    assert "${POSTGRES_PASSWORD:?set POSTGRES_PASSWORD}" in text
    assert "${GATEWAY_TOKEN:?set GATEWAY_TOKEN}" in text
    assert "${GRAFANA_ADMIN_PASSWORD:?set GRAFANA_ADMIN_PASSWORD}" in text
    assert "change-me-before-deploy" not in text
    assert "POSTGRES_PASSWORD:-postgres" not in text
    assert "GRAFANA_ADMIN_PASSWORD:-admin" not in text


# --------------------------------------------------------------------------------------
# vector.yaml: parses; globs the per-run chains; ships to a durable local sink
# --------------------------------------------------------------------------------------


def _vector() -> dict:
    return yaml.safe_load((OPS / "vector" / "vector.yaml").read_text())


def test_vector_yaml_parses_and_ships_audit_chains_to_durable_sink() -> None:
    cfg = _vector()
    src = cfg["sources"]["audit_chains"]
    assert src["type"] == "file"
    assert any("/audit/*.jsonl" in inc for inc in src["include"])
    sink = cfg["sinks"]["durable_spool"]
    assert sink["type"] == "file"
    assert sink["inputs"] == ["audit_chains"]
    assert "/spool/" in sink["path"]
    # Raw JSONL preserved verbatim (append merge, no re-encoding that could break the hash chain).
    assert sink["encoding"]["codec"] == "text"


def test_vector_exports_internal_metrics_for_shipper_lag() -> None:
    cfg = _vector()
    assert cfg["sources"]["vector_internal"]["type"] == "internal_metrics"
    assert cfg["sinks"]["vector_metrics"]["type"] == "prometheus_exporter"


# --------------------------------------------------------------------------------------
# prometheus.yml + alerts.yml
# --------------------------------------------------------------------------------------


def _prometheus() -> dict:
    return yaml.safe_load((OPS / "prometheus" / "prometheus.yml").read_text())


def _alerts() -> dict:
    return yaml.safe_load((OPS / "prometheus" / "alerts.yml").read_text())


def test_prometheus_scrapes_server_and_vector() -> None:
    cfg = _prometheus()
    jobs = {sc["job_name"] for sc in cfg["scrape_configs"]}
    assert {"langgraph-server", "vector"} <= jobs
    assert cfg["rule_files"] == ["/etc/prometheus/alerts.yml"]


def test_prometheus_rule_file_exists() -> None:
    # rule_files points at the container path; the mounted source must exist on disk.
    assert (OPS / "prometheus" / "alerts.yml").is_file()


def test_alerts_cover_the_plan_cross_checks() -> None:
    groups = _alerts()["groups"]
    all_alerts = {rule["alert"] for grp in groups for rule in grp.get("rules", [])}
    # Alert coverage: denial spike, daily spend >80%, scheduler silence, audit-shipper lag.
    assert "PolicyDenialSpike" in all_alerts
    assert "DailySpendOver80Percent" in all_alerts
    assert "SchedulerSilence" in all_alerts
    assert {"AuditShipperDown", "AuditShipperLag"} <= all_alerts


def test_alert_component_ids_match_vector_config() -> None:
    """Vector component ids the shipper-lag alerts key on must exist in vector.yaml (no drift)."""
    alerts_text = (OPS / "prometheus" / "alerts.yml").read_text()
    vcfg = _vector()
    assert "audit_chains" in vcfg["sources"] and 'component_id="audit_chains"' in alerts_text
    assert "durable_spool" in vcfg["sinks"] and 'component_id="durable_spool"' in alerts_text


# --------------------------------------------------------------------------------------
# grafana provisioning + dashboard
# --------------------------------------------------------------------------------------


def test_grafana_datasource_provisioning_parses() -> None:
    path = OPS / "grafana" / "provisioning" / "datasources" / "datasource.yml"
    cfg = yaml.safe_load(path.read_text())
    ds = cfg["datasources"][0]
    assert ds["type"] == "prometheus"
    assert ds["url"] == "http://prometheus:9090"


def test_grafana_dashboard_provider_points_at_mounted_dir() -> None:
    path = OPS / "grafana" / "provisioning" / "dashboards" / "dashboards.yml"
    cfg = yaml.safe_load(path.read_text())
    assert cfg["providers"][0]["options"]["path"] == "/var/lib/grafana/dashboards"


def test_grafana_dashboard_json_is_valid_and_has_the_four_panels() -> None:
    dashboards = list((OPS / "grafana" / "dashboards").glob("*.json"))
    assert dashboards, "expected at least one provisioned dashboard json"
    model = json.loads(dashboards[0].read_text())
    titles = {p["title"] for p in model["panels"]}
    # runs, denials, daily spend, shipper lag (the brief's dashboard requirements).
    assert any("Runs" in t for t in titles)
    assert any("denial" in t.lower() for t in titles)
    assert any("spend" in t.lower() for t in titles)
    assert any("shipper" in t.lower() or "lag" in t.lower() for t in titles)
