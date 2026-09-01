"""Aggregated offline and live configuration preflight checks."""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

from opendevops.config import AppConfig, validate_runtime_config
from opendevops.interfaces.scheduler.jobs import load_jobs
from opendevops.interfaces.scheduler.maintenance import require_pg_dump_16
from opendevops.models import registry
from opendevops.policy.loader import check_credential_coverage, load_policy

REGISTERED_JOB_TYPES = frozenset({"hygiene", "escalation-sweep"})


@dataclass
class PreflightReport:
    successes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.failures

    def merge(self, other: PreflightReport) -> None:
        self.successes.extend(other.successes)
        self.warnings.extend(other.warnings)
        self.failures.extend(other.failures)


def configured_credential_families(cfg: AppConfig) -> set[str]:
    families: set[str] = set()
    if cfg.targets.kubernetes.kubeconfig_ro is not None:
        families.update({"kubectl", "helm"})
    if cfg.targets.github.token_env is not None:
        families.add("gh")
    if cfg.targets.github.token_env_rw is not None:
        families.add("gh-rw")
    for family, target_name in (("aws", "aws"), ("gcloud", "gcloud"), ("az", "azure")):
        target = getattr(cfg.targets, target_name)
        if target.credential_env:
            families.add(family)
        if target.credential_env_rw:
            families.add(f"{family}-rw")
    if cfg.targets.ssh.key_env is not None:
        families.add("ssh")
    return families


def _failure(report: PreflightReport, group: str, exc: BaseException | str) -> None:
    report.failures.append(f"{group}: {exc}")


def _require_env(report: PreflightReport, name: str, group: str) -> str | None:
    value = os.environ.get(name)
    if not value:
        _failure(report, group, f"environment variable {name!r} is unset or empty")
        return None
    return value


def _require_file(report: PreflightReport, path: Path | str | None, group: str) -> None:
    if path is None or not Path(path).expanduser().is_file():
        _failure(report, group, f"file not found: {path}")


def _check_local_runtime(cfg: AppConfig, loaded: Any, report: PreflightReport) -> None:
    kube = cfg.targets.kubernetes
    kubeconfigs = [
        kube.kubeconfig_ro,
        kube.kubeconfig_rw,
        *kube.kubeconfig_rw_by_environment.values(),
    ]
    for path in kubeconfigs:
        if path is not None:
            _require_file(report, path, "local credentials")
    github = cfg.targets.github
    for name in (github.token_env, github.token_env_rw):
        if name:
            _require_env(report, name, "local credentials")
    for target_name in ("aws", "gcloud", "azure"):
        target = getattr(cfg.targets, target_name)
        for name in [*target.credential_env, *target.credential_env_rw]:
            _require_env(report, name, "local credentials")
    ssh = cfg.targets.ssh
    if ssh.key_env:
        key_path = _require_env(report, ssh.key_env, "local credentials")
        if key_path:
            _require_file(report, key_path, "local credentials")
    if ssh.key_passphrase_env:
        _require_env(report, ssh.key_passphrase_env, "local credentials")
    if ssh.key_env or ssh.hosts:
        _require_file(report, ssh.known_hosts_path, "local credentials")
    for executable in sorted(loaded.flags_allowed_merged):
        if shutil.which(executable, path=cfg.execution.trusted_path) is None:
            _failure(
                report,
                "trusted executables",
                f"{executable!r} not found under execution.trusted_path",
            )


def _check_remote_runtime(cfg: AppConfig, report: PreflightReport) -> None:
    assert cfg.executor.urls is not None
    for environment, channels in cfg.executor.urls.items():
        for channel in ("ro", "rw"):
            url = getattr(channels, channel)
            parsed = urlsplit(url)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                _failure(report, "remote executor", f"invalid {environment}/{channel} URL: {url}")
            try:
                name = cfg.executor.signing_key_env_for(environment, channel)
            except ValueError as exc:
                _failure(report, "remote executor", exc)
            else:
                _require_env(report, name, "remote executor")
    tls = cfg.executor.tls
    if tls is not None:
        for path in (tls.ca_file, tls.cert_file, tls.key_file):
            if path is not None:
                _require_file(report, path, "remote executor TLS")


def run_offline_preflight(
    cfg: AppConfig,
    *,
    check_environment: bool = True,
    service: str | None = None,
) -> PreflightReport:
    """Run every offline check and return all discoverable problems at once."""
    report = PreflightReport()
    try:
        validate_runtime_config(cfg)
        report.successes.append("runtime invariants")
    except Exception as exc:  # noqa: BLE001
        _failure(report, "runtime invariants", exc)

    try:
        registry.assert_all_agents_priced(cfg)
        report.successes.append("model aliases and pricing")
    except Exception as exc:  # noqa: BLE001
        _failure(report, "models", exc)
    if check_environment:
        for role in sorted(cfg.models.agents):
            try:
                registry.build_chat_model(cfg, role)
            except Exception as exc:  # noqa: BLE001
                _failure(report, f"model {role}", exc)
        if not any(item.startswith("model ") for item in report.failures):
            report.successes.append("model providers, extras, and credentials")

    loaded = None
    try:
        loaded = load_policy(cfg.policy.dir)
        gaps = check_credential_coverage(loaded, configured_credential_families(cfg))
        if gaps:
            report.failures.extend(f"policy credentials: {gap}" for gap in gaps)
        else:
            report.successes.append("policy schema, lints, and credential coverage")
    except Exception as exc:  # noqa: BLE001
        _failure(report, "policy", exc)

    specs = []
    if check_environment:
        try:
            specs = load_jobs(cfg.scheduler.jobs_file)
            unknown = sorted(
                {spec.job_type for spec in specs if spec.job_type} - REGISTERED_JOB_TYPES
            )
            if unknown:
                _failure(report, "scheduler jobs", f"unregistered job_type(s): {unknown}")
            else:
                report.successes.append("scheduler job schema and registered types")
        except Exception as exc:  # noqa: BLE001
            _failure(report, "scheduler jobs", exc)

        if loaded is not None:
            if cfg.executor.mode == "local":
                _check_local_runtime(cfg, loaded, report)
            else:
                _check_remote_runtime(cfg, report)

        slack_problems = []
        for name in (cfg.slack.bot_token_env, cfg.slack.app_token_env):
            if not name or not os.environ.get(name):
                slack_problems.append(name or "unnamed Slack token")
        if not cfg.principals:
            slack_problems.append("principals mapping")
        if slack_problems:
            target = report.failures if service == "slack" else report.warnings
            target.append(f"Slack runtime is not ready: missing {', '.join(slack_problems)}")

        if any(spec.job_type == "hygiene" for spec in specs):
            scheduler_problems: list[str] = []
            for name in ("OPENDEVOPS_BACKUP_DATABASE_URI", "PGPASSWORD", "OPENDEVOPS_BACKUP_DIR"):
                if not os.environ.get(name):
                    scheduler_problems.append(name)
            try:
                require_pg_dump_16()
            except Exception as exc:  # noqa: BLE001
                scheduler_problems.append(str(exc))
            if scheduler_problems:
                target = report.failures if service == "scheduler" else report.warnings
                target.append(
                    "scheduler hygiene runtime is not ready: " + ", ".join(scheduler_problems)
                )
    return report


async def run_live_preflight(cfg: AppConfig) -> PreflightReport:
    """Probe LangGraph Server and each remote executor health endpoint without model calls."""
    try:
        import httpx
    except ImportError:
        return PreflightReport(
            failures=["live probes require the 'server' extra (httpx is not installed)"]
        )

    report = PreflightReport()
    if cfg.server.url:
        headers: dict[str, str] = {}
        if cfg.server.api_key_env:
            token = os.environ.get(cfg.server.api_key_env)
            if token:
                headers["Authorization"] = f"Bearer {token}"
        try:
            async with httpx.AsyncClient(headers=headers, timeout=5) as client:
                response = await client.get(urljoin(cfg.server.url.rstrip("/") + "/", "healthz"))
                response.raise_for_status()
            report.successes.append("LangGraph Server /healthz")
        except Exception as exc:  # noqa: BLE001
            _failure(report, "LangGraph Server live probe", exc)
    else:
        report.warnings.append("LangGraph Server live probe skipped: server.url is unset")

    if cfg.executor.mode == "remote" and cfg.executor.urls is not None:
        from opendevops.tools.executor import _build_remote_http_client

        client = _build_remote_http_client(cfg)
        try:
            urls = {
                getattr(channels, channel).rstrip("/")
                for channels in cfg.executor.urls.values()
                for channel in ("ro", "rw")
            }
            for url in sorted(urls):
                try:
                    response = await client.get(f"{url}/healthz", timeout=5)
                    response.raise_for_status()
                    report.successes.append(f"remote executor {url}/healthz")
                except Exception as exc:  # noqa: BLE001
                    _failure(report, f"remote executor live probe {url}", exc)
        finally:
            await client.aclose()
    return report
