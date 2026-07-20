"""Policy engine: declarative YAML rules + Python hooks, default-deny, fail-closed.

Public surface re-exported here is the data model + loader + argv parser plus the
decision engine and hook registry, and the :class:`PolicyMiddleware` integration point.
"""

from __future__ import annotations

# Importing this module runs its ``@policy_hook`` decorators, registering the shipped built-in
# hooks (``dry_run_before_apply``) at import time. builtin_hooks imports the hooks registry
# directly, so import order within this file does not matter. The re-export keeps the symbol
# reachable and makes the import non-removable by an "unused import" lint. A ``hook:`` rule whose
# name is unregistered fails closed at decide time, so this registration is load-bearing for the
# shipped kubectl-mutate pack.
from opendevops.policy.builtin_hooks import dry_run_before_apply
from opendevops.policy.engine import (
    BUILTIN_FS_TOOLS,
    RULE_BUILTIN_FS,
    PolicyEngine,
    YamlRuleEngine,
)
from opendevops.policy.hooks import (
    PolicyHook,
    get_hook,
    policy_hook,
    registered_hooks,
)
from opendevops.policy.loader import (
    LoadedPolicy,
    PolicyLintError,
    check_credential_coverage,
    load_policy,
)
from opendevops.policy.middleware import PolicyMiddleware
from opendevops.policy.parsing import (
    ALIAS_TABLES,
    SUBCOMMAND_BINARIES,
    VALUE_FLAGS,
    ParsedArgv,
    ParseError,
    match_resource,
    parse_argv,
)
from opendevops.policy.schema import (
    RESERVED_RULE_IDS,
    RULE_DEFAULT_DENY,
    RULE_FAIL_CLOSED,
    RULE_FLAG_NOT_ALLOWED,
    RULE_REWRITE_DIVERGED,
    RULE_UNKNOWN_TOOL,
    Channel,
    Decision,
    Effect,
    Escalation,
    Match,
    Metadata,
    PolicyFile,
    Rewrite,
    Rule,
    StrMatcher,
    ToolCallCtx,
)

__all__ = [
    # engine
    "PolicyEngine",
    "YamlRuleEngine",
    "BUILTIN_FS_TOOLS",
    "RULE_BUILTIN_FS",
    # middleware
    "PolicyMiddleware",
    # hooks
    "PolicyHook",
    "policy_hook",
    "get_hook",
    "registered_hooks",
    "dry_run_before_apply",
    # schema
    "Channel",
    "Decision",
    "Effect",
    "Escalation",
    "Match",
    "Metadata",
    "PolicyFile",
    "Rewrite",
    "Rule",
    "StrMatcher",
    "ToolCallCtx",
    "RESERVED_RULE_IDS",
    "RULE_DEFAULT_DENY",
    "RULE_FAIL_CLOSED",
    "RULE_FLAG_NOT_ALLOWED",
    "RULE_REWRITE_DIVERGED",
    "RULE_UNKNOWN_TOOL",
    # parsing
    "ALIAS_TABLES",
    "SUBCOMMAND_BINARIES",
    "VALUE_FLAGS",
    "ParseError",
    "ParsedArgv",
    "match_resource",
    "parse_argv",
    # loader
    "LoadedPolicy",
    "PolicyLintError",
    "check_credential_coverage",
    "load_policy",
]
