"""Read-only configuration and evidence preflight."""

from __future__ import annotations

import argparse
import json
import shutil
from collections.abc import Callable
from pathlib import Path

from re_agent.backend.registry import create_backend
from re_agent.config.loader import load_config
from re_agent.config.schema import ReAgentConfig
from re_agent.llm.registry import CLI_EXECUTABLES


def cmd_doctor(args: argparse.Namespace) -> int:
    config = load_config(Path(args.config))
    checks: list[dict[str, object]] = []

    def add(name: str, passed: bool, detail: str = "") -> None:
        checks.append({"check": name, "passed": passed, "detail": detail})

    add("source_root", Path(config.project_profile.source_root).is_dir(), config.project_profile.source_root)
    for role, model in (
        ("reverser", config.agents.reverser or config.llm),
        ("checker", config.agents.checker or config.llm),
    ):
        if model.provider in CLI_EXECUTABLES:
            executable = model.cli_path or CLI_EXECUTABLES[model.provider]
            add(role + " executable", shutil.which(executable) is not None, executable)
    validation = config.validation
    commands = validation.build_commands + validation.test_commands + validation.runtime_commands
    if validation.enabled and any(isinstance(command, str) for command in commands):
        add("validation shell", shutil.which("/bin/sh") is not None,
            "Shell strings require /bin/sh; use argument arrays for native Windows validation")
    has_gates = bool(
        validation.build_commands
        or validation.test_commands
        or validation.runtime_commands
        or validation.differential_cases_file
        or (config.matching.enabled and config.matching.oracle_command)
    )
    add(
        "acceptance policy",
        not validation.enabled
        or not validation.require_verified
        or (has_gates and validation.trust_configured_commands),
        "Verified acceptance requires configured, explicitly trusted validation gates",
    )
    for required, commands, name in [
        (validation.require_build, validation.build_commands, "build"),
        (validation.require_tests, validation.test_commands, "tests"),
        (validation.require_runtime, validation.runtime_commands, "runtime"),
    ]:
        add(name + " gate", not validation.enabled or not required or bool(commands))
    if config.matching.enabled:
        _matching_checks(config, add, getattr(args, "skip_canary", False))
    try:
        backend = create_backend(config.backend)
        add("decompile capability", backend.capabilities.has_decompile)
        if args.address:
            result = backend.decompile(args.address)
            add("target evidence", bool(result.decompiled.strip()), result.name)
    except (OSError, ValueError, RuntimeError) as exc:
        add("backend", False, str(exc))
    print(json.dumps({"checks": checks, "ready": all(c["passed"] for c in checks)}, indent=2))
    return 0 if all(c["passed"] for c in checks) else 1


def _matching_checks(config: ReAgentConfig, add: Callable[[str, bool, str], None], skip_canary: bool) -> None:
    import sys

    matching = config.matching
    for label, command in (("match oracle", matching.oracle_command), ("match permuter", matching.permuter_command)):
        if command:
            executable = sys.executable if command[0] == "{python}" else command[0]
            add(label, shutil.which(executable) is not None or Path(executable).is_file(), executable)
    for label, value in [("original binary", matching.original_binary),
                         *(("toolchain file", path) for path in matching.toolchain_files)]:
        if value:
            add(label, Path(value).is_file(), value)
    add("match acceptance", config.validation.trust_configured_commands,
        "Exact matches count only when validation.trust_configured_commands attests the oracle")
    if not matching.canary_address:
        add("match canary", True, "Not configured; set matching.canary_address to prove the toolchain first")
    elif skip_canary:
        add("match canary", True, "Skipped by --skip-canary")
    else:
        from re_agent.cli.cmd_matching import canary

        try:
            report = canary(config)
        except (OSError, ValueError) as exc:
            add("match canary", False, str(exc))
        else:
            add("match canary", bool(report["exact"]),
                f"{report['function']} ({report['address']}): {report['error'] or report['summary']}")
