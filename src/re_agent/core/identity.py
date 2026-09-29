"""Fingerprint project inputs so completed results cannot silently go stale."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path

from re_agent.config.schema import ReAgentConfig


def project_fingerprint(config: ReAgentConfig) -> str:
    digest = hashlib.sha256()
    # Acceptance policy and source profile affect the meaning of an accepted result.
    values = {
        "profile": asdict(config.project_profile),
        "validation": asdict(config.validation),
        "parity": asdict(config.parity),
        "backend": asdict(config.backend),
    }
    # Execution-only settings must not change identities recorded by earlier releases.
    values["validation"].pop("parallel_safe", None)
    if not values["profile"].get("annotation_modules"):
        values["profile"].pop("annotation_modules", None)  # Absent before annotations existed.
    if config.matching.enabled:
        # Only enabled matching changes what acceptance means; disabled keeps prior identities.
        values["matching"] = asdict(config.matching)
    digest.update(json.dumps(values, sort_keys=True).encode())
    root = Path(config.project_profile.source_root).resolve()
    digest.update(str(root).encode())
    if root.exists():
        for path in sorted(
            p for p in root.rglob("*") if p.is_file() and p.suffix in config.project_profile.source_extensions
        ):
            digest.update(str(path.relative_to(root)).encode())
            digest.update(path.read_bytes())
    if config.backend.export_dir:
        for path in sorted(Path(config.backend.export_dir).glob("*.json")):
            digest.update(path.name.encode())
            digest.update(path.read_bytes())
    for value in (
        config.backend.address_map,
        config.parity.semantic_rules_file,
        config.validation.differential_cases_file,
        config.project_profile.compilation_database,
    ):
        if value:
            digest.update(Path(value).read_bytes())
    if config.matching.enabled:
        # A different compiler or original binary invalidates every recorded match.
        for value in [config.matching.original_binary, *config.matching.toolchain_files]:
            if value:
                digest.update(Path(value).read_bytes())
    return digest.hexdigest()


def acceptance_fingerprint(config: ReAgentConfig) -> str:
    """Identify the models and acceptance policy that produced accepted results.

    Only model identity counts; pricing, CLI paths, timeouts, token limits and
    budgets change how a model is run, not what an accepted result means.
    """
    models = {role: {key: getattr(model, key) for key in ("provider", "model", "base_url", "effort")}
              for role, model in (("reverser", config.agents.reverser or config.llm),
                                  ("checker", config.agents.checker or config.llm))}
    policy = {key: value for key, value in asdict(config.orchestrator).items()
              if key.startswith("objective_") or key == "cumulative_validation"}
    return hashlib.sha256(json.dumps({"models": models, "policy": policy}, sort_keys=True).encode()).hexdigest()
