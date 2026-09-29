"""Toolchain identification, compiler-flag search and whole-binary comparison."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from re_agent.config.schema import ReAgentConfig
from re_agent.core.models import FunctionTarget


def named_target(config: ReAgentConfig, address: str, qualified: str | None = None) -> FunctionTarget:
    """Name a function already in the source tree by its qualified name or the project's hook index."""
    if qualified:
        class_name, _, function_name = qualified.rpartition("::")
        return FunctionTarget(address, class_name, function_name)
    from re_agent.parity.source_indexer import SourceIndexer
    from re_agent.utils.address import normalize_address

    indexer = SourceIndexer(Path(config.project_profile.source_root), config.project_profile)
    for hook_address, (class_name, function_name) in indexer.hook_address_index.items():
        if normalize_address(hook_address) == normalize_address(address) and function_name:
            return FunctionTarget(address, class_name, function_name)
    raise ValueError(f"{address} is not in the project's hook index; name the function explicitly")


def canary(config: ReAgentConfig, extra_env: dict[str, str] | None = None) -> dict[str, Any]:
    """Score a function whose existing source is known to match; anything short of exact is a setup error."""
    from re_agent.orchestrator.single import evaluate_source_match

    assert config.matching.canary_address is not None
    target = named_target(config, config.matching.canary_address, config.matching.canary_function)
    verdict = evaluate_source_match(target, config, extra_env=extra_env)
    return {"address": target.address, "function": f"{target.class_name}::{target.function_name}".lstrip(":"),
            "exact": verdict.accepted, "score": verdict.score, "summary": verdict.summary, "error": verdict.error}


def cmd_toolchain(args: argparse.Namespace) -> int:
    from re_agent.config.loader import load_config
    from re_agent.verification.binary import identify

    if not args.flags:
        binary = args.binary
        if binary is None:
            binary = load_config(Path(args.config)).matching.original_binary
        if not binary:
            raise ValueError("Specify --binary or configure matching.original_binary")
        print(json.dumps(identify(Path(binary)), indent=2))
        return 0
    config = load_config(Path(args.config))
    if not config.matching.oracle_command:
        raise ValueError("Flag search requires matching.oracle_command")
    if args.address:
        config.matching.canary_address, config.matching.canary_function = args.address, args.function
    if not config.matching.canary_address:
        raise ValueError("Flag search requires --address or matching.canary_address")
    # Oracles read candidate flags from RE_AGENT_MATCH_FLAGS; the existing source is the fixed input.
    variants = [dict(canary(config, {"RE_AGENT_MATCH_FLAGS": flags}), flags=flags) for flags in args.flags]
    ranked = sorted(variants, key=lambda row: (row["error"] is not None, -row["score"]))
    print(json.dumps({"variants": variants, "best": ranked[0]}, indent=2))
    return 0 if ranked[0]["exact"] else 1


def cmd_match_binary(args: argparse.Namespace) -> int:
    from re_agent.config.loader import load_config
    from re_agent.verification.binary import compare_binaries

    original = args.original or load_config(Path(args.config)).matching.original_binary
    if not original:
        raise ValueError("Specify --original or configure matching.original_binary")
    report = compare_binaries(Path(original), Path(args.rebuilt))
    if args.format == "json":
        print(json.dumps(report, indent=2))
    else:
        verdict = ("identical" if report["identical"] else
                   "identical after masking build-varying fields" if report["identical_after_masking"] else "differs")
        print(f"{args.rebuilt}: {verdict} ({report['format']}; {report['sizes']['rebuilt']} bytes)")
        for field in report["masked_fields"]:
            print(f"  masked {field['name']} at {field['offset']:#x} ({field['size']} bytes)")
        for item in report["differences"]:
            print(f"  {item['region']}: {item['differing_bytes']} bytes differ, first at {item['first_difference']:#x}")
    return 0 if report["identical_after_masking"] else 1
