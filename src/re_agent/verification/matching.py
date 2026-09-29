"""Compare compiled candidates with the original function through a project-owned oracle.

The oracle compiles the overlaid candidate with the original toolchain and flags,
locates the function in the resulting object, and compares it with the original
bytes, treating relocations by the symbol they reference. It prints one JSON
object on stdout:

    {"exact": false, "score": 0.93, "summary": "...", "target_size": 212,
     "candidate_size": 208, "diff": ["...", {"offset": 14, "kind": "register",
     "target": "mov ecx,[esi+0x10]", "candidate": "mov eax,[esi+0x10]"}]}

Exit status 0 means a comparison ran, whatever its outcome. Any other status (for
example a compiler error) is an oracle error; its diagnostics feed repair.
"""

from __future__ import annotations

import json
import math
import os
import re
import subprocess
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from re_agent.config.schema import MatchingConfig
from re_agent.core.models import FunctionTarget, MatchVerdict
from re_agent.utils.process import run_process
from re_agent.verification.candidate import _NON_CODE, _overlay_root, diagnostic_excerpt

PLACEHOLDERS = ("candidate_file", "overlay_root", "source_file", "address", "function", "original_binary", "python")
_PLACEHOLDER = re.compile(r"\{(" + "|".join(PLACEHOLDERS) + r")\}")


def qualified_name(target: FunctionTarget) -> str:
    return f"{target.class_name}::{target.function_name}" if target.class_name else target.function_name


def oracle_values(
    config: MatchingConfig, target: FunctionTarget, candidate_file: Path, source_file: str | None
) -> dict[str, str]:
    return {
        "candidate_file": str(candidate_file.resolve()),
        "overlay_root": str(_overlay_root(candidate_file).resolve()),
        "source_file": source_file or "",
        "address": target.address,
        "function": qualified_name(target),
        "original_binary": str(Path(config.original_binary).resolve()) if config.original_binary else "",
        "python": sys.executable,  # Runs bundled oracles such as re_agent.oracles.msvc with this interpreter.
    }


def expand(argv: list[str], values: Mapping[str, str]) -> list[str]:
    # Single pass: replacement values are data, never additional placeholders.
    return [_PLACEHOLDER.sub(lambda match: values[match[1]], arg) for arg in argv]


def forbidden_constructs(code: str, patterns: list[str]) -> list[str]:
    """Report constructs that would make a byte match meaningless, ignoring comments and literals."""
    tokens = _NON_CODE.sub(" ", code)
    found = []
    for pattern in patterns:
        match = re.search(pattern, tokens)
        if match:
            found.append(f"forbidden construct `{match.group(0).strip()}` (pattern {pattern})")
    return found


def run_oracle(
    config: MatchingConfig,
    values: Mapping[str, str],
    cwd: str,
    extra_env: Mapping[str, str] | None = None,
) -> MatchVerdict:
    """Run the configured oracle once; failures become verdicts, never exceptions."""
    command = expand(config.oracle_command, values)
    try:
        proc = run_process(command, cwd=cwd, env=_environment(values, extra_env), timeout_s=config.timeout_s)
    except OSError as exc:
        return _error(f"Match oracle could not start: {exc}")
    except subprocess.TimeoutExpired:
        return _error(f"Match oracle timed out after {config.timeout_s}s")
    if proc.returncode != 0:
        detail = diagnostic_excerpt(proc.stderr + "\n" + proc.stdout)
        return _error(f"Match oracle exit {proc.returncode}" + (f"\n{detail}" if detail else ""))
    try:
        return parse_oracle_output(proc.stdout, config.diff_max_lines)
    except ValueError as exc:
        return _error(f"Match oracle output rejected: {exc}")


def parse_oracle_output(stdout: str, max_lines: int = 120) -> MatchVerdict:
    def reject_constant(value: str) -> None:
        raise ValueError(f"Non-standard JSON constant: {value}")

    payload = json.loads(stdout, parse_constant=reject_constant)
    if not isinstance(payload, dict):
        raise ValueError("expected one JSON object")
    exact, score = payload.get("exact"), payload.get("score")
    if not isinstance(exact, bool):
        raise ValueError("'exact' must be a boolean")
    if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score):
        raise ValueError("'score' must be a finite number")
    if not 0 <= score <= 1:
        raise ValueError("'score' must be between 0 and 1")
    if exact and score != 1:
        raise ValueError("an exact match must have score 1")
    sizes = []
    for key in ("target_size", "candidate_size"):
        value = payload.get(key)
        if value is not None and (isinstance(value, bool) or not isinstance(value, int) or value < 0):
            raise ValueError(f"'{key}' must be a nonnegative integer")
        sizes.append(value)
    summary = payload.get("summary", "")
    if not isinstance(summary, str):
        raise ValueError("'summary' must be a string")
    diff = payload.get("diff", [])
    if not isinstance(diff, list):
        raise ValueError("'diff' must be a list")
    return MatchVerdict(
        exact=exact,
        score=float(score),
        summary=summary or ("Exact match" if exact else f"{score:.1%} match"),
        diff=render_diff(diff, max_lines),
        target_size=sizes[0],
        candidate_size=sizes[1],
    )


def render_diff(diff: list[Any], max_lines: int) -> list[str]:
    lines = []
    for item in diff:
        if isinstance(item, str):
            lines.append(item[:500])
        elif isinstance(item, dict):
            position = item.get("offset", item.get("index"))
            head = " ".join(str(part) for part in (
                f"@{position:#x}" if isinstance(position, int) and not isinstance(position, bool) else position,
                item.get("kind"),
            ) if part is not None)
            sides = [f"{side} `{item[side]}`" for side in ("target", "candidate") if item.get(side) is not None]
            lines.append((head + ": " if head else "") + " | ".join(sides) if sides else json.dumps(item))
        else:
            lines.append(json.dumps(item))
    if len(lines) > max_lines:
        omitted = len(lines) - (max_lines - 1)
        lines = [*lines[: max_lines - 1], f"[{omitted} more diff lines omitted]"]
    return lines


def run_permuter(config: MatchingConfig, values: Mapping[str, str], cwd: str) -> tuple[str | None, str]:
    """Ask the permuter for an improved function; its own score is never trusted.

    Contract: print ``{"code": "<one complete function>"}``, or ``{"code": null}``
    when nothing better was found.
    """
    command = expand(config.permuter_command, values)
    try:
        proc = run_process(command, cwd=cwd, env=_environment(values, None), timeout_s=config.permuter_timeout_s)
    except OSError as exc:
        return None, f"permuter could not start: {exc}"
    except subprocess.TimeoutExpired:
        return None, f"permuter timed out after {config.permuter_timeout_s}s"
    if proc.returncode != 0:
        return None, f"permuter exit {proc.returncode}: {diagnostic_excerpt(proc.stderr)}"
    try:
        payload = json.loads(proc.stdout)
    except ValueError as exc:
        return None, f"permuter output rejected: {exc}"
    if not isinstance(payload, dict) or "code" not in payload:
        return None, "permuter output rejected: expected an object with a 'code' key"
    code = payload["code"]
    if code is not None and not (isinstance(code, str) and code.strip()):
        return None, "permuter output rejected: 'code' must be a nonempty string or null"
    return code, "permuter proposed a candidate" if code else "permuter found no improvement"


def _environment(values: Mapping[str, str], extra_env: Mapping[str, str] | None) -> dict[str, str]:
    env = os.environ.copy()
    env.update({
        "RE_AGENT_CANDIDATE_FILE": values["candidate_file"],
        "RE_AGENT_OVERLAY_ROOT": values["overlay_root"],
        "RE_AGENT_SOURCE_FILE": values["source_file"],
        "RE_AGENT_TARGET_ADDRESS": values["address"],
        "RE_AGENT_TARGET_FUNCTION": values["function"],
        "RE_AGENT_ORIGINAL_BINARY": values["original_binary"],
    })
    env.update(extra_env or {})
    return env


def _error(message: str) -> MatchVerdict:
    return MatchVerdict(exact=False, score=0.0, summary=message.splitlines()[0], error=message)
