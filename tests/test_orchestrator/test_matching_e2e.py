"""End to end with a real compiler: refine a functional candidate into identical bytes."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from re_agent.backend.stub import StubBackend
from re_agent.cli.cmd_matching import canary
from re_agent.config.schema import ReAgentConfig
from re_agent.core.models import FunctionTarget
from re_agent.orchestrator.single import reverse_single
from re_agent.verification.binary import compare_binaries
from tests.test_agents.test_loop import MockLLM

ORACLE = Path(__file__).resolve().parents[2] / "examples" / "matching_elf" / "oracle.py"
FLAGS = ["-O2", "-fno-inline"]
BODY = """{
    if (x > 10) {
        counter += x;
        puts("big");
        return helper(x) + 2;
    }
    return x - 1;
}"""
SOURCE = """#include <stdio.h>
int counter;
int helper(int x) { return x * 3; }
int f(int x) BODY
int main(void) { return f(counter); }
"""


def _gnu_binutils() -> bool:
    if not sys.platform.startswith("linux") or not shutil.which("gcc") or not shutil.which("objdump"):
        return False
    return "GNU objdump" in subprocess.run(["objdump", "--version"], capture_output=True, text=True).stdout


pytestmark = pytest.mark.skipif(not _gnu_binutils(), reason="requires Linux, gcc and GNU binutils")


def build(directory: Path, body: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "ref.c").write_text(SOURCE.replace("BODY", body))
    subprocess.run(["gcc", *FLAGS, "ref.c", "-o", "program"], cwd=directory, check=True)
    return directory / "program"


def address_of(binary: Path, name: str) -> str:
    symbols = subprocess.run(["nm", str(binary)], capture_output=True, text=True, check=True).stdout
    return "0x" + next(line.split()[0] for line in symbols.splitlines() if line.split()[-1] == name)


def configure(tmp_path: Path, original: Path) -> ReAgentConfig:
    project = tmp_path / "project"
    (project / "src").mkdir(parents=True)
    (project / "src" / "ref.c").write_text(SOURCE.replace("BODY", "{\n    return 0;\n}"))
    config = ReAgentConfig()
    config.project_profile.source_root = str(project / "src")
    config.project_profile.source_extensions = [".c"]
    config.project_profile.hook_patterns = []
    config.output.report_dir = str(tmp_path / "reports")
    config.output.log_dir = str(tmp_path / "logs")
    config.parity.enabled = False
    config.orchestrator.objective_verifier_enabled = False
    config.orchestrator.investigation_enabled = False
    config.validation.copy_project = True
    config.validation.project_root = str(project)
    config.validation.trust_configured_commands = True
    config.matching.enabled = True
    config.matching.original_binary = str(original)
    config.matching.oracle_command = [
        sys.executable, str(ORACLE), "--original", "{original_binary}", "--address", "{address}",
        "--function", "{function}", "--source", "{candidate_file}", "--cc", "gcc", "--", *FLAGS,
    ]
    return config


def test_functional_candidate_is_refined_into_an_identical_binary(tmp_path):
    original = build(tmp_path / "original", BODY)
    config = configure(tmp_path, original)
    config.matching.canary_address = address_of(original, "helper")
    config.matching.canary_function = "helper"
    assert canary(config)["exact"]  # The toolchain reproduces untouched source before any model call.

    functional = "int f(int x) " + BODY.replace("+ 2;", "+ 1 + 1 + 1;")
    exact = "int f(int x) " + BODY
    reverser = MockLLM([f"```c\n{functional}\n```", f"```c\n{exact}\n```"])
    checker = MockLLM(['{"verdict":"PASS","summary":"Matches the decompile"}'])
    result = reverse_single(FunctionTarget(address_of(original, "f"), "", "f"), config, StubBackend(), reverser,
                            checker_llm=checker)

    assert result.success and result.match_tier == "exact", result.error
    assert result.rounds_used == 2 and checker._idx == 1
    prompt = json.loads(next(Path(config.output.log_dir).rglob("match1-*.json")).read_text())["prompt"]
    assert "mismatch: target `" in prompt

    rebuilt = build(tmp_path / "rebuilt", result.code.removeprefix("int f(int x) "))
    assert compare_binaries(original, rebuilt)["identical_after_masking"]
