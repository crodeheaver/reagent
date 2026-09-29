"""Matching through real overlays: placeholders, trust, lint and exact acceptance."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from re_agent.backend.stub import StubBackend
from re_agent.config.schema import ReAgentConfig
from re_agent.core.models import FunctionTarget
from re_agent.core.session import Session
from re_agent.orchestrator.single import evaluate_source_match, reverse_single, validate_result
from tests.test_agents.test_loop import MockLLM

ORACLE = """
import json, sys
from pathlib import Path
text = Path(sys.argv[1]).read_text()
log = Path(sys.argv[4]); log.write_text(log.read_text() + sys.argv[2] + " " + sys.argv[3] + "\\n")
if "UNDECLARED" in text:
    print("error: use of undeclared identifier", file=sys.stderr); sys.exit(1)
exact = "return x + 2;" in text
print(json.dumps({"exact": exact, "score": 1.0 if exact else 0.5, "target_size": 6, "candidate_size": 6,
                  "diff": [] if exact else [{"offset": 3, "kind": "immediate", "target": "add eax,2",
                                             "candidate": "add eax,1"}]}))
"""
PASS = '{"verdict":"PASS","summary":"Matches the decompile"}'


def project(tmp_path: Path, trusted: bool = True) -> ReAgentConfig:
    source_root = tmp_path / "src"
    source_root.mkdir()
    (source_root / "f.cpp").write_text("int helper();\n\nint f(int x) {\n    return 0;\n}\n")
    oracle = tmp_path / "oracle.py"
    oracle.write_text(ORACLE)
    (tmp_path / "oracle.log").write_text("")
    config = ReAgentConfig()
    config.project_profile.source_root = str(source_root)
    config.project_profile.hook_patterns = []
    config.output.report_dir = str(tmp_path / "reports")
    config.output.log_dir = str(tmp_path / "logs")
    config.output.session_file = str(tmp_path / "session.json")
    config.parity.enabled = False
    config.orchestrator.objective_verifier_enabled = False
    config.orchestrator.investigation_enabled = False
    config.orchestrator.max_review_rounds = 2
    config.validation.trust_configured_commands = trusted
    config.validation.working_directory = str(tmp_path)
    config.matching.enabled = True
    config.matching.plateau_rounds = 2
    config.matching.oracle_command = [sys.executable, str(oracle), "{candidate_file}", "{address}", "{function}",
                                      str(tmp_path / "oracle.log")]
    return config


def oracle_runs(tmp_path: Path) -> list[str]:
    return (tmp_path / "oracle.log").read_text().splitlines()


TARGET = FunctionTarget("0x401000", "", "f")


def test_exact_first_candidate_is_accepted_without_review(tmp_path):
    config = project(tmp_path)
    checker = MockLLM([PASS])
    session = Session(config.output.session_file)
    result = reverse_single(TARGET, config, StubBackend(), MockLLM(["```cpp\nint f(int x) { return x + 2; }\n```"]),
                            checker_llm=checker, session=session)
    assert result.success and result.match_tier == "exact"
    assert checker._idx == 0
    assert oracle_runs(tmp_path) == ["0x401000 f"]
    assert result.validation_verdict is not None
    assert result.validation_verdict.summary.endswith("no build or test commands configured")


def test_exact_match_requires_trusted_commands(tmp_path):
    config = project(tmp_path, trusted=False)
    result = reverse_single(TARGET, config, StubBackend(), MockLLM(["```cpp\nint f(int x) { return x + 2; }\n```"]),
                            checker_llm=MockLLM([PASS]))
    assert not result.success
    assert result.match_verdict is not None and result.match_verdict.exact


def test_functional_candidate_refines_to_exact_match(tmp_path):
    config = project(tmp_path)
    reverser = MockLLM(["```cpp\nint f(int x) { return x + 1 + 1; }\n```",
                        "```cpp\nint f(int x) { return x + 2; }\n```"])
    checker = MockLLM([PASS])
    result = reverse_single(TARGET, config, StubBackend(), reverser, checker_llm=checker)
    assert result.success and result.match_tier == "exact"
    assert result.code == "int f(int x) { return x + 2; }"
    assert checker._idx == 1
    logs = list(Path(config.output.log_dir).rglob("match1-*.json"))
    assert len(logs) == 1
    entry = json.loads(logs[0].read_text())
    assert "@0x3 immediate: target `add eax,2` | candidate `add eax,1`" in entry["prompt"]
    assert entry["candidates"][0]["score"] == 1.0


def test_forbidden_construct_is_rejected_before_the_oracle(tmp_path):
    config = project(tmp_path)
    reverser = MockLLM(["```cpp\nint f(int x) { return x + 1 + 1; }\n```",
                        "```cpp\nint f(int x) { __asm { add x, 2 } return x + 2; }\n```"])
    result = reverse_single(TARGET, config, StubBackend(), reverser, checker_llm=MockLLM([PASS]))
    assert not result.success
    assert result.code == "int f(int x) { return x + 1 + 1; }"
    assert len(oracle_runs(tmp_path)) == 1  # The reviewed candidate once; never the rejected one.
    assert result.error == "No exact match (no improvement in 2 rounds; best 50.0%)"


def test_compile_errors_reach_repair_without_review(tmp_path):
    config = project(tmp_path)
    reverser = MockLLM(["```cpp\nint f(int x) { return UNDECLARED; }\n```",
                        "```cpp\nint f(int x) { return x + 2; }\n```"])
    checker = MockLLM([PASS])
    result = reverse_single(TARGET, config, StubBackend(), reverser, checker_llm=checker)
    assert result.success and result.rounds_used == 2
    assert checker._idx == 0


def test_promotion_revalidation_enforces_exact_policy(tmp_path):
    from re_agent.core.models import ReversalResult

    config = project(tmp_path)
    functional = ReversalResult(TARGET, "int f(int x) { return x + 1 + 1; }", success=True)
    assert validate_result(functional, config, StubBackend(), require_exact=False).success
    assert not validate_result(functional, config, StubBackend()).success
    config.matching.require_exact = False
    assert validate_result(functional, config, StubBackend()).success


def test_existing_source_is_scored_through_the_same_path(tmp_path):
    config = project(tmp_path)
    verdict = evaluate_source_match(TARGET, config)
    assert verdict.error is None and verdict.score == 0.5
    missing = evaluate_source_match(FunctionTarget("0x2", "", "g"), config)
    assert missing.error == "No source definition for g"
