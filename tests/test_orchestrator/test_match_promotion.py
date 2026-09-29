"""Promotions that change previously exact functions in the same file are reverted."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

from re_agent.config.schema import ReAgentConfig
from re_agent.core.models import FunctionTarget, MatchVerdict, ReversalResult
from re_agent.core.session import Session
from re_agent.orchestrator.class_runner import _promote

# Stand-in for an inlining side effect: g stops matching once f's body says so.
ORACLE = """
import json, sys
from pathlib import Path
text = Path(sys.argv[1]).read_text()
exact = sys.argv[2] != "g" or "BREAKS_G" not in text
print(json.dumps({"exact": exact, "score": 1.0 if exact else 0.8}))
"""
SOURCE = "static int g(int x) {\n    return x * 3;\n}\n\nint f(int x) {\n    return 0;\n}\n"


def scratch(tmp_path: Path) -> tuple[ReAgentConfig, Session, Path]:
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    source = root / "src" / "unit.cpp"
    source.write_text(SOURCE)
    oracle = tmp_path / "oracle.py"
    oracle.write_text(ORACLE)
    config = ReAgentConfig()
    config.project_profile.source_root = str(root / "src")
    config.project_profile.hook_patterns = []
    config.output.report_dir = str(tmp_path / "reports")
    config.validation.project_root = str(root)
    config.validation.copy_project = True
    config.validation.trust_configured_commands = True
    config.matching.enabled = True
    config.matching.oracle_command = [sys.executable, str(oracle), "{candidate_file}", "{function}"]
    session = Session(tmp_path / "session.json")
    session.record_result(ReversalResult(FunctionTarget("0x10", "", "g"), "static int g(int x) { return x * 3; }",
                                         success=True, match_verdict=MatchVerdict(True, 1.0)))
    return config, session, source


def test_promotion_that_breaks_an_exact_sibling_is_reverted(tmp_path):
    config, session, source = scratch(tmp_path)
    result = ReversalResult(FunctionTarget("0x20", "", "f"), "int f(int x) { return x; /* BREAKS_G */ }",
                            success=True, match_verdict=MatchVerdict(True, 1.0))
    with pytest.raises(ValueError, match=r"changed previously exact functions in the same file: g \(0x10\): 80.0%"):
        _promote(result, config, session)
    assert source.read_text() == SOURCE


def test_promotion_keeping_siblings_exact_is_written(tmp_path):
    config, session, source = scratch(tmp_path)
    _promote(ReversalResult(FunctionTarget("0x20", "", "f"), "int f(int x) { return x; }", success=True),
             config, session)
    assert "return x; }" in source.read_text()


def test_restoring_earlier_results_skips_the_check(tmp_path):
    config, _, source = scratch(tmp_path)
    _promote(ReversalResult(FunctionTarget("0x20", "", "f"), "int f(int x) { return x; /* BREAKS_G */ }"), config)
    assert "BREAKS_G" in source.read_text()


def test_amending_a_result_does_not_consume_another_attempt(tmp_path):
    session = Session(tmp_path / "session.json")
    result = ReversalResult(FunctionTarget("0x20", "", "f"), "int f();", success=True, run_id="run-1")
    session.record_result(result)
    result.success, result.error = False, "Promotion reverted"
    session.amend_result(result)
    assert session.attempt_count("0x20") == 1
    assert not session.is_completed("0x20")
    assert session.get_all_functions()[0]["error"] == "Promotion reverted"
