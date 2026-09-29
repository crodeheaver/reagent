"""Oracle contract: strict JSON, failures as verdicts, placeholders as data."""
import json
import sys

import pytest

from re_agent.config.schema import MatchingConfig
from re_agent.core.models import FunctionTarget
from re_agent.verification.matching import (
    expand,
    forbidden_constructs,
    oracle_values,
    parse_oracle_output,
    render_diff,
    run_oracle,
    run_permuter,
)


def _oracle(tmp_path, body: str, **config: object) -> MatchingConfig:
    script = tmp_path / "oracle.py"
    script.write_text("import json, os, sys\n" + body)
    return MatchingConfig(enabled=True, oracle_command=[sys.executable, str(script), "{address}", "{function}"],
                          **config)


def _values(tmp_path) -> dict[str, str]:
    candidate = tmp_path / "overlay" / "a file.cpp"
    candidate.parent.mkdir(exist_ok=True)
    (candidate.parent / ".re-agent-overlay").write_text("schema_version=1\n")
    candidate.write_text("int f() { return 1; }\n")
    return oracle_values(MatchingConfig(), FunctionTarget("0x401000", "CFoo", "Bar"), candidate, None)


def test_values_describe_target_and_overlay(tmp_path):
    values = _values(tmp_path)
    assert values["function"] == "CFoo::Bar"
    assert values["address"] == "0x401000"
    assert values["overlay_root"].endswith("overlay")
    assert oracle_values(MatchingConfig(), FunctionTarget("1", "", "f"), tmp_path / "x.c", None)["function"] == "f"


def test_expansion_is_single_pass_and_keeps_spaces():
    values = {"candidate_file": "/a b/{address}.cpp", "address": "0x1"}
    assert expand(["--file={candidate_file}", "{address}", "{unknown}"], values) == [
        "--file=/a b/{address}.cpp", "0x1", "{unknown}"]


def test_exact_and_partial_results(tmp_path):
    config = _oracle(tmp_path, "print(json.dumps({'exact': sys.argv[1] == '0x401000', 'score': 1.0 "
                               "if sys.argv[1] == '0x401000' else 0.5, 'diff': [{'offset': 16, 'kind': 'register',"
                               " 'target': 'mov ecx,1', 'candidate': 'mov eax,1'}], 'target_size': 8}))")
    exact = run_oracle(config, _values(tmp_path), str(tmp_path))
    assert exact.exact and exact.accepted and exact.score == 1.0
    assert exact.target_size == 8
    partial = run_oracle(config, {**_values(tmp_path), "address": "0x2"}, str(tmp_path))
    assert not partial.exact and partial.score == 0.5 and partial.error is None
    assert partial.diff == ["@0x10 register: target `mov ecx,1` | candidate `mov eax,1`"]
    assert partial.summary == "50.0% match"


def test_oracle_receives_environment(tmp_path):
    config = _oracle(tmp_path, "print(json.dumps({'exact': False, 'score': 0, "
                               "'summary': os.environ['RE_AGENT_TARGET_FUNCTION'] + os.environ['EXTRA']}))")
    assert run_oracle(config, _values(tmp_path), str(tmp_path), {"EXTRA": "!"}).summary == "CFoo::Bar!"


@pytest.mark.parametrize("payload", [
    "[]", "{}", '{"exact": 1, "score": 1}', '{"exact": true, "score": 0.9}', '{"exact": false, "score": 1.5}',
    '{"exact": false, "score": NaN}', '{"exact": false, "score": true}', '{"exact": false, "score": 0, "diff": "x"}',
    '{"exact": false, "score": 0, "target_size": -1}', "not json",
])
def test_malformed_output_is_an_oracle_error(tmp_path, payload):
    config = _oracle(tmp_path, f"print({payload!r})")
    verdict = run_oracle(config, _values(tmp_path), str(tmp_path))
    assert verdict.error is not None and verdict.error.startswith("Match oracle output rejected")
    assert not verdict.accepted


def test_compiler_failure_keeps_first_and_last_diagnostics(tmp_path):
    config = _oracle(tmp_path, "print('error: unknown type CVector', file=sys.stderr)\n"
                               "[print('cascade', i, file=sys.stderr) for i in range(40)]\n"
                               "print('1 error generated', file=sys.stderr); sys.exit(2)")
    verdict = run_oracle(config, _values(tmp_path), str(tmp_path))
    assert verdict.error is not None and verdict.error.startswith("Match oracle exit 2")
    assert "unknown type CVector" in verdict.error and "1 error generated" in verdict.error
    assert "cascade 20" not in verdict.error
    assert verdict.summary == "Match oracle exit 2"


def test_missing_executable_and_timeout_are_verdicts(tmp_path):
    missing = MatchingConfig(oracle_command=[str(tmp_path / "absent")])
    assert "could not start" in (run_oracle(missing, _values(tmp_path), str(tmp_path)).error or "")
    slow = _oracle(tmp_path, "import time; time.sleep(30)", timeout_s=1)
    assert "timed out" in (run_oracle(slow, _values(tmp_path), str(tmp_path)).error or "")


def test_diff_is_bounded_with_explicit_marker():
    lines = render_diff([f"line {i}" for i in range(50)] + [{"index": 3}, 7], 10)
    assert len(lines) == 10
    assert lines[-1] == "[43 more diff lines omitted]"
    assert render_diff([{"index": 3}, 7, {"kind": "extra", "candidate": "nop"}], 10) == [
        '{"index": 3}', "7", "extra: candidate `nop`"]


def test_parse_defaults_summary():
    verdict = parse_oracle_output(json.dumps({"exact": True, "score": 1}))
    assert verdict.summary == "Exact match" and verdict.diff == []


def test_forbidden_constructs_ignore_comments_and_literals():
    patterns = MatchingConfig().forbidden_patterns
    assert forbidden_constructs('int f() { /* __asm nop */ return puts("_emit"); }', patterns) == []
    assert forbidden_constructs("int f() { __asm { mov eax, 1 } }", patterns)
    assert forbidden_constructs("int f() { asm volatile(\"nop\"); return 0; }", patterns)
    assert forbidden_constructs("int f() {\n#pragma optimize(\"\", off)\n return 0; }", patterns)
    assert forbidden_constructs("int f() { __pragma(optimize(\"\", off)) return 0; }", patterns)
    assert forbidden_constructs("int f() { return asmTable[0] + _asm_count; }", patterns) == []


def test_permuter_contract(tmp_path):
    script = tmp_path / "permuter.py"
    config = MatchingConfig(permuter_command=[sys.executable, str(script), "{candidate_file}"])
    script.write_text("import json; print(json.dumps({'code': 'int f() { return 2; }'}))")
    assert run_permuter(config, _values(tmp_path), str(tmp_path)) == (
        "int f() { return 2; }", "permuter proposed a candidate")
    script.write_text("import json; print(json.dumps({'code': None}))")
    assert run_permuter(config, _values(tmp_path), str(tmp_path)) == (None, "permuter found no improvement")
    script.write_text("print('{}')")
    assert "rejected" in run_permuter(config, _values(tmp_path), str(tmp_path))[1]
    script.write_text("import sys; sys.exit(3)")
    assert "exit 3" in run_permuter(config, _values(tmp_path), str(tmp_path))[1]
