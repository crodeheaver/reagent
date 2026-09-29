"""Matching phase: exact matches skip review; refinement keeps the best candidate."""
from __future__ import annotations

import copy

from re_agent.agents.loop import run_fix_loop
from re_agent.backend.stub import StubBackend
from re_agent.config.schema import MatchingConfig
from re_agent.core.models import FunctionTarget, MatchVerdict, ReversalResult
from tests.test_agents.test_loop import MockLLM

TARGET = FunctionTarget("0x401000", "", "f")
PASS = '{"verdict":"PASS","summary":"Matches the decompile"}'


def block(*codes: str) -> str:
    return "\n".join(f"```cpp\n{code}\n```" for code in codes)


class Gates:
    """Deterministic stand-ins for overlay validation and the match oracle."""

    def __init__(self, scores: dict[str, float], compiles: bool = True) -> None:
        self.scores, self.compiles = scores, compiles
        self.full: list[str] = []
        self.matched: list[str] = []

    def verdict(self, code: str) -> MatchVerdict:
        if not self.compiles:
            return MatchVerdict(False, 0.0, "Match oracle exit 1", error="Match oracle exit 1\nerror: bad type")
        score = self.scores.get(code, 0.1)
        return MatchVerdict(score == 1.0, score, "exact" if score == 1.0 else f"{score:.0%}",
                            diff=[] if score == 1.0 else ["@0x4 register: target `ecx` | candidate `eax`"])

    def gate(self, result: ReversalResult) -> ReversalResult:
        """Functional acceptance keeps model review; exact bytes override it."""
        self.full.append(result.code)
        checked = copy.copy(result)
        checked.match_verdict = self.verdict(result.code)
        checked.success = checked.match_verdict.accepted or (result.success and checked.match_verdict.error is None)
        return checked

    def match(self, result: ReversalResult) -> ReversalResult:
        self.matched.append(result.code)
        checked = copy.copy(result)
        checked.match_verdict = self.verdict(result.code)
        checked.success = checked.match_verdict.accepted
        return checked


def run(gates: Gates, reverser: MockLLM, checker: MockLLM, matching: MatchingConfig, **kwargs: object):
    return run_fix_loop(TARGET, StubBackend(), reverser, checker, max_rounds=2, objective_verifier_enabled=False,
                        investigation_enabled=False, candidate_gate=gates.gate, candidate_preflight=gates.gate,
                        matching=matching, match_gate=gates.match, **kwargs)  # type: ignore[arg-type]


def test_exact_candidate_skips_model_review():
    gates = Gates({"int f() { return 2; }": 1.0})
    checker = MockLLM([PASS])
    result = run(gates, MockLLM([block("int f() { return 2; }")]), checker, MatchingConfig(enabled=True))
    assert result.success and result.match_tier == "exact"
    assert checker._idx == 0
    assert result.rounds_used == 1


def test_refinement_keeps_best_candidate_and_confirms_exact_match():
    functional, worse, exact = "int f() { return 1+1; }", "int f() { return 3-1; }", "int f() { return 2; }"
    gates = Gates({functional: 0.5, worse: 0.4, exact: 1.0})
    reverser = MockLLM([block(functional), block(worse, exact)])
    checker = MockLLM([PASS])
    result = run(gates, reverser, checker, MatchingConfig(enabled=True, candidates_per_round=2))
    assert result.success and result.match_tier == "exact"
    assert result.code == exact
    assert result.rounds_used == 2
    assert checker._idx == 1
    assert gates.matched == [worse, exact]
    assert gates.full[-1] == exact  # Every configured gate confirms the exact match.


def test_plateau_returns_best_score_without_accepting_functional_candidate():
    functional = "int f() { return 1+1; }"
    gates = Gates({functional: 0.5, "int f() { return 9; }": 0.3, "int f() { return 8; }": 0.2})
    reverser = MockLLM([block(functional), block("int f() { return 9; }"), block("int f() { return 8; }")])
    result = run(gates, reverser, MockLLM([PASS]), MatchingConfig(enabled=True, plateau_rounds=2))
    assert not result.success
    assert result.code == functional
    assert result.error == "No exact match (no improvement in 2 rounds; best 50.0%)"
    assert result.rounds_used == 3


def test_resubmitted_candidates_are_not_rescored():
    functional = "int f() { return 1+1; }"
    gates = Gates({functional: 0.5})
    reverser = MockLLM([block(functional), block(functional)])
    result = run(gates, reverser, MockLLM([PASS]), MatchingConfig(enabled=True, plateau_rounds=2))
    assert gates.matched == []
    assert "no improvement in 2 rounds" in (result.error or "")


def test_functional_result_is_kept_when_exact_is_not_required():
    functional = "int f() { return 1+1; }"
    gates = Gates({functional: 0.5})
    reverser = MockLLM([block(functional), block("int f() { return 7; }")])
    result = run(gates, reverser, MockLLM([PASS]),
                 MatchingConfig(enabled=True, require_exact=False, plateau_rounds=1))
    assert result.success and result.match_tier == "functional"
    assert result.code == functional
    assert result.match_verdict is not None and result.match_verdict.score == 0.5


def test_budget_exhaustion_returns_best_candidate():
    functional = "int f() { return 1+1; }"
    gates = Gates({functional: 0.5, "int f() { return 7; }": 0.6})
    reverser = MockLLM([block(functional), block("int f() { return 7; }"), block("int f() { return 6; }")])
    result = run(gates, reverser, MockLLM([PASS]), MatchingConfig(enabled=True), max_llm_calls=3)
    assert not result.success
    assert result.code == "int f() { return 7; }"
    assert "LLM call budget exhausted (3/3)" in (result.error or "")


def test_permuter_runs_once_on_plateau_above_threshold_and_is_rescored():
    functional, exact = "int f() { return 1+1; }", "int f() { return 2; }"
    gates = Gates({functional: 0.95, exact: 1.0})
    calls: list[str] = []

    def permute(best: ReversalResult) -> tuple[str | None, str]:
        calls.append(best.code)
        return exact, "permuter proposed a candidate"

    reverser = MockLLM([block(functional), block("int f() { return 5; }")])
    result = run(gates, reverser, MockLLM([PASS]), MatchingConfig(enabled=True, permuter_threshold=0.9),
                 permute=permute)
    assert calls == [functional]
    assert result.success and result.code == exact


def test_oracle_error_skips_review_and_feeds_repair():
    gates = Gates({}, compiles=False)
    reverser = MockLLM([block("int f() { return x; }"), block("int f() { return y; }")])
    checker = MockLLM([PASS])
    result = run(gates, reverser, checker, MatchingConfig(enabled=True))
    assert checker._idx == 0
    assert not result.success
    assert result.error is not None and result.error.startswith("No exact match")


class AsmBackend(StubBackend):
    def get_asm(self, target: str):  # type: ignore[override]
        from re_agent.core.models import AsmResult

        return AsmResult(target, "401000 lea eax,[rdi+0x2]\n401003 ret", 2, 0, False)


def test_propose_match_builds_a_bounded_prompt_and_reads_c_fences():
    from re_agent.agents.reverser import ReverserAgent

    llm = MockLLM(["```c\nint f(int x) { return x + 2; }\n```\n```cpp\nint f(int x) { return 2 + x; }\n```\n"
                   "```c\nint f(int x) { return x - -2; }\n```"])
    matching = MatchingConfig(enabled=True, candidates_per_round=2, prompt_hints=["Declare locals in reverse"])
    agent = ReverserAgent(llm, AsmBackend(), matching=matching)
    best = ReversalResult(TARGET, "int f(int x) { return x + 1 + 1; }", match_verdict=MatchVerdict(
        False, 0.5, "1 differing instructions", diff=["@0x0 mismatch: target `lea eax,[rdi+0x2]` | candidate `x`"],
        target_size=4, candidate_size=6))
    codes = agent.propose_match(TARGET, best, ["round 1.1: 40.0% match"])
    assert codes == ["int f(int x) { return x + 2; }", "int f(int x) { return 2 + x; }"]
    for expected in ("50.0% match", "Size: target 4 bytes, candidate 6 bytes", "401003 ret",
                     "- round 1.1: 40.0% match", "- Declare locals in reverse", "`\\b__asm\\b`", "Return 2 distinct"):
        assert expected in agent.last_prompt


def test_propose_match_rejects_evidence_requests():
    import pytest

    from re_agent.agents.reverser import ReverserAgent

    agent = ReverserAgent(MockLLM(['{"actions":[{"tool":"decompile"}]}']), StubBackend(),
                          matching=MatchingConfig(enabled=True))
    with pytest.raises(ValueError, match="cannot request evidence"):
        agent.propose_match(TARGET, ReversalResult(TARGET, "int f();"), [])


def test_c_fences_are_extracted_in_repair_rounds():
    from re_agent.agents.reverser import ReverserAgent

    assert ReverserAgent._extract_code("Here:\n```c\nint f(void) { return 1; }\n```") == "int f(void) { return 1; }"
