"""Local preflight skips review only for candidate-level rejections."""
from dataclasses import replace

import pytest

from re_agent.agents.loop import run_fix_loop
from re_agent.backend.stub import StubBackend
from re_agent.core.models import Finding, FunctionTarget, ValidationVerdict, Verdict
from tests.test_agents.test_loop import MockLLM

CANDIDATES = ["```cpp\nint f() { return 1; }\n```", "```cpp\nint f() { return 2; }\n```"]
PASS = '{"verdict":"PASS","summary":"Matches"}'


class RecordingLLM(MockLLM):
    def __init__(self, responses):
        super().__init__(responses)
        self.prompts = []

    def send(self, messages, **kwargs):
        self.prompts.append(messages[-1].content)
        return super().send(messages, **kwargs)


def _run(validation, parity=(), rounds=1):
    """Run the loop with a local gate that always reports *validation* and *parity*."""

    def local_gate(result):
        return replace(result, validation_verdict=validation, parity_findings=list(parity),
                       success=result.success and validation.verdict == Verdict.PASS and not parity)

    reverser, checker = RecordingLLM(CANDIDATES), MockLLM([PASS])
    result = run_fix_loop(FunctionTarget("100", "", "f"), StubBackend(), reverser, checker, max_rounds=rounds,
                          objective_verifier_enabled=False, candidate_gate=local_gate,
                          candidate_preflight=local_gate)
    return result, reverser, checker


@pytest.mark.parametrize("summary", [
    "Candidate overlay created; no build or test commands configured",
    "Configured commands passed but are not accepted as proof until "
    "validation.trust_configured_commands is explicitly enabled",
])
def test_configuration_level_unknown_still_gets_model_review(summary):
    result, _, checker = _run(ValidationVerdict(Verdict.UNKNOWN, summary))
    assert checker._idx == 1
    assert result.checker_verdict.summary == "Matches"
    assert not result.success  # The gate still decides acceptance.


def test_failed_gate_skips_review_and_reports_diagnostics_once():
    failed = ValidationVerdict(Verdict.FAIL, "Candidate build gate failed", ["build: exit 1\nerror: unique-diagnostic"])
    result, reverser, checker = _run(failed, rounds=2)
    assert checker._idx == 0
    assert result.checker_verdict.summary == "Local candidate preflight failed; model review skipped"
    assert reverser.prompts[1].count("unique-diagnostic") == 1


def test_parity_rejection_of_a_passing_build_skips_review():
    parity = [Finding("red", "Large disassembly with a tiny source body")]
    result, _, checker = _run(ValidationVerdict(Verdict.PASS, "All gates passed"), parity)
    assert checker._idx == 0
    assert result.checker_verdict.issues == ["parity: Large disassembly with a tiny source body"]


def test_unusable_candidate_shape_keeps_its_specific_fix_instruction():
    reverser, checker = MockLLM(["```cpp\nint f() { return 0; } int g() { return 1; }\n```"]), MockLLM([PASS])
    result = run_fix_loop(FunctionTarget("100", "", "f"), StubBackend(), reverser, checker, max_rounds=1,
                          objective_verifier_enabled=False, candidate_gate=lambda result: result)
    assert checker._idx == 0
    assert result.checker_verdict.fix_instructions == [
        "Return exactly one complete function definition without helper definitions."]
