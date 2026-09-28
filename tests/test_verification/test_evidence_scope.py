"""Expanded or incomplete IR must neither drive repairs nor reject accepted candidates."""
import json

import pytest

from re_agent.agents.loop import run_fix_loop
from re_agent.backend.protocol import BackendCapabilities
from re_agent.backend.stub import StubBackend
from re_agent.core.models import AnalysisArtifact, AsmResult, FunctionTarget, Verdict
from re_agent.verification.objective import verify_candidate
from tests.test_agents.test_loop import MockLLM


class ScopeBackend(StubBackend):
    def __init__(self, address="200", listing="100 CALL RAX\n102 JMP RBX", calls=1):
        self.ir_address = address
        self.listing = listing
        self.calls = calls

    @property
    def capabilities(self):
        return BackendCapabilities(has_asm=True, has_pcode=True)

    def get_asm(self, address):
        return AsmResult(address, self.listing, 2, 1, False)

    def get_pcode(self, address):
        return AnalysisArtifact("pcode", address, json.dumps({"data": [
            {"address": self.ir_address, "opcode": "CALLIND"} for _ in range(self.calls)]}))


def test_out_of_scope_ir_is_reported_and_its_comparison_skipped():
    # Five out-of-scope IR calls would otherwise be a P-code call mismatch.
    result = verify_candidate("void f() {}", FunctionTarget("100", "", "f"), ScopeBackend(calls=5))
    assert result.evidence_conflict
    assert result.verdict == Verdict.PASS
    assert result.findings == []
    assert "p-code comparison skipped" in result.summary and "first: 200" in result.summary


def test_matching_ir_scope_does_not_block_candidate():
    result = verify_candidate("void f() {}", FunctionTarget("100", "", "f"), ScopeBackend("0x100"))
    assert not result.evidence_conflict


@pytest.mark.parametrize("listing", [
    "PUSH EBP\nADD ESP, 8\nDEC ECX\nADC EAX, 1",  # mnemonics are not addresses
    "100 PUSH EBP\n102 CALL RAX\n[truncated; request specific evidence]",
    "100 PUSH EBP\n102 CALL RAX\n...",
    "100 PUSH EBP\n1FA CALL RAX",  # listing stops right before the IR continues
], ids=["no-addresses", "marker", "ellipsis", "cut-off"])
def test_unaddressed_or_truncated_listings_are_not_scope_conflicts(listing):
    result = verify_candidate("void f() {}", FunctionTarget("100", "", "f"), ScopeBackend(listing=listing, calls=5))
    assert not result.evidence_conflict
    # The complete IR is still compared against the candidate.
    assert any("P-code call mismatch" in finding for finding in result.findings)


def test_evidence_conflict_does_not_reject_an_accepted_candidate():
    reverser = MockLLM(["```cpp\nvoid f() {}\n```"])
    checker = MockLLM(['{"verdict":"PASS","summary":"Matches assembly"}'])
    result = run_fix_loop(FunctionTarget("100", "", "f"), ScopeBackend(calls=5), reverser, checker, max_rounds=3)
    assert result.success
    assert result.error is None
    assert result.objective_verdict.evidence_conflict
    assert result.rounds_used == 1
    assert reverser._idx == checker._idx == 1
