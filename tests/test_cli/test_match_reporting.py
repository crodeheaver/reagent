"""Match outcomes survive sessions, journals and reports without inflating progress."""
from pathlib import Path

from re_agent.config.schema import ReAgentConfig
from re_agent.core.identity import project_fingerprint
from re_agent.core.models import FunctionTarget, MatchVerdict, ReversalResult
from re_agent.core.session import Session
from re_agent.core.target_plan import TargetPlan
from re_agent.orchestrator.parallel import decode_result
from re_agent.reports.coverage import format_coverage, manifest_coverage
from re_agent.reports.formatter import _result_to_dict, format_result, results_to_markdown
from re_agent.reports.tracker import ProgressTracker


def exact(size: int = 16) -> MatchVerdict:
    return MatchVerdict(True, 1.0, "Exact match", target_size=size, candidate_size=size)


def partial(size: int = 48) -> MatchVerdict:
    return MatchVerdict(False, 0.75, "75.0% match", diff=["@0x4 register: target `ecx` | candidate `eax`"],
                        target_size=size, candidate_size=size + 2)


def test_journal_roundtrip_preserves_match_verdict():
    result = ReversalResult(FunctionTarget("0x1", "", "f"), "int f();", success=True, match_verdict=exact())
    data = _result_to_dict(result)
    assert data["match_tier"] == "exact"
    decoded = decode_result(data)
    assert decoded.match_verdict == result.match_verdict
    assert decoded.match_tier == "exact"
    assert decode_result(_result_to_dict(ReversalResult(FunctionTarget("0x1", "", "f"), ""))).match_verdict is None


def test_tiers_distinguish_exact_functional_and_failed():
    target = FunctionTarget("0x1", "", "f")
    assert ReversalResult(target, "", success=True, match_verdict=partial()).match_tier == "functional"
    assert ReversalResult(target, "", success=False, match_verdict=exact()).match_tier is None
    rejected = MatchVerdict(True, 1.0, violations=["forbidden construct `__asm`"])
    assert ReversalResult(target, "", success=True, match_verdict=rejected).match_tier == "functional"


def test_terminal_and_markdown_output_show_match(tmp_path):
    result = ReversalResult(FunctionTarget("0x1", "", "f"), "int f();", match_verdict=partial())
    text = format_result(result)
    assert "Match: 75.0% | 75.0% match" in text
    assert "@0x4 register" in text
    assert results_to_markdown([result]).splitlines()[-1].endswith("| - | 75.0% |")


def test_session_summary_and_manifest_coverage_count_exact_bytes(tmp_path: Path):
    targets = [FunctionTarget(f"00000{i}00", "", f"f{i}") for i in range(1, 5)]
    plan = TargetPlan("a" * 64, [targets[0].address], targets)
    session = Session(tmp_path / "session.json")
    session.bind(plan.identity)
    session.record_result(ReversalResult(targets[0], "a", success=True, match_verdict=exact(16)))
    session.record_result(ReversalResult(targets[1], "b", success=True, match_verdict=partial(48)))
    session.record_result(ReversalResult(targets[2], "c", success=False,
                                         match_verdict=MatchVerdict(False, 0, error="Match oracle exit 1")))
    summary = session.get_summary()
    assert summary["exact_matches"] == 1
    assert "Exact matches:    1" in ProgressTracker(session).print_summary()
    assert [row["match"] for row in ProgressTracker(session).get_function_table()] == ["exact", "75.0%", "error"]
    report = manifest_coverage(plan, session, plan.identity)
    assert report["matching"] == {"exact": 1, "scored": 1, "exact_bytes": 16, "measured_bytes": 64}
    assert [row["match"] for row in report["functions"]] == ["exact", "75.0%", "error", "-"]
    assert "Exact matches: 1; scored without exact match: 1 (25.0% of 64 measured bytes)" in format_coverage(report)
    stale = manifest_coverage(plan, session, "b" * 64)
    assert stale["matching"]["exact"] == 0  # Stale results never count as progress.


def test_disabled_matching_keeps_project_identity(tmp_path):
    config = ReAgentConfig()
    config.project_profile.source_root = str(tmp_path)
    baseline = project_fingerprint(config)
    config.matching.oracle_command = ["oracle"]
    assert project_fingerprint(config) == baseline
    binary = tmp_path / "original.bin"
    binary.write_bytes(b"\x90\xc3")
    config.matching.enabled = True
    config.matching.original_binary = str(binary)
    enabled = project_fingerprint(config)
    assert enabled != baseline
    binary.write_bytes(b"\x90\x90\xc3")
    assert project_fingerprint(config) != enabled
