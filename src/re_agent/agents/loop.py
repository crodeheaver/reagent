"""Fix loop — reverser -> checker -> fix, bounded by max rounds."""

from __future__ import annotations

import copy
import hashlib
import json
import time
import uuid
from collections.abc import Callable
from dataclasses import asdict, is_dataclass
from pathlib import Path

from re_agent.agents.checker import CheckerAgent
from re_agent.agents.match_refinement import Evaluate, Permute, RefinementRound, rank, refine_match
from re_agent.agents.reverser import ReverserAgent
from re_agent.backend.protocol import REBackend
from re_agent.config.schema import MatchingConfig, ProjectProfile
from re_agent.core.models import (
    CheckerVerdict,
    FunctionTarget,
    ObjectiveVerdict,
    ReversalResult,
    Verdict,
)
from re_agent.core.session import Session
from re_agent.llm.observed import CallBudget, ObservedProvider
from re_agent.llm.protocol import LLMProvider
from re_agent.parity.source_indexer import SourceIndexer
from re_agent.verification.candidate import extract_candidate_body, unresolved_placeholders
from re_agent.verification.objective import verify_candidate

_SHAPE_FIX = "Return exactly one complete function definition without helper definitions."
_EVIDENCE_FIX = "Resolve the reported issue using binary evidence; do not invent declarations for unknown targets."


def run_fix_loop(
    target: FunctionTarget,
    backend: REBackend,
    reverser_llm: LLMProvider,
    checker_llm: LLMProvider | None = None,
    max_rounds: int = 4,
    log_dir: Path | None = None,
    source_root: Path | None = None,
    project_profile: ProjectProfile | None = None,
    indexer: SourceIndexer | None = None,
    session: Session | None = None,
    report_dir: Path | None = None,
    objective_verifier_enabled: bool = True,
    objective_call_count_tolerance: int = 3,
    objective_control_flow_tolerance: int = 2,
    investigation_enabled: bool = True,
    max_investigations: int = 8,
    candidate_gate: Callable[[ReversalResult], ReversalResult] | None = None,
    max_llm_calls: int = 80,
    candidate_preflight: Callable[[ReversalResult], ReversalResult] | None = None,
    matching: MatchingConfig | None = None,
    match_gate: Evaluate | None = None,
    permute: Permute | None = None,
) -> ReversalResult:
    """Run the reverser->checker->fix loop up to max_rounds.

    With ``matching``, an exact byte match ends the loop without model review, and
    a functional or best-scoring candidate then enters score-guided refinement:
    ``match_gate`` scores candidates with the oracle alone and ``candidate_gate``
    confirms an exact match against every configured gate.

    Args:
        target: Function to reverse
        backend: RE backend for Ghidra data
        reverser_llm: LLM provider for the reverser agent
        checker_llm: LLM provider for the checker agent (defaults to reverser_llm)
        max_rounds: Maximum fix iterations
        log_dir: Directory to write prompt/response logs

    Returns:
        ReversalResult with the final code and verdict
    """
    if checker_llm is None:
        checker_llm = reverser_llm

    if max_rounds < 1:
        raise ValueError("max_rounds must be positive")
    run_id = uuid.uuid4().hex
    if log_dir:
        log_dir = log_dir / run_id
        log_dir.mkdir(parents=True, exist_ok=True)
    budget = CallBudget(max_llm_calls)
    reverser_llm = ObservedProvider(reverser_llm, budget, "reverser", log_dir)
    checker_llm = ObservedProvider(checker_llm, budget, "checker", log_dir)
    reverser = ReverserAgent(
        reverser_llm,
        backend,
        source_root=source_root,
        project_profile=project_profile,
        indexer=indexer,
        session=session,
        report_dir=report_dir,
        investigation_enabled=investigation_enabled,
        max_investigations=max_investigations,
        matching=matching,
    )
    checker = CheckerAgent(checker_llm, backend)

    if log_dir:
        log_dir.mkdir(parents=True, exist_ok=True)

    code = ""
    last_verdict: CheckerVerdict | None = None
    last_objective_verdict: ObjectiveVerdict | None = None

    result = ReversalResult(target=target, code="", run_id=run_id)
    gate_issues: list[str] = []
    seen_failures: set[str] = set()
    best_match: ReversalResult | None = None

    for round_num in range(1, max_rounds + 1):
        timestamp = time.strftime("%Y%m%d-%H%M%S")

        # Reverse (or fix)
        if round_num == 1:
            code, tag = reverser.reverse(target)
        else:
            assert last_verdict is not None
            code, tag = reverser.fix(
                checker_report=last_verdict.summary,
                issues=[*last_verdict.issues, *gate_issues],
                fix_instructions=last_verdict.fix_instructions,
                target=target,
                objective_findings=last_objective_verdict.findings if last_objective_verdict else None,
            )

        if log_dir:
            log_entry = {
                "round": round_num,
                "timestamp": timestamp,
                "phase": "reverse" if round_num == 1 else "fix",
                "target": f"{target.class_name}::{target.function_name}",
                "address": target.address,
                "prompt": reverser.last_prompt,
                "response": reverser.last_response,
                "code_length": len(code),
                "llm_metadata": _provider_metadata(reverser_llm),
            }
            log_path = log_dir / f"round{round_num}-{timestamp}-reverser.json"
            log_path.write_text(json.dumps(log_entry, indent=2), encoding="utf-8")

        # Avoid spending a reviewer call on output the configured candidate gate
        # cannot consume. Keep the same repair/checkpoint path as other failures.
        preflight_issues: list[str] = []
        fix_instruction = _EVIDENCE_FIX
        if candidate_gate is not None:
            try:
                extract_candidate_body(code)
            except ValueError as exc:
                preflight_issues = [str(exc)]
                fix_instruction = _SHAPE_FIX
        placeholders = unresolved_placeholders(code)
        if placeholders:
            preflight_issues = ["Unresolved decompiler placeholders: " + ", ".join(placeholders)]
            fix_instruction = _EVIDENCE_FIX
        if not preflight_issues and candidate_preflight is not None:
            checked = candidate_preflight(ReversalResult(
                target=target, code=code, success=True, rounds_used=round_num, run_id=run_id,
            ))
            # Skip review only when the local gate rejected this candidate itself: a
            # gate failed, or it passed but parity policy rejected it. UNKNOWN (no or
            # untrusted commands) is a configuration outcome that review cannot change.
            verdict_kind = checked.validation_verdict.verdict if checked.validation_verdict else None
            if matching is not None and checked.match_verdict is not None:
                if best_match is None or rank(checked) > rank(best_match):
                    best_match = checked
                if checked.success and checked.match_verdict.accepted:
                    # Identical bytes are stronger evidence than any review.
                    _log_skipped_review(log_dir, round_num, timestamp, checked)
                    if session is not None:
                        session.record_checkpoint(checked)
                    return checked
                if checked.match_verdict.error or checked.match_verdict.violations:
                    preflight_issues = _gate_issues(checked)
            if not checked.success and verdict_kind in (Verdict.FAIL, Verdict.PASS):
                preflight_issues = _gate_issues(checked)
        if preflight_issues:
            checker.last_prompt = ""
            checker.last_response = ""
            verdict = CheckerVerdict(
                verdict=Verdict.FAIL,
                summary="Local candidate preflight failed; model review skipped",
                issues=preflight_issues,
                fix_instructions=[fix_instruction],
            )
        else:
            verdict = checker.check(code, target)
        last_verdict = verdict

        objective_verdict: ObjectiveVerdict | None = None
        if objective_verifier_enabled:
            objective_verdict = verify_candidate(
                code,
                target,
                backend,
                call_count_tolerance=objective_call_count_tolerance,
                control_flow_tolerance=objective_control_flow_tolerance,
            )
        last_objective_verdict = objective_verdict

        if log_dir:
            check_log = {
                "round": round_num,
                "timestamp": timestamp,
                "phase": "check",
                "checker_skipped": bool(preflight_issues),
                "prompt": checker.last_prompt,
                "response": checker.last_response,
                "verdict": verdict.verdict.value,
                "summary": verdict.summary,
                "issues": verdict.issues,
                "fix_instructions": verdict.fix_instructions,
                "objective_verdict": objective_verdict.verdict.value if objective_verdict else None,
                "objective_summary": objective_verdict.summary if objective_verdict else "",
                "objective_findings": objective_verdict.findings if objective_verdict else [],
                "llm_metadata": _provider_metadata(checker_llm),
            }
            check_path = log_dir / f"round{round_num}-{timestamp}-checker.json"
            check_path.write_text(json.dumps(check_log, indent=2), encoding="utf-8")

        result = ReversalResult(
            target=target,
            code=code,
            checker_verdict=verdict,
            objective_verdict=objective_verdict,
            rounds_used=round_num,
            success=verdict.verdict == Verdict.PASS
            and (objective_verdict is None or objective_verdict.verdict != Verdict.FAIL),
            run_id=run_id,
        )
        if candidate_gate is not None:
            result = candidate_gate(result)
        # Preflight diagnostics already reach the fix prompt as checker issues.
        gate_issues = [issue for issue in _gate_issues(result) if issue not in verdict.issues]
        if log_dir:
            from re_agent.reports.formatter import results_to_json

            (log_dir / f"round{round_num}-result.json").write_text(results_to_json([result]), encoding="utf-8")
        if session is not None:
            session.record_checkpoint(result)
        if result.success:
            if matching is None or (result.match_verdict is not None and result.match_verdict.accepted):
                return result
            break  # Functionally accepted; refine towards identical bytes.
        failure_key = hashlib.sha256(
            json.dumps(
                [
                    code,
                    verdict.summary,
                    verdict.issues,
                    objective_verdict.findings if objective_verdict else [],
                    gate_issues,
                ],
                sort_keys=True,
            ).encode()
        ).hexdigest()
        if failure_key in seen_failures:
            result.error = "Stopped: identical candidate and diagnostics without progress"
            break
        seen_failures.add(failure_key)

    if matching is None:
        return result
    return _refine(result, best_match, matching, reverser, budget, match_gate, candidate_gate, permute,
                   session, log_dir)


def _refine(
    result: ReversalResult,
    best_match: ReversalResult | None,
    matching: MatchingConfig,
    reverser: ReverserAgent,
    budget: CallBudget,
    match_gate: Evaluate | None,
    candidate_gate: Callable[[ReversalResult], ReversalResult] | None,
    permute: Permute | None,
    session: Session | None,
    log_dir: Path | None,
) -> ReversalResult:
    """Search for an exact match, then decide between exact, functional and failed."""
    functional = result if result.success else None
    # Prefer the reviewed candidate; otherwise the closest compiled attempt.
    start = functional or best_match
    rounds = result.rounds_used
    if start is None:
        stop_reason = "no candidate reached the match oracle"
    elif match_gate is None or matching.max_rounds == 0:
        stop_reason = "matching refinement disabled"
    else:
        start.rounds_used = rounds

        def on_round(record: RefinementRound, best: ReversalResult) -> None:
            if log_dir:
                entry = {"round": rounds + record.number, "phase": "match", "prompt": reverser.last_prompt,
                         "response": reverser.last_response, "candidates": record.candidates, "note": record.note,
                         "best_score": rank(best), "llm_metadata": _provider_metadata(reverser.llm)}
                (log_dir / f"match{record.number}-{time.strftime('%Y%m%d-%H%M%S')}.json").write_text(
                    json.dumps(entry, indent=2), encoding="utf-8")
            if session is not None:
                checkpoint = copy.copy(best)
                checkpoint.rounds_used = rounds + record.number
                session.record_checkpoint(checkpoint)

        refinement = refine_match(start, matching, lambda best, attempts: reverser.propose_match(
            best.target, best, attempts), match_gate, budget, permute=permute, on_round=on_round)
        rounds += refinement.rounds
        stop_reason = refinement.stop_reason
        best = refinement.best
        if best.match_verdict is not None and best.match_verdict.accepted:
            confirmed = best
            if candidate_gate is not None:
                confirmed = candidate_gate(ReversalResult(best.target, best.code, success=True,
                                                          rounds_used=rounds, run_id=best.run_id))
            confirmed.rounds_used = rounds
            if confirmed.success and confirmed.match_verdict is not None and confirmed.match_verdict.accepted:
                return confirmed
            confirmed.success = False
            confirmed.error = "Exact match did not pass the configured validation gates"
            return confirmed
        if rank(best) > rank(start):
            start = best
    if functional is not None and not matching.require_exact:
        functional.rounds_used = rounds
        return functional
    final = copy.copy(start) if start is not None else result
    final.success = False
    final.rounds_used = rounds
    score = rank(final)
    earlier = f"; {result.error}" if start is None and result.error else ""
    final.error = (f"No exact match ({stop_reason}; best {score:.1%})" if score >= 0
                   else f"No exact match ({stop_reason}{earlier})")
    return final


def _gate_issues(result: ReversalResult) -> list[str]:
    issues = [f"parity: {f.reason}" for f in result.parity_findings]
    if result.validation_verdict and result.validation_verdict.verdict != Verdict.PASS:
        issues.extend([result.validation_verdict.summary, *result.validation_verdict.findings])
    match = result.match_verdict
    if match is not None and match.error:
        issues.append(match.error)
    if match is not None:
        issues.extend(match.violations)
    return issues


def _log_skipped_review(log_dir: Path | None, round_num: int, timestamp: str, result: ReversalResult) -> None:
    if not log_dir:
        return
    match = result.match_verdict
    entry = {"round": round_num, "timestamp": timestamp, "phase": "check", "checker_skipped": True,
             "reason": "exact byte match", "match_summary": match.summary if match else ""}
    (log_dir / f"round{round_num}-{timestamp}-checker.json").write_text(json.dumps(entry, indent=2), encoding="utf-8")


def _provider_metadata(provider: LLMProvider) -> dict[str, object]:
    metadata = getattr(provider, "last_metadata", None)
    if metadata is None:
        return {}
    if is_dataclass(metadata) and not isinstance(metadata, type):
        value = asdict(metadata)
        return {str(k): v for k, v in value.items()}
    if isinstance(metadata, dict):
        return {str(k): v for k, v in metadata.items()}
    return {}
