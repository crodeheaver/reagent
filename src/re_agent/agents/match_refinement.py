"""Score-guided search for a byte-identical candidate after the repair loop."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field

from re_agent.config.schema import MatchingConfig
from re_agent.core.models import ReversalResult
from re_agent.llm.observed import CallBudget

Propose = Callable[[ReversalResult, list[str]], list[str]]
Evaluate = Callable[[ReversalResult], ReversalResult]
Permute = Callable[[ReversalResult], tuple[str | None, str]]


@dataclass
class RefinementRound:
    number: int
    candidates: list[dict[str, object]] = field(default_factory=list)
    note: str = ""


@dataclass
class Refinement:
    best: ReversalResult
    rounds: int
    stop_reason: str


def rank(result: ReversalResult) -> float:
    """Order candidates by score; uncompared, failing or rejected ones rank below every score."""
    verdict = result.match_verdict
    if verdict is None or verdict.error or verdict.violations:
        return -1.0
    return verdict.score


def refine_match(
    start: ReversalResult,
    matching: MatchingConfig,
    propose: Propose,
    evaluate: Evaluate,
    budget: CallBudget,
    *,
    permute: Permute | None = None,
    on_round: Callable[[RefinementRound, ReversalResult], None] | None = None,
) -> Refinement:
    """Keep the best-scoring candidate, never the latest; stop on a match, a plateau or the budget."""
    best, stale, rounds = start, 0, 0
    attempts: list[str] = []
    seen = {_key(start.code)}
    permuted: set[str] = set()
    if _exact(start):
        return Refinement(start, 0, "exact match")

    def consider(code: str, origin: str, record: RefinementRound) -> bool:
        nonlocal best
        if _key(code) in seen:
            attempts.append(f"{origin}: resubmitted an earlier candidate")
            return False
        seen.add(_key(code))
        evaluated = evaluate(ReversalResult(start.target, code, rounds_used=start.rounds_used + rounds,
                                            run_id=start.run_id))
        attempts.append(f"{origin}: {_describe(evaluated)}")
        record.candidates.append({"origin": origin, "code": code, "score": rank(evaluated),
                                  "summary": evaluated.match_verdict.summary if evaluated.match_verdict else ""})
        if rank(evaluated) > rank(best):
            best = evaluated
            return True
        return False

    for number in range(1, matching.max_rounds + 1):
        if budget.used >= budget.limit:
            return Refinement(best, rounds, f"LLM call budget exhausted ({budget.used}/{budget.limit})")
        rounds = number
        record = RefinementRound(number)
        try:
            codes = propose(best, attempts)
        except ValueError as exc:
            codes, record.note = [], str(exc)
            attempts.append(f"round {number}: no usable candidate ({exc})")
        improved = False
        for index, code in enumerate(codes, 1):
            improved = consider(code, f"round {number}.{index}", record) or improved
            if _exact(best):
                break
        if (permute is not None and not improved and not _exact(best) and rank(best) >= matching.permuter_threshold
                and _key(best.code) not in permuted):
            permuted.add(_key(best.code))
            proposal, note = permute(best)
            record.note = (record.note + "; " if record.note else "") + note
            if proposal:
                improved = consider(proposal, f"round {number} permuter", record)
        if on_round is not None:
            on_round(record, best)
        if _exact(best):
            return Refinement(best, rounds, "exact match")
        stale = 0 if improved else stale + 1
        if stale >= matching.plateau_rounds:
            return Refinement(best, rounds, f"no improvement in {stale} rounds")
    return Refinement(best, rounds, f"matching round limit reached ({matching.max_rounds})")


def _exact(result: ReversalResult) -> bool:
    return result.match_verdict is not None and result.match_verdict.accepted


def _key(code: str) -> str:
    return hashlib.sha256(code.strip().encode()).hexdigest()


def _describe(result: ReversalResult) -> str:
    verdict = result.match_verdict
    if verdict is None:
        return "not compared"
    if verdict.violations:
        return "rejected: " + "; ".join(verdict.violations)
    if verdict.error:
        return "oracle error: " + verdict.error.splitlines()[0][:200]
    if verdict.exact:
        return "exact match"
    first = f" (first difference: {verdict.diff[0][:160]})" if verdict.diff else ""
    return f"{verdict.score:.1%} match{first}"
