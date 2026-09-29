"""Single function reversal pipeline."""

from __future__ import annotations

import logging
from pathlib import Path

from re_agent.agents.loop import run_fix_loop
from re_agent.backend.protocol import REBackend
from re_agent.config.schema import ReAgentConfig
from re_agent.core.models import (
    Finding,
    FunctionTarget,
    HookEntry,
    MatchVerdict,
    ReversalResult,
    SourceMatch,
    ValidationVerdict,
    Verdict,
)
from re_agent.core.session import Session
from re_agent.llm.protocol import LLMProvider
from re_agent.parity.engine import fetch_ghidra_data, score_single
from re_agent.parity.rules import read_semantic_rules
from re_agent.parity.source_indexer import SourceIndexer
from re_agent.verification.candidate import (
    _sanitize_path_component,
    _working_directory,
    cleanup_candidate_overlay,
    create_candidate_overlay,
    extract_candidate_body,
    validate_candidate,
)
from re_agent.verification.matching import (
    forbidden_constructs,
    oracle_values,
    qualified_name,
    run_oracle,
    run_permuter,
)

logger = logging.getLogger(__name__)


def reverse_single(
    target: FunctionTarget,
    config: ReAgentConfig,
    backend: REBackend,
    llm: LLMProvider,
    session: Session | None = None,
    output_dir: Path | None = None,
    indexer: SourceIndexer | None = None,
    checker_llm: LLMProvider | None = None,
) -> ReversalResult:
    """Reverse a single function: agent loop -> optional parity check -> record.

    Args:
        output_dir: If provided, write the generated code to a file in this
            directory.  The file is named ``<address>_<class>_<func>.cpp``.
        indexer: Pre-built source indexer.  When running multiple functions
            in the same class, callers should build the indexer once and pass
            it here to avoid re-scanning the entire source tree each time.
    """
    log_dir = Path(config.output.log_dir) if config.output.log_dir else None
    checked: ReversalResult | None = None

    # The loop decides whether a functional but non-matching candidate is final.
    loop_policy = False if config.matching.enabled else None

    def preflight(result: ReversalResult) -> ReversalResult:
        nonlocal checked
        checked = validate_result(result, config, backend, indexer, require_exact=loop_policy)
        return checked

    def gate(result: ReversalResult) -> ReversalResult:
        if checked is not None and checked.code == result.code:
            result.validation_verdict = checked.validation_verdict
            result.parity_status = checked.parity_status
            result.parity_findings = checked.parity_findings
            result.match_verdict = checked.match_verdict
            result.success = result.success and checked.success
            return result
        return validate_result(result, config, backend, indexer, require_exact=loop_policy)

    matching = config.matching if config.matching.enabled else None

    try:
        result = run_fix_loop(
            target=target,
            backend=backend,
            reverser_llm=llm,
            checker_llm=checker_llm or llm,
            max_rounds=config.orchestrator.max_review_rounds,
            log_dir=log_dir,
            source_root=Path(config.project_profile.source_root),
            project_profile=config.project_profile,
            indexer=indexer,
            session=session,
            report_dir=Path(config.output.report_dir),
            objective_verifier_enabled=config.orchestrator.objective_verifier_enabled,
            objective_call_count_tolerance=config.orchestrator.objective_call_count_tolerance,
            objective_control_flow_tolerance=config.orchestrator.objective_control_flow_tolerance,
            investigation_enabled=config.orchestrator.investigation_enabled,
            max_investigations=config.orchestrator.max_investigations,
            candidate_gate=gate,
            candidate_preflight=preflight if config.validation.enabled else None,
            max_llm_calls=config.orchestrator.max_llm_calls_per_function,
            matching=matching,
            match_gate=(lambda result: validate_result(result, config, backend, indexer, match_only=True))
            if matching else None,
            permute=(lambda result: permute_candidate(result, config, indexer))
            if matching and matching.permuter_command else None,
        )
    except (RuntimeError, OSError, ValueError) as exc:
        result = ReversalResult(target=target, code="", success=False, error=str(exc))
        logger.error("Reversal failed for %s: %s", target.address, exc)

    # Write generated code to a file so users don't have to dig through logs
    if result.code:
        code_dir = output_dir or (Path(config.output.report_dir) / "code")
        try:
            code_dir.mkdir(parents=True, exist_ok=True)
            safe_name = f"{target.address}_{target.class_name}_{target.function_name}.cpp"
            safe_name = _sanitize_path_component(safe_name)
            code_path = code_dir / safe_name
            code_path.write_text(result.code, encoding="utf-8")
            logger.info("Code written to %s", code_path)
        except OSError as exc:
            logger.warning("Failed to write code file: %s", exc)

    if session:
        session.record_result(result)

    return result


def _target_to_hook(target: FunctionTarget) -> HookEntry:
    return HookEntry(
        class_path=target.class_name,
        fn_name=target.function_name,
        address=target.address,
        reversed=True,
        locked=False,
        is_virtual=False,
    )


def validate_result(
    result: ReversalResult,
    config: ReAgentConfig,
    backend: REBackend,
    indexer: SourceIndexer | None = None,
    *,
    match_only: bool = False,
    require_exact: bool | None = None,
) -> ReversalResult:
    """Run the configured gates, or with ``match_only`` just the match oracle.

    ``require_exact=False`` lets the repair loop see functional acceptance of a
    non-matching candidate; promotion keeps the configured policy.
    """
    from re_agent.orchestrator.execution import validation_lane

    with validation_lane():
        if match_only:
            return _evaluate_match_only(result, config, indexer)
        return _validate_result(result, config, backend, indexer, require_exact)


def _resolve_source(target: FunctionTarget, indexer: SourceIndexer) -> SourceMatch | None:
    matches = indexer.find_all(target.class_name, target.function_name)
    if len(matches) > 1:
        locations = ", ".join(f"{match.path}:{match.line}" for match in matches)
        raise ValueError(
            f"Ambiguous overloaded source function; refusing to replace an arbitrary definition ({locations})"
        )
    original_source = indexer.find_by_address(target.address)
    if original_source is None:
        original_source = matches[0] if matches else indexer.find(target.class_name, target.function_name)
    return original_source


def _overlay(
    result: ReversalResult, config: ReAgentConfig, indexer: SourceIndexer | None
) -> tuple[Path, SourceMatch | None, SourceIndexer]:
    if indexer is None:
        indexer = SourceIndexer(Path(config.project_profile.source_root), config.project_profile)
    original_source = _resolve_source(result.target, indexer)
    candidate_file = create_candidate_overlay(
        result.target,
        result.code,
        original_source,
        Path(config.project_profile.source_root),
        Path(config.output.report_dir),
        project_root=Path(config.validation.project_root),
        copy_project=config.validation.copy_project,
        state_file=config.output.session_file,
    )
    return candidate_file, original_source, indexer


def _discard_overlay(candidate_file: Path | None, config: ReAgentConfig) -> bool:
    if candidate_file is None or not config.validation.copy_project or config.validation.keep_project_copy:
        return False
    cleanup_candidate_overlay(candidate_file)
    return True


def _match(
    config: ReAgentConfig,
    result: ReversalResult,
    candidate_file: Path,
    source: SourceMatch | None,
    extra_env: dict[str, str] | None = None,
) -> MatchVerdict:
    violations = forbidden_constructs(result.code, config.matching.forbidden_patterns)
    if violations:
        return MatchVerdict(False, 0.0, "Forbidden constructs; candidate not compared", violations=violations)
    values = oracle_values(config.matching, result.target, candidate_file, source.path if source else None)
    return run_oracle(config.matching, values, _working_directory(config.validation, candidate_file), extra_env)


def _evaluate_match_only(
    result: ReversalResult,
    config: ReAgentConfig,
    indexer: SourceIndexer | None,
    extra_env: dict[str, str] | None = None,
) -> ReversalResult:
    """Score one candidate with the oracle alone; other gates confirm exact matches later."""
    candidate_file: Path | None = None
    try:
        candidate_file, source, _ = _overlay(result, config, indexer)
        verdict = _match(config, result, candidate_file, source, extra_env)
    except (OSError, ValueError) as exc:
        verdict = MatchVerdict(False, 0.0, "Candidate overlay failed", error=str(exc))
    finally:
        _discard_overlay(candidate_file, config)
    return ReversalResult(
        target=result.target,
        code=result.code,
        rounds_used=result.rounds_used,
        success=verdict.accepted and config.validation.trust_configured_commands,
        run_id=result.run_id,
        match_verdict=verdict,
    )


def evaluate_source_match(
    target: FunctionTarget,
    config: ReAgentConfig,
    indexer: SourceIndexer | None = None,
    extra_env: dict[str, str] | None = None,
) -> MatchVerdict:
    """Score the definition already in the source tree, through the same overlay and oracle."""
    from re_agent.orchestrator.execution import validation_lane

    if indexer is None:
        indexer = SourceIndexer(Path(config.project_profile.source_root), config.project_profile)
    try:
        source = _resolve_source(target, indexer)
    except ValueError as exc:
        return MatchVerdict(False, 0.0, "Source definition is ambiguous", error=str(exc))
    if source is None:
        return MatchVerdict(False, 0.0, "Source definition not found",
                            error=f"No source definition for {qualified_name(target)}")
    with validation_lane():
        result = _evaluate_match_only(ReversalResult(target, source.body), config, indexer, extra_env)
    assert result.match_verdict is not None
    return result.match_verdict


def permute_candidate(
    result: ReversalResult, config: ReAgentConfig, indexer: SourceIndexer | None = None
) -> tuple[str | None, str]:
    """Hand the best candidate, overlaid in its project, to the configured permuter."""
    from re_agent.orchestrator.execution import validation_lane

    candidate_file: Path | None = None
    with validation_lane():
        try:
            candidate_file, source, _ = _overlay(result, config, indexer)
            values = oracle_values(config.matching, result.target, candidate_file, source.path if source else None)
            return run_permuter(config.matching, values, _working_directory(config.validation, candidate_file))
        except (OSError, ValueError) as exc:
            return None, f"permuter skipped: {exc}"
        finally:
            _discard_overlay(candidate_file, config)


def _validate_result(
    result: ReversalResult,
    config: ReAgentConfig,
    backend: REBackend,
    indexer: SourceIndexer | None = None,
    require_exact: bool | None = None,
) -> ReversalResult:
    """Validate one round and return its candidate-level diagnostics."""
    if require_exact is None:
        require_exact = config.matching.require_exact
    target = result.target
    if result.code:
        candidate_file: Path | None = None
        try:
            candidate_file, original_source, indexer = _overlay(result, config, indexer)
            candidate_body = extract_candidate_body(result.code)
            source = indexer.analyze_body(
                str(candidate_file),
                original_source.line if original_source else 1,
                candidate_body,
            )

            validation_verdict = validate_candidate(
                config.validation,
                candidate_file,
                original_source.path if original_source else None,
            )
            # A candidate that failed its build or tests has nothing meaningful to compare.
            match_verdict = (
                _match(config, result, candidate_file, original_source)
                if config.matching.enabled and validation_verdict.verdict != Verdict.FAIL
                else None
            )

            # Fetch Ghidra data from the backend for signal checks
            ghidra_data = None
            if config.parity.enabled and backend.capabilities.has_decompile:
                try:
                    ghidra_data = fetch_ghidra_data(target.address, backend)
                except Exception:
                    logger.debug("Ghidra data fetch failed for %s, running source-only", target.address, exc_info=True)

            status = None
            findings: list[Finding] = []
            if config.parity.enabled:
                status, findings = score_single(
                    entry=_target_to_hook(target),
                    source=source,
                    ghidra=ghidra_data,
                    config=config.parity,
                    semantic_rules=read_semantic_rules(Path(config.parity.semantic_rules_file))
                    if config.parity.semantic_rules_file
                    else None,
                )

            if not config.validation.enabled:
                validation_accepted = True
            elif config.validation.require_verified:
                validation_accepted = validation_verdict.verdict == Verdict.PASS
            else:
                validation_accepted = validation_verdict.verdict != Verdict.FAIL
            compiled = (match_verdict is not None and match_verdict.error is None and not match_verdict.violations
                        and config.validation.trust_configured_commands)
            if compiled and validation_verdict.verdict == Verdict.UNKNOWN:
                validation_accepted = True  # The trusted oracle compiled the candidate; no other gate exists.
            accepted = result.success and validation_accepted
            if status is not None:
                if config.validation.parity_fail_on_red and status.value == "red":
                    accepted = False
                if config.validation.parity_fail_on_yellow and status.value == "yellow":
                    accepted = False
            if config.matching.enabled:
                if (match_verdict is not None and match_verdict.accepted
                        and config.validation.trust_configured_commands):
                    # Identical bytes subsume model review and source heuristics; the
                    # configured gates still ran. With only the oracle, UNKNOWN is expected.
                    accepted = validation_verdict.verdict != Verdict.FAIL
                elif require_exact:
                    accepted = False
            result = ReversalResult(
                target=result.target,
                code=result.code,
                checker_verdict=result.checker_verdict,
                objective_verdict=result.objective_verdict,
                validation_verdict=validation_verdict,
                parity_status=status,
                parity_findings=findings,
                rounds_used=result.rounds_used,
                success=accepted,
                run_id=result.run_id,
                match_verdict=match_verdict,
            )
        except (FileNotFoundError, OSError, ValueError) as exc:
            logger.warning("Candidate validation failed for %s: %s", target.address, exc)
            result.validation_verdict = ValidationVerdict(
                verdict=Verdict.FAIL,
                summary="Candidate overlay/validation failed",
                findings=[str(exc)],
            )
            result.success = False
        finally:
            if _discard_overlay(candidate_file, config) and result.validation_verdict is not None:
                result.validation_verdict.overlay_file = None
                result.validation_verdict.findings.append(
                    "Temporary isolated project copy removed after validation"
                )

    return result
