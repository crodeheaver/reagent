"""Deterministic scheduler tests without network/model requests."""
import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import Mock

import pytest

from re_agent.config.schema import ReAgentConfig
from re_agent.core.models import FunctionTarget, ReversalResult
from re_agent.core.session import Session
from re_agent.orchestrator.execution import current
from re_agent.orchestrator.parallel import reverse_parallel


@pytest.fixture
def setup(tmp_path):
    config = ReAgentConfig()
    config.output.report_dir = str(tmp_path / "reports")
    config.output.session_file = str(tmp_path / "session.json")
    config.project_profile.source_root = str(tmp_path / "source")
    config.orchestrator.max_parallel_functions = 2
    config.orchestrator.max_attempts_per_function = 1
    config.orchestrator.selection_strategy = "high-impact"
    config.validation.enabled = False
    config.parity.enabled = False
    backend = Mock()
    backend.xrefs_from.return_value = []
    targets = [FunctionTarget(hex(i), "C", f"f{i}") for i in range(1, 5)]
    return config, backend, targets, Session(config.output.session_file)


@pytest.mark.parametrize("workers", [1, 2, 4])
def test_bounded_overlap_isolation_order_and_checkpoints(setup, monkeypatch, workers):
    config, backend, targets, session = setup
    config.orchestrator.max_parallel_functions = workers
    barrier = threading.Barrier(workers)
    paths, providers = [], []
    lock = threading.Lock()

    def fake(target, cfg, backend, llm, *, checker_llm, session):
        with lock:
            paths.append(cfg.output.report_dir)
            providers.extend([llm, checker_llm])
        barrier.wait(timeout=10)
        current().emit("call", "reverser")
        result = ReversalResult(target, code="int f() { return 1; }", success=True, rounds_used=1)
        session.record_checkpoint(result)
        return result

    monkeypatch.setattr("re_agent.orchestrator.parallel.reverse_single", fake)
    result = reverse_parallel([*targets, targets[0]], config, backend, session, lambda c: Mock(), 4)
    assert [r.target for r in result] == targets
    assert len(set(paths)) == 4
    assert len({id(p) for p in providers}) == 8
    assert all(p.close.call_count == 1 for p in providers)
    assert all(session.attempt_count(t.address) == 1 for t in targets)
    journal = {p.stem: json.loads(p.read_text()) for p in Path(config.output.report_dir).glob("parallel/*/jobs/*.json")}
    assert all(j["calls"] == 1 and j["rounds"] == 1 for j in journal.values())
    # Recovery publication is idempotent, including completed jobs.
    assert reverse_parallel(targets, config, backend, session, lambda c: Mock(), 4) == []
    assert all(session.attempt_count(t.address) == 1 for t in targets)


def test_stop_keeps_results_that_finished(setup, monkeypatch):
    config, backend, targets, session = setup
    cancel = threading.Event()

    def finished(target, cfg, backend, llm, **kwargs):
        current().emit("checkpoint", ReversalResult(target, code="late", success=True, rounds_used=1))
        cancel.set()  # Stop arrives after the attempt finished, before publication.
        return ReversalResult(target, code="late", success=True, rounds_used=1)

    monkeypatch.setattr("re_agent.orchestrator.parallel.reverse_single", finished)
    result = reverse_parallel(targets[:1], config, backend, session, lambda c: Mock(), 1, cancel=cancel)
    assert [(r.code, r.success) for r in result] == [("late", True)]
    assert session.is_completed(targets[0].address) and session.attempt_count(targets[0].address) == 1
    assert json.loads(session.path.with_suffix(".json.execution.json").read_text())["phase"] == "stopped"


def test_interrupted_attempt_keeps_recorded_success_without_new_calls(setup, monkeypatch):
    config, backend, targets, session = setup
    config.orchestrator.max_review_rounds = 2
    cancel = threading.Event()

    def interrupted(target, cfg, backend, llm, *, session, **kwargs):
        session.record_checkpoint(ReversalResult(target, code="accepted", success=True, rounds_used=2))
        cancel.set()
        current().check()  # Cancelled after the final round was recorded.

    monkeypatch.setattr("re_agent.orchestrator.parallel.reverse_single", interrupted)
    assert reverse_parallel(targets[:1], config, backend, session, lambda c: Mock(), 1, cancel=cancel) == []
    monkeypatch.setattr("re_agent.orchestrator.parallel.reverse_single", Mock(side_effect=AssertionError))
    result = reverse_parallel(targets[:1], config, backend, session, lambda c: Mock(), 1)
    assert [(r.code, r.success, r.rounds_used) for r in result] == [("accepted", True, 2)]
    assert session.attempt_count(targets[0].address) == 1


def test_cancel_interrupted_attempt_and_resume_budget(setup, monkeypatch):
    config, backend, targets, session = setup
    cancel = threading.Event()
    budgets = []

    def interrupted(target, cfg, backend, llm, **kwargs):
        current().emit("call", "reverser")
        current().emit("checkpoint", ReversalResult(target, code="draft", rounds_used=1))
        cancel.set()
        current().check()

    monkeypatch.setattr("re_agent.orchestrator.parallel.reverse_single", interrupted)
    assert reverse_parallel(targets[:1], config, backend, session, lambda c: Mock(), 1, cancel=cancel) == []
    assert session.attempt_count(targets[0].address) == 0

    def resumed(target, cfg, backend, llm, **kwargs):
        budgets.append((cfg.orchestrator.max_llm_calls_per_function, cfg.orchestrator.max_review_rounds))
        return ReversalResult(target, code="accepted", success=True, rounds_used=1)

    monkeypatch.setattr("re_agent.orchestrator.parallel.reverse_single", resumed)
    config.orchestrator.max_parallel_functions = 4
    config.orchestrator.max_parallel_requests = 2
    result = reverse_parallel(targets[:1], config, backend, session, lambda c: Mock(), 1)
    assert budgets == [(config.orchestrator.max_llm_calls_per_function - 1,
                        config.orchestrator.max_review_rounds - 1)]
    assert result[0].rounds_used == 2
    assert session.attempt_count(targets[0].address) == 1


def test_retry_limit_and_failure_independence(setup, monkeypatch):
    config, backend, targets, session = setup
    config.orchestrator.max_attempts_per_function = 2

    def fake(target, *args, **kwargs):
        return ReversalResult(target, code="", success=target != targets[0])

    monkeypatch.setattr("re_agent.orchestrator.parallel.reverse_single", fake)
    result = reverse_parallel(targets, config, backend, session, lambda c: Mock(), 5)
    assert len(result) == 5
    assert session.attempt_count(targets[0].address) == 2
    assert all(session.is_completed(t.address) for t in targets[1:])


@pytest.mark.parametrize("outcome", ["empty", "raise"])
def test_rerun_after_failed_job_without_code(setup, monkeypatch, outcome):
    config, backend, targets, session = setup

    def fake(target, *args, **kwargs):
        if outcome == "raise":
            raise KeyError("worker bug")
        return ReversalResult(target, code="", success=False, error="no candidate")

    monkeypatch.setattr("re_agent.orchestrator.parallel.reverse_single", fake)
    assert len(reverse_parallel(targets[:2], config, backend, session, lambda c: Mock(), 4)) == 2
    # Recovery replays the journal, including failures that never produced code.
    rerun = Session(config.output.session_file)
    assert reverse_parallel(targets[:2], config, backend, rerun, lambda c: Mock(), 4) == []
    assert all(rerun.attempt_count(t.address) == 1 for t in targets[:2])


def test_resumed_job_with_artifacts_runs_real_pipeline_without_empty_feedback(tmp_path, monkeypatch):
    from re_agent.backend.stub import StubBackend
    from re_agent.orchestrator import parallel
    from tests.test_agents.test_loop import MockLLM
    from tests.test_audit_regressions import config_for

    config = config_for(tmp_path)
    config.validation.enabled = False
    config.orchestrator.max_parallel_functions = 2
    target = FunctionTarget("0x1", "C", "f")
    session, cancel = Session(config.output.session_file), threading.Event()

    def interrupted(target, cfg, *args, **kwargs):
        code = Path(cfg.output.report_dir) / "code"
        code.mkdir(parents=True)
        (code / "draft.cpp").write_text("int f() { return 0; }")
        cancel.set()
        current().check()

    real = parallel.reverse_single
    monkeypatch.setattr(parallel, "reverse_single", interrupted)
    assert reverse_parallel([target], config, StubBackend(), session, lambda c: Mock(), 1, cancel=cancel) == []
    monkeypatch.setattr(parallel, "reverse_single", real)
    prompts = []

    class Recording(MockLLM):
        def send(self, messages, **kwargs):
            prompts.append(messages[-1].content)
            return super().send(messages, **kwargs)

    def factory(cfg):
        return Recording(['```cpp\nint f() { return 1; }\n```', '{"verdict":"PASS"}'])

    result = reverse_parallel([target], config, StubBackend(), session, factory, 1)
    assert [r.success for r in result] == [True], result
    assert prompts and "Previous attempt checkpoint" not in prompts[0]


def test_competing_coordinator_lease(setup, monkeypatch):
    config, backend, targets, session = setup
    entered, release = threading.Event(), threading.Event()

    def fake(target, *args, **kwargs):
        entered.set()
        assert release.wait(10)
        return ReversalResult(target, code="", success=True)

    monkeypatch.setattr("re_agent.orchestrator.parallel.reverse_single", fake)
    with ThreadPoolExecutor() as pool:
        first = pool.submit(reverse_parallel, targets[:1], config, backend, session, lambda c: Mock(), 1)
        assert entered.wait(10)
        try:
            with pytest.raises(OSError):
                reverse_parallel(targets[:1], config, backend, session, lambda c: Mock(), 1)
        finally:
            release.set()
        assert len(first.result(timeout=10)) == 1


@pytest.mark.parametrize("workers", [1, 2, 4])
def test_full_manifest_pipeline_all_workers(tmp_path, workers):
    from re_agent.backend.stub import StubBackend
    from re_agent.config.schema import LLMConfig
    from re_agent.core.target_plan import TargetPlan
    from re_agent.orchestrator.batch_runner import reverse_manifest
    from tests.test_agents.test_loop import MockLLM
    from tests.test_audit_regressions import config_for

    config = config_for(tmp_path)
    config.validation.enabled = False
    config.orchestrator.max_parallel_functions = workers
    config.agents.reverser = LLMConfig(model="reverse")
    config.agents.checker = LLMConfig(model="check")
    targets = [FunctionTarget(hex(i), "", "f") for i in range(1, 5)]

    def factory(cfg):
        return MockLLM(['{"verdict":"PASS"}'] if cfg.model == "check" else ['```cpp\nint f() { return 1; }\n```'])

    result = reverse_manifest(TargetPlan("a" * 64, [], targets), config, StubBackend(),
                              factory(config.agents.reverser), Session(config.output.session_file), 4,
                              factory(config.agents.checker), provider_factory=factory)
    assert len(result) == 4
    assert all(r.success and r.checker_verdict.verdict.value == "PASS" for r in result)


def test_cumulative_proposals_same_file_revalidate_latest_generation(tmp_path, monkeypatch):
    from re_agent.backend.stub import StubBackend
    from re_agent.core.target_plan import TargetPlan
    from re_agent.orchestrator.batch_runner import reverse_manifest
    from tests.test_audit_regressions import config_for

    config = config_for(tmp_path)
    config.validation.enabled = False
    config.validation.copy_project = True
    config.validation.project_root = str(tmp_path)
    config.orchestrator.max_parallel_functions = 2
    config.orchestrator.max_attempts_per_function = 1
    source = Path(config.project_profile.source_root) / "f.cpp"
    original = "int a() { return 0; }\nint b() { return 0; }\n"
    source.write_text(original)
    targets = [FunctionTarget("1", "", "a"), FunctionTarget("2", "", "b")]
    barrier = threading.Barrier(2)
    snapshots, generations = [], []

    def fake(target, cfg, *args, **kwargs):
        snapshot = Path(cfg.project_profile.source_root) / "f.cpp"
        snapshots.append(snapshot)
        assert snapshot.read_text() == original
        barrier.wait(timeout=10)
        return ReversalResult(target, f"int {target.function_name}() {{ return 7; }}", success=True)

    def validate(result, cfg, backend):
        current_source = (Path(cfg.project_profile.source_root) / "f.cpp").read_text()
        generations.append(current_source)
        if result.target.function_name == "b":
            assert "int a() { return 7; }" in current_source
            result.success = False  # A stale proposal cannot leak a provisional PASS.
        return result

    monkeypatch.setattr("re_agent.orchestrator.parallel.reverse_single", fake)
    monkeypatch.setattr("re_agent.orchestrator.class_runner.validate_result", validate)
    session = Session(config.output.session_file)
    result = reverse_manifest(TargetPlan("a" * 64, [], targets), config, StubBackend(), None,
                              session, 2, provider_factory=lambda c: Mock())
    assert [r.success for r in result] == [True, False]
    assert source.read_text() == original
    assert len(set(snapshots)) == 2 and all(not p.exists() for p in snapshots)
    assert not session.is_completed("2")


@pytest.mark.parametrize("stage", ["waiting", "promoting"])
def test_stop_keeps_cumulative_proposal_for_next_run(tmp_path, monkeypatch, stage):
    from re_agent.backend.stub import StubBackend
    from re_agent.core.target_plan import TargetPlan
    from re_agent.orchestrator.batch_runner import reverse_manifest
    from tests.test_audit_regressions import config_for

    config = config_for(tmp_path)
    config.validation.enabled = False
    config.validation.copy_project = True
    config.validation.project_root = str(tmp_path)
    config.orchestrator.max_parallel_functions = 2
    config.orchestrator.max_attempts_per_function = 1
    source = Path(config.project_profile.source_root) / "f.cpp"
    source.write_text("int a() { return 0; }\nint b() { return 0; }\n")
    plan = TargetPlan("a" * 64, [], [FunctionTarget("1", "", "a"), FunctionTarget("2", "", "b")])
    session = Session(config.output.session_file)
    stop = session.path.with_suffix(".json.execution.stop")
    b_done, calls, first_run = threading.Event(), [], [True]

    def fake(target, cfg, *args, **kwargs):
        calls.append(target.function_name)
        if target.function_name == "b":
            b_done.set()
        elif stage == "waiting" and first_run[0]:  # b finishes first and waits for a's promotion
            assert b_done.wait(10)
            stop.write_text("")
            while True:
                current().check()
                time.sleep(.01)
        return ReversalResult(target, f"int {target.function_name}() {{ return 7; }}", success=True)

    def validate(result, cfg, backend):
        if stage == "promoting" and first_run[0]:
            stop.write_text("")
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                current().check()  # Promotion validation observes the stop.
                time.sleep(.01)
        return result

    monkeypatch.setattr("re_agent.orchestrator.parallel.reverse_single", fake)
    monkeypatch.setattr("re_agent.orchestrator.class_runner.validate_result", validate)
    first = reverse_manifest(plan, config, StubBackend(), None, session, 4, provider_factory=lambda c: Mock())
    assert json.loads(session.path.with_suffix(".json.execution.json").read_text())["phase"] == "stopped"
    assert not any(r.success for r in first) and not session.is_completed("2")
    calls.clear()
    first_run[0] = False
    reverse_manifest(plan, config, StubBackend(), None, session, 4, provider_factory=lambda c: Mock())
    assert session.is_completed("1") and session.is_completed("2")
    assert calls == (["a"] if stage == "waiting" else [])  # The finished proposal is not re-run.
    assert all(session.attempt_count(a) == 1 for a in ("1", "2"))


def test_unpromotable_proposal_fails_its_attempt(tmp_path, monkeypatch):
    from re_agent.backend.stub import StubBackend
    from re_agent.core.target_plan import TargetPlan
    from re_agent.orchestrator.batch_runner import reverse_manifest
    from tests.test_audit_regressions import config_for

    config = config_for(tmp_path)
    config.validation.enabled = False
    config.validation.copy_project = True
    config.validation.project_root = str(tmp_path)
    config.orchestrator.max_parallel_functions = 2
    config.orchestrator.max_attempts_per_function = 1
    monkeypatch.setattr("re_agent.orchestrator.parallel.reverse_single",
                        lambda target, *a, **k: ReversalResult(target, "int missing() { return 1; }", success=True))
    session = Session(config.output.session_file)
    plan = TargetPlan("a" * 64, [], [FunctionTarget("1", "", "missing")])
    for _ in range(2):  # The journaled outcome must not fail recovery either.
        reverse_manifest(plan, config, StubBackend(), None, session, 1, provider_factory=lambda c: Mock())
    assert not session.is_completed("1") and session.attempt_count("1") == 1
    assert "unique source definition" in session.get_all_functions()[0]["error"]


@pytest.mark.parametrize("error", [ValueError, RuntimeError])
def test_fatal_configuration_stops_dispatch(setup, error):
    config, backend, targets, session = setup

    def factory(cfg):
        raise error("invalid provider settings")

    assert reverse_parallel(targets, config, backend, session, factory, 4) == []
    status = json.loads(session.path.with_suffix(".json.execution.json").read_text())
    assert status["phase"] == "failed"
    assert status["error"]["category"] == "configuration"
    assert len(status["jobs"]) <= 2
    assert all(session.attempt_count(t.address) == 0 for t in targets)


def test_journal_recovers_crash_before_session_publication(setup, monkeypatch):
    config, backend, targets, session = setup
    monkeypatch.setattr("re_agent.orchestrator.parallel.reverse_single",
                        lambda target, *args, **kwargs: ReversalResult(target, "accepted", success=True))
    publish = session.record_result_once
    monkeypatch.setattr(session, "record_result_once", Mock(side_effect=OSError("interrupted write")))
    with pytest.raises(OSError, match="interrupted write"):
        reverse_parallel(targets[:1], config, backend, session, lambda c: Mock(), 1)
    monkeypatch.setattr(session, "record_result_once", publish)
    assert reverse_parallel(targets[:1], config, backend, session, lambda c: Mock(), 1) == []
    assert session.is_completed(targets[0].address)
    assert session.attempt_count(targets[0].address) == 1


def test_scheduler_waits_for_dependencies_and_serializes_cycles(setup, monkeypatch):
    from re_agent.core.models import XRef

    config, backend, targets, session = setup
    config.orchestrator.selection_strategy = "dependency-order"
    edges = {"0x1": ["0x2", "0x3"], "0x2": ["0x4"], "0x3": ["0x4"], "0x4": []}
    backend.xrefs_from.side_effect = lambda a: [XRef(b, "", "CALL") for b in edges[a]]
    done, lock = set(), threading.Lock()

    def fake(target, *args, **kwargs):
        with lock:
            assert set(edges[target.address]) <= done
            done.add(target.address)
        return ReversalResult(target, "ok", success=True)

    monkeypatch.setattr("re_agent.orchestrator.parallel.reverse_single", fake)
    assert len(reverse_parallel(targets, config, backend, session, lambda c: Mock(), 4)) == 4
    assert len(done) == 4


def test_actual_validation_uses_separate_writable_roots(setup, monkeypatch, tmp_path):
    import sys

    from re_agent.backend.stub import StubBackend
    from re_agent.orchestrator.execution import Execution, executing
    from re_agent.orchestrator.single import validate_result
    from re_agent.verification.candidate import run_process as run

    config, _, targets, _ = setup
    targets = [FunctionTarget(t.address, "", t.function_name) for t in targets]
    root = Path(config.project_profile.source_root)
    root.mkdir()
    (root / "f.cpp").write_text("int f1() { return 0; }\nint f2() { return 0; }\n")
    config.validation.enabled = True
    config.validation.copy_project = True
    config.validation.parallel_safe = True
    config.validation.project_root = str(tmp_path)
    config.validation.trust_configured_commands = True
    config.validation.build_commands = [[sys.executable, "-c",
        "from pathlib import Path; p=Path('shared-build-name'); assert not p.exists(); p.write_text('ok')"]]
    config.orchestrator.max_parallel_validations = 2
    barrier = threading.Barrier(2)
    roots = []

    def invoke(args, **kwargs):
        roots.append(kwargs["cwd"])
        barrier.wait(10)
        return run(args, **kwargs)

    monkeypatch.setattr("re_agent.verification.candidate.run_process", invoke)
    context = Execution(threading.Event(), threading.Semaphore(2), lambda *args: None)

    def validate(target):
        with executing(context):
            return validate_result(ReversalResult(target, f"int {target.function_name}() {{ return 1; }}",
                                                   success=True), config, StubBackend())

    with ThreadPoolExecutor() as pool:
        results = list(pool.map(validate, targets[:2]))
    assert all(r.success for r in results), [r.validation_verdict for r in results]
    assert len(set(roots)) == 2
    assert all(not Path(r).exists() for r in roots)


def test_parallel_enumeration_falls_back_without_sharing_provider(setup, monkeypatch):
    from re_agent.core.models import FunctionEntry
    from re_agent.orchestrator.class_runner import reverse_class

    config, backend, targets, session = setup
    backend.remaining.side_effect = NotImplementedError("remaining unavailable")
    backend.unimplemented.return_value = [FunctionEntry(t.address, t.function_name, t.class_name) for t in targets]
    monkeypatch.setattr("re_agent.orchestrator.parallel.reverse_single",
                        lambda target, *args, **kwargs: ReversalResult(target, "ok", success=True))
    result = reverse_class("C", config, backend, None, session, 4, provider_factory=lambda c: Mock())
    assert len(result) == 4
    with pytest.raises(ValueError, match="positive"):
        reverse_class("C", config, backend, None, session, 0, provider_factory=lambda c: Mock())


def test_library_parallel_run_rebinds_changed_semantic_identity(setup, monkeypatch):
    config, backend, targets, session = setup
    monkeypatch.setattr("re_agent.orchestrator.parallel.reverse_single",
                        lambda target, *args, **kwargs: ReversalResult(target, "ok", success=True))
    assert len(reverse_parallel(targets[:1], config, backend, session, lambda c: Mock(), 1)) == 1
    original = json.loads(session.path.read_text())["acceptance"]
    config.llm.cli_path, config.llm.input_cost_per_million = "/opt/cli", 9.0
    assert reverse_parallel(targets[:1], config, backend, session, lambda c: Mock(), 1) == []
    config.llm.model = "new-model"
    assert len(reverse_parallel(targets[:1], config, backend, session, lambda c: Mock(), 1)) == 1
    assert json.loads(session.path.read_text())["acceptance"] != original
    assert session.attempt_count(targets[0].address) == 1
    assert len(json.loads(session.path.read_text())["history"]) == 1
