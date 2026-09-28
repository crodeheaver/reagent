"""Smoke tests for CLI."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from re_agent.cli.main import build_parser, main
from re_agent.core.models import FunctionTarget, ReversalResult


def test_parser_builds() -> None:
    parser = build_parser()
    assert parser is not None


def test_estimate_parser_accepts_class() -> None:
    args = build_parser().parse_args(["estimate", "--class", "CTest", "--limit", "3"])
    assert args.command == "estimate"
    assert args.class_name == "CTest"
    assert args.limit == 3


def test_no_command_returns_zero() -> None:
    assert main([]) == 0


def test_version_flag() -> None:
    import pytest
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0


def test_init_creates_config(tmp_path: Path) -> None:
    config_path = tmp_path / "re-agent.yaml"
    result = main(["--config", str(config_path), "init"])
    assert result == 0
    assert config_path.exists()


def test_init_fails_if_exists(tmp_path: Path) -> None:
    config_path = tmp_path / "re-agent.yaml"
    config_path.write_text("existing")
    result = main(["--config", str(config_path), "init"])
    assert result == 1


def test_status_no_session(tmp_path: Path) -> None:
    config_path = tmp_path / "re-agent.yaml"
    # Create a minimal config with session file in tmp
    config_path.write_text(f'''
output:
  session_file: "{tmp_path.as_posix()}/progress.json"
  report_dir: "{tmp_path.as_posix()}/reports"
  log_dir: "{tmp_path.as_posix()}/logs"
''')
    result = main(["--config", str(config_path), "status"])
    assert result == 0


def test_reverse_dry_run(tmp_path: Path, capsys) -> None:
    config_path = tmp_path / "re-agent.yaml"
    config_path.write_text("llm:\n  provider: claude\n")
    result = main(["--config", str(config_path), "reverse", "--address", "0x6F86A0",
                   "--class", "CVehicleModelInfo", "--function", "SetupCommonData", "--dry-run"])
    captured = capsys.readouterr()
    assert result == 0
    assert "Would reverse: 0x6F86A0" in captured.out
    assert "Class: CVehicleModelInfo" in captured.out
    assert "Function: SetupCommonData" in captured.out


def test_reverse_no_target(tmp_path: Path) -> None:
    config_path = tmp_path / "re-agent.yaml"
    config_path.write_text("llm:\n  provider: claude\n")
    result = main(["--config", str(config_path), "reverse"])
    assert result == 1


def _reverse_target(tmp_path: Path, args: list[str], hooks: dict[str, tuple[str, str]] | None = None) -> FunctionTarget:
    """Run single-address reversal against the stub backend and capture the resolved target."""
    config_path = tmp_path / "re-agent.yaml"
    config_path.write_text(
        "llm:\n  provider: claude\n"
        "backend:\n  type: stub\n"
        "validation:\n  enabled: false\n"
        f"output:\n  session_file: {(tmp_path / 'progress.json').as_posix()}\n"
    )
    captured: list[FunctionTarget] = []

    def fake_reverse_single(target: FunctionTarget, *args: object, **kwargs: object) -> ReversalResult:
        captured.append(target)
        return ReversalResult(target=target, code="", success=True)

    class FakeIndexer:
        def __init__(self, *args: object) -> None:
            self.hook_address_index = hooks or {}

    with patch("re_agent.llm.registry.create_provider"), \
            patch("re_agent.orchestrator.single.reverse_single", fake_reverse_single), \
            patch("re_agent.parity.source_indexer.SourceIndexer", FakeIndexer):
        assert main(["--config", str(config_path), "reverse", "--address", "0x100", *args]) == 0
    return captured[0]


def test_reverse_uses_decompiler_identity_by_default(tmp_path: Path) -> None:
    target = _reverse_target(tmp_path, [])
    assert (target.class_name, target.function_name) == ("CStub", "StubFunction")


def test_reverse_function_option_overrides_decompiler_name(tmp_path: Path) -> None:
    target = _reverse_target(tmp_path, ["--function", "SetupCommonData"])
    assert (target.class_name, target.function_name) == ("CStub", "SetupCommonData")


def test_reverse_explicit_identity_overrides_project_hooks(tmp_path: Path) -> None:
    hooks = {"0x100": ("CHooked", "HookedName")}
    target = _reverse_target(tmp_path, [], hooks)
    assert (target.class_name, target.function_name) == ("CHooked", "HookedName")
    target = _reverse_target(tmp_path, ["--class", "CVehicleModelInfo", "--function", "SetupCommonData"], hooks)
    assert (target.class_name, target.function_name) == ("CVehicleModelInfo", "SetupCommonData")


def test_reverse_function_requires_address(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config_path = tmp_path / "re-agent.yaml"
    config_path.write_text("llm:\n  provider: claude\n")
    assert main(["--config", str(config_path), "reverse", "--class", "CTest", "--function", "Run", "--dry-run"]) == 1
    assert "--function requires --address" in capsys.readouterr().err
