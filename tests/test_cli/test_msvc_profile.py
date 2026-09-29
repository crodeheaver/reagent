"""init --profile msvc-matching writes a loadable matching setup that doctor gates."""
from __future__ import annotations

import json
import sys

from re_agent.cli.main import main
from re_agent.config.loader import load_config


def test_msvc_profile_writes_matching_sections(tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    assert main(["init", "--profile", "msvc-matching"]) == 0
    config = load_config(tmp_path / "re-agent.yaml")
    assert config.project_profile.annotation_modules == ["GAME"]
    assert config.project_profile.hook_patterns == []
    assert any("no C++11" in rule for rule in config.project_profile.prompt_rules)
    assert config.orchestrator.selection_strategy == "smallest-first"
    assert config.validation.copy_project and not config.validation.trust_configured_commands
    assert config.matching.enabled and config.matching.require_exact
    assert config.matching.oracle_command[:3] == ["{python}", "-m", "re_agent.oracles.msvc"]
    assert "{overlay_root}/src" in config.matching.oracle_command

    capsys.readouterr()
    (tmp_path / "src").mkdir()
    assert main(["doctor", "--skip-canary"]) == 1
    checks = {check["check"]: check for check in json.loads(capsys.readouterr().out)["checks"]}
    assert checks["match oracle"]["passed"] and checks["match oracle"]["detail"] == sys.executable
    assert not checks["original binary"]["passed"]  # orig/game.exe is a placeholder until configured.
    assert not checks["match acceptance"]["passed"]  # Trust is attested only after the canary matches.
