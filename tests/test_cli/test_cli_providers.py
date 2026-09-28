"""Preflight commands recognise every CLI-backed provider, including Grok Build."""
import json
from unittest.mock import patch

from re_agent.cli.main import main


def _config(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"backend": {"type": "stub"}, "project_profile": {"source_root": str(tmp_path)},
                                "llm": {"provider": "grok-cli", "model": ""}}), encoding="utf-8")
    return str(path)


def test_doctor_checks_the_grok_executable(tmp_path, capsys):
    with patch("re_agent.cli.cmd_doctor.shutil.which", return_value=None):
        assert main(["--config", _config(tmp_path), "doctor"]) == 1
    checks = {check["check"]: check for check in json.loads(capsys.readouterr().out)["checks"]}
    assert checks["reverser executable"] == {"check": "reverser executable", "passed": False, "detail": "grok"}
    assert not checks["checker executable"]["passed"]


def test_estimate_notes_grok_token_limits_are_not_enforced(tmp_path, capsys):
    assert main(["--config", _config(tmp_path), "estimate", "--address", "0x401000"]) == 0
    assert "for CLI roles: reverser, checker" in capsys.readouterr().out
