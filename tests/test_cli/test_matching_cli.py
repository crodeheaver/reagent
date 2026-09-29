"""Doctor canary, flag search and whole-binary comparison from the command line."""
from __future__ import annotations

import json
import sys
from pathlib import Path

from re_agent.cli.main import main
from tests.test_verification.test_binary import build_pe

# Exact only for the canary's real source under the right flags; flags arrive in the environment.
ORACLE = """
import json, os, sys
from pathlib import Path
text = Path(sys.argv[1]).read_text()
flags = os.environ.get("RE_AGENT_MATCH_FLAGS", "-O2")
exact = sys.argv[2] == "CTimer::Get" and "return m_divider / 1000;" in text and flags == "-O2"
print(json.dumps({"exact": exact, "score": 1.0 if exact else 0.6, "summary": "flags " + flags}))
"""


def config_file(tmp_path: Path, **matching: object) -> Path:
    source = tmp_path / "src"
    source.mkdir(exist_ok=True)
    (source / "timer.cpp").write_text("unsigned CTimer::Get() {\n    return m_divider / 1000;\n}\n")
    oracle = tmp_path / "oracle.py"
    oracle.write_text(ORACLE)
    path = tmp_path / "config.json"
    path.write_text(json.dumps({
        "backend": {"type": "stub"},
        "project_profile": {"source_root": str(source), "hook_patterns": []},
        "output": {"report_dir": str(tmp_path / "reports")},
        "validation": {"trust_configured_commands": True, "working_directory": str(tmp_path)},
        "matching": {"enabled": True, "oracle_command": [sys.executable, str(oracle), "{candidate_file}", "{function}"],
                     "canary_address": "0x561A40", "canary_function": "CTimer::Get", **matching},
    }), encoding="utf-8")
    return path


def checks(capsys) -> dict[str, dict[str, object]]:
    return {check["check"]: check for check in json.loads(capsys.readouterr().out)["checks"]}


def test_doctor_proves_the_toolchain_with_the_canary(tmp_path, capsys):
    assert main(["--config", str(config_file(tmp_path)), "doctor"]) == 0
    report = checks(capsys)
    assert report["match canary"]["passed"]
    assert report["match canary"]["detail"] == "CTimer::Get (0x561A40): flags -O2"
    assert report["acceptance policy"]["passed"]  # The trusted oracle is a validation gate.


def test_doctor_fails_when_the_canary_does_not_match(tmp_path, capsys):
    path = config_file(tmp_path, canary_function="CTimer::Other")
    assert main(["--config", str(path), "doctor"]) == 1
    assert not checks(capsys)["match canary"]["passed"]
    assert main(["--config", str(path), "doctor", "--skip-canary"]) == 0


def test_doctor_reports_missing_matching_inputs(tmp_path, capsys):
    path = config_file(tmp_path, original_binary=str(tmp_path / "missing.exe"), canary_address=None,
                       canary_function=None)
    assert main(["--config", str(path), "doctor"]) == 1
    report = checks(capsys)
    assert not report["original binary"]["passed"]
    assert report["match canary"]["passed"]


def test_flag_search_ranks_variants(tmp_path, capsys):
    path = config_file(tmp_path)
    assert main(["--config", str(path), "toolchain", "--flags=-O1", "--flags=-O2"]) == 0
    output = json.loads(capsys.readouterr().out)
    assert [row["flags"] for row in output["variants"]] == ["-O1", "-O2"]
    assert output["best"]["flags"] == "-O2" and output["best"]["exact"]
    assert main(["--config", str(path), "toolchain", "--flags=-O1", "--flags=-Os"]) == 1


def test_toolchain_identifies_binary_without_config(tmp_path, capsys):
    binary = tmp_path / "game.exe"
    binary.write_bytes(build_pe())
    assert main(["--config", str(tmp_path / "absent.yaml"), "toolchain", "--binary", str(binary)]) == 0
    assert json.loads(capsys.readouterr().out)["linker_hint"] == "Visual Studio .NET 2003"


def test_match_binary_exit_status_and_report(tmp_path, capsys):
    original, rebuilt, changed = (tmp_path / name for name in ("a.exe", "b.exe", "c.exe"))
    original.write_bytes(build_pe())
    rebuilt.write_bytes(build_pe(timestamp=5))
    changed.write_bytes(build_pe(text=b"\x90\x90\x90\xc3"))
    config = config_file(tmp_path, original_binary=str(original))
    assert main(["--config", str(config), "match-binary", "--rebuilt", str(rebuilt)]) == 0
    assert "identical after masking build-varying fields" in capsys.readouterr().out
    assert main(["--config", str(config), "match-binary", "--rebuilt", str(changed), "--format", "json"]) == 1
    assert json.loads(capsys.readouterr().out)["differences"][0]["region"] == ".text"
