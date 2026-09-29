"""End to end on a Windows target: annotations, the bundled MSVC oracle, refinement and relinking."""
from __future__ import annotations

import subprocess

import pytest

from re_agent.backend.stub import StubBackend
from re_agent.config.schema import ReAgentConfig
from re_agent.core.models import FunctionTarget
from re_agent.orchestrator.single import reverse_single
from re_agent.verification.binary import compare_binaries
from tests.test_agents.test_loop import MockLLM
from tests.test_oracles.test_msvc_oracle import BODY, COMPILE, GAME, LIB, LINK, MISSING, TARGET, build

pytestmark = pytest.mark.skipif(MISSING is not None, reason=str(MISSING))

NAMES = {"DIVIDER": "?m_snTimerDivider@CTimer@@2IA", "TABLE": "?g_table@@3PAHA",
         "CYCLES": "?GetCyclesPerMillisecond@CTimer@@SAIXZ", "UPDATE": "?Update@CTimer@@QAEHH@Z", "PUTS": "_puts"}


def annotated(body: str, symbols: dict[str, int]) -> str:
    text = GAME.replace("BODY", body)
    for placeholder, name in NAMES.items():
        text = text.replace(f"0x{placeholder}", hex(symbols[name]))
    return text


def test_annotated_project_refines_to_an_identical_image(tmp_path):
    original, symbols = build(tmp_path / "original", {"game.cpp": GAME.replace("BODY", BODY), "lib.cpp": LIB})
    project = tmp_path / "project"
    (project / "src").mkdir(parents=True)
    (project / "src" / "game.cpp").write_text(annotated("{\n    return 0;\n}", symbols))

    config = ReAgentConfig()
    config.project_profile.source_root = str(project / "src")
    config.project_profile.source_extensions = [".cpp"]
    config.project_profile.hook_patterns = []
    config.project_profile.annotation_modules = ["GAME"]
    config.output.report_dir = str(tmp_path / "reports")
    config.output.log_dir = str(tmp_path / "logs")
    config.parity.enabled = False
    config.orchestrator.objective_verifier_enabled = False
    config.orchestrator.investigation_enabled = False
    config.validation.copy_project = True
    config.validation.project_root = str(project)
    config.validation.trust_configured_commands = True
    config.matching.enabled = True
    config.matching.original_binary = str(original)
    # No --size: the next annotated address (the LIBRARY marker for puts) bounds the function.
    config.matching.oracle_command = [
        "{python}", "-m", "re_agent.oracles.msvc", "--original", "{original_binary}", "--address", "{address}",
        "--function", "{function}", "--source", "{candidate_file}", "--compile", COMPILE.format(flags=""),
        "--annotations", "{overlay_root}/src", "--module", "GAME",
    ]

    address = hex(symbols["?Update@CTimer@@QAEHH@Z"])
    from re_agent.parity.source_indexer import SourceIndexer

    indexer = SourceIndexer(project / "src", config.project_profile)
    assert indexer.hook_address_index[address] == ("CTimer", "Update")  # Annotations name the target.

    functional = "int CTimer::Update(int x) " + BODY.replace("case 4: return 17;", "case 4: return 18;")
    reverser = MockLLM([f"```cpp\n{functional}\n```", f"```cpp\nint CTimer::Update(int x) {BODY}\n```"])
    checker = MockLLM(['{"verdict":"PASS","summary":"Matches the decompile"}'])
    result = reverse_single(FunctionTarget(address, "CTimer", "Update"), config, StubBackend(), reverser,
                            checker_llm=checker, indexer=indexer)
    assert result.success and result.match_tier == "exact", result.error
    assert result.rounds_used == 2 and checker._idx == 1

    rebuilt_dir = tmp_path / "rebuilt"
    rebuilt_dir.mkdir()
    body = result.code.removeprefix("int CTimer::Update(int x) ")
    (rebuilt_dir / "game.cpp").write_text(annotated(body, symbols))
    subprocess.run([*TARGET, "-O2", "-c", str(rebuilt_dir / "game.cpp"), "-o", str(rebuilt_dir / "game.obj")],
                   check=True)
    rebuilt = rebuilt_dir / "game.exe"
    subprocess.run([*LINK, f"/out:{rebuilt}", str(rebuilt_dir / "game.obj"), str(tmp_path / "original" / "lib.obj")],
                   check=True)
    assert compare_binaries(original, rebuilt)["identical_after_masking"]
