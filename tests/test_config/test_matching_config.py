"""Matching configuration is validated before any compile or model call."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from re_agent.backend.stub import StubBackend
from re_agent.config.loader import load_config
from re_agent.core.function_picker import pick_next
from re_agent.core.models import AsmResult, FunctionEntry
from re_agent.core.session import Session


def load(tmp_path: Path, matching: dict[str, object], **sections: object):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"matching": matching, **sections}), encoding="utf-8")
    return load_config(path)


def test_defaults_are_disabled_and_reject_inline_assembly(tmp_path):
    config = load(tmp_path, {})
    assert not config.matching.enabled
    assert config.matching.require_exact and config.matching.unit_regression
    assert any("asm" in pattern for pattern in config.matching.forbidden_patterns)


def test_enabled_matching_roundtrips(tmp_path):
    config = load(tmp_path, {"enabled": True, "oracle_command": ["python", "oracle.py", "{address}"],
                             "candidates_per_round": 3, "permuter_threshold": "0.95"})
    assert config.matching.oracle_command == ["python", "oracle.py", "{address}"]
    assert config.matching.candidates_per_round == 3
    assert config.matching.permuter_threshold == 0.95


@pytest.mark.parametrize(("matching", "sections", "message"), [
    ({"enabled": True}, {}, "requires matching.oracle_command"),
    ({"enabled": True, "oracle_command": ["x"]}, {"validation": {"enabled": False}}, "requires validation.enabled"),
    ({"oracle_command": "python oracle.py"}, {}, "oracle_command must be a list"),
    ({"oracle_command": [""]}, {}, "oracle_command must be a list"),
    ({"candidates_per_round": 9}, {}, "candidates_per_round"),
    ({"plateau_rounds": 0}, {}, "plateau_rounds"),
    ({"max_rounds": -1}, {}, "max_rounds"),
    ({"permuter_threshold": 1.5}, {}, "permuter_threshold"),
    ({"forbidden_patterns": ["("]}, {}, "invalid regex"),
    ({"canary_function": "CFoo::Bar"}, {}, "requires matching.canary_address"),
])
def test_invalid_matching_settings_are_rejected(tmp_path, matching, sections, message):
    with pytest.raises(ValueError, match=message):
        load(tmp_path, matching, **sections)


def test_smallest_first_orders_by_instruction_count(tmp_path):
    sizes = {"0x10": 40, "0x20": 3}

    class Backend(StubBackend):
        def remaining(self, class_name=None):  # type: ignore[override]
            return [FunctionEntry("0x10", "Big", "C", caller_count=0), FunctionEntry("0x20", "Small", "C", 9),
                    FunctionEntry("0x30", "Unknown", "C", 0)]

        def get_asm(self, target):  # type: ignore[override]
            return AsmResult(target, "", sizes[target], 0, False) if target in sizes else None

    session = Session(tmp_path / "session.json")
    target = pick_next("C", Backend(), session, strategy="smallest-first")
    assert target is not None and target.function_name == "Small"
    assert load(tmp_path, {}, orchestrator={"selection_strategy": "smallest-first"})
