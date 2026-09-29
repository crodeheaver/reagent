"""reccmp-style annotations map original addresses to qualified source names."""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path

import pytest

from re_agent.config.loader import load_config
from re_agent.config.schema import ProjectProfile, ReAgentConfig
from re_agent.core.identity import project_fingerprint
from re_agent.parity.annotations import parse_annotations, read_annotations
from re_agent.parity.source_indexer import SourceIndexer

SOURCE = r'''
// GLOBAL: GAME 0x5B0000
int g_count = 0;
// GLOBAL: GAME 0x5b0010
// GLOBAL: BETA 0x6b0010
const char* g_names[4] = { "a{", "b" };

namespace Game {
template <class T> struct Vec { T x; };

// VTABLE: GAME 0x5c0000
class CFoo : public Vec<int> {
public:
    // FUNCTION: GAME 0x401010
    int GetX() const { return m_x; }
    int m_x;
};

// FUNCTION: GAME 0x401000
void CFoo::Bar(int x,
               int y)
{
    /* } a brace in a comment */
}

// STUB: GAME 0x401100
CVector& CFoo::operator+=(const CVector& other) { return *this; }

// FUNCTION: GAME 0x401120
bool CFoo::operator()(int) const { return true; }

// FUNCTION: GAME 0x401130
CFoo::~CFoo() {}
}

// SYNTHETIC: GAME 0x401200
// CFoo::`scalar deleting destructor'

// STRING: GAME 0x5d0000
// FUNCTION: GAME 0x401400
int __stdcall WinMain(int a) { return a; }
'''


def test_names_are_qualified_by_enclosing_scopes():
    found = {a.address: (a.kind, a.name, a.line) for a in parse_annotations(SOURCE, "unit.cpp", {"GAME"})}
    assert found == {
        "0x5b0000": ("GLOBAL", "g_count", 2),
        "0x5b0010": ("GLOBAL", "g_names", 4),
        "0x5c0000": ("VTABLE", "Game::CFoo::`vftable'", 11),
        "0x401010": ("FUNCTION", "Game::CFoo::GetX", 14),
        "0x401000": ("FUNCTION", "Game::CFoo::Bar", 19),
        "0x401100": ("STUB", "Game::CFoo::operator+=", 26),
        "0x401120": ("FUNCTION", "Game::CFoo::operator()", 29),
        "0x401130": ("FUNCTION", "Game::CFoo::~CFoo", 32),
        "0x401200": ("SYNTHETIC", "CFoo::`scalar deleting destructor'", 36),
        "0x401400": ("FUNCTION", "WinMain", 40),
    }


def test_modules_filter_markers():
    assert [a.address for a in parse_annotations(SOURCE, modules={"BETA"})] == ["0x6b0010"]
    assert len(parse_annotations(SOURCE)) == 11


def test_source_index_resolves_annotated_addresses(tmp_path):
    (tmp_path / "timer.cpp").write_text(
        "// FUNCTION: GAME 0x561A40\nunsigned CTimer::GetCyclesPerMillisecond() {\n    return 1;\n}\n")
    profile = ProjectProfile(hook_patterns=[], annotation_modules=["GAME"], source_extensions=[".cpp"])
    indexer = SourceIndexer(tmp_path, profile)
    for spelling in ("0x561A40", "0x00561a40", "561a40"):
        match = indexer.find_by_address(spelling)
        assert match is not None and "return 1;" in match.body
    assert SourceIndexer(tmp_path, ProjectProfile(hook_patterns=[], source_extensions=[".cpp"])).find_by_address(
        "0x561A40") is None
    assert [a.name for a in read_annotations(tmp_path, [".cpp"], {"GAME"})] == ["CTimer::GetCyclesPerMillisecond"]


def test_disabled_annotations_keep_earlier_project_identity(tmp_path):
    config = ReAgentConfig()
    config.project_profile.source_root = str(tmp_path)
    profile = asdict(config.project_profile)
    profile.pop("annotation_modules")
    values = {"profile": profile, "validation": asdict(config.validation), "parity": asdict(config.parity),
              "backend": asdict(config.backend)}
    values["validation"].pop("parallel_safe")
    earlier = hashlib.sha256()  # The 0.4 algorithm, for a project without source files or exports.
    earlier.update(json.dumps(values, sort_keys=True).encode())
    earlier.update(str(tmp_path.resolve()).encode())
    assert project_fingerprint(config) == earlier.hexdigest()
    config.project_profile.annotation_modules = ["GAME"]
    assert project_fingerprint(config) != earlier.hexdigest()


@pytest.mark.parametrize("modules", ["GAME", ["GAME MODULE"], [""]])
def test_invalid_annotation_modules_are_rejected(tmp_path, modules):
    path = tmp_path / "config.json"
    path.write_text(json.dumps({"project_profile": {"annotation_modules": modules}}))
    with pytest.raises(ValueError, match="annotation_modules"):
        load_config(Path(path))
