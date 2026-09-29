"""Name handling for the MSVC oracle: undecoration, symbol sources and function bounds."""
from __future__ import annotations

import json
import sys

import pytest

from re_agent.oracles.msvc import SymbolMap, Undecorator, qualified_name, read_symbols


@pytest.mark.parametrize(("undecorated", "expected"), [
    ("public: static unsigned int __cdecl CTimer::GetCyclesPerMillisecond(void)", "CTimer::GetCyclesPerMillisecond"),
    ("public: int __thiscall CTimer::Update(int)", "CTimer::Update"),
    ("public: static unsigned int CTimer::m_snTimerDivider", "CTimer::m_snTimerDivider"),
    ("int *g_table", "g_table"),
    ("public: __thiscall CTimer::CTimer(void)", "CTimer::CTimer"),
    ("public: virtual __thiscall CFoo::~CFoo(void)", "CFoo::~CFoo"),
    ("public: void __thiscall Vec<int, char>::Push(int)", "Vec<int, char>::Push"),
    ("public: class CVector & __thiscall CVector::operator+=(class CVector const &)", "CVector::operator+="),
    ("public: bool __thiscall CFoo::operator()(int) const", "CFoo::operator()"),
    ("void * __cdecl operator new(unsigned int)", "operator new"),
    ("const CFoo::`vftable'", "CFoo::`vftable'"),
    ("const CFoo::`RTTI Complete Object Locator'", "CFoo::`RTTI Complete Object Locator'"),
    ("int __stdcall WinMain(struct HINSTANCE__ *, int)", "WinMain"),
])
def test_qualified_name_from_undecorated(undecorated, expected):
    assert qualified_name(undecorated) == expected


def test_undecorator_falls_back_without_a_tool():
    undecorate = Undecorator([])  # No external tool: plain names still decode.
    assert undecorate("?Update@CTimer@@QAEHH@Z") == "CTimer::Update"
    assert undecorate("??0CTimer@@QAE@XZ") == "CTimer::CTimer"
    assert undecorate("??1CTimer@@QAE@XZ") == "CTimer::~CTimer"
    assert undecorate("?g_table@@3PAHA") == "g_table"
    assert undecorate("?Foo@?$Vec@H@@QAEXXZ") == "?Foo@?$Vec@H@@QAEXXZ"  # Templates need a real undecorator.
    assert undecorate("_puts") == "puts"
    assert undecorate("_Sleep@4") == "Sleep"
    assert undecorate("@Fast@8") == "Fast"
    assert undecorate("__imp__MessageBoxA@16") == "__imp_MessageBoxA"
    assert undecorate("__imp_?Get@CFoo@@QAEHXZ") == "__imp_CFoo::Get"


def test_undecorator_reads_msvc_and_llvm_output(tmp_path):
    script = tmp_path / "undname.py"
    script.write_text(
        "import sys\n"
        "for name in sys.argv[1:]:\n"
        "    print(f'Undecoration of :- \"{name}\"')\n"
        "    print('is :- \"public: int __thiscall CFoo::Bar(int)\"')\n")
    assert Undecorator([sys.executable, str(script)])("?Bar@CFoo@@QAEHH@Z") == "CFoo::Bar"
    script.write_text("import sys\nfor name in sys.argv[1:]:\n    print(name)\n    print('int __cdecl Baz(void)')\n"
                      "    print()\n")
    assert Undecorator([sys.executable, str(script)])("?Baz@@YAHXZ") == "Baz"


def test_symbol_sources(tmp_path):
    map_file = tmp_path / "game.map"
    map_file.write_text(
        " game\n\n  Address         Publics by Value              Rva+Base       Lib:Object\n\n"
        " 0001:00000000       ?Update@CTimer@@QAEHH@Z    00401000 f   timer.obj\n"
        " 0001:00000040       .LBB0_2                    0000000000401040     timer.obj\n"
        " 0003:00000004       ?g_table@@3PAHA            0000000000403004     timer.obj\n")
    json_file = tmp_path / "names.json"
    json_file.write_text(json.dumps({"561a40": {"full_name": "CTimer::Get", "size": 16}, "0x561b00": "CTimer::Put"}))
    text_file = tmp_path / "names.txt"
    text_file.write_text("# address name\n0x401200 CFoo::operator new\n401300,Helper\n")
    names = SymbolMap()
    for path in (map_file, json_file, text_file):
        for address, name, size in read_symbols(path):
            names.add(address, name, size)
    assert names.lookup("?Update@CTimer@@QAEHH@Z") == 0x401000
    assert names.lookup("missing", "CTimer::Get") == 0x561A40
    assert names.lookup("CFoo::operator new") == 0x401200 and names.lookup("Helper") == 0x401300
    assert ".LBB0_2" not in names.addresses  # Assembler labels never bound functions.
    assert names.end_of(0x561A40) == 0x561A50  # Sizes win over neighbours.
    assert names.end_of(0x401000) == 0x401200
    assert names.describe(0x403008) == "?g_table@@3PAHA+0x4"
    names.add(0x401400, "CFoo::Bar")
    names.add(0x401500, "CFoo::Bar")
    assert names.lookup("CFoo::Bar") is None  # Overloads need decorated names.
