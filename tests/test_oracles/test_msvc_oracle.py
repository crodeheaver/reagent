"""The MSVC oracle against PE images built by clang's MSVC target and lld-link.

clang stands in for cl.exe: its code generation differs from MSVC's, but the objects
(COFF, MSVC decoration, relocations) and fixed-base images are the same kind of input.
Hand-written assembly reproduces MSVC's inline jump and byte tables.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from re_agent.oracles.msvc import main

TARGET = ["clang", "--target=i686-pc-windows-msvc"]
LINK = ["lld-link", "/nologo", "/entry:mainCRTStartup", "/subsystem:console", "/nodefaultlib", "/fixed",
        "/safeseh:no", "/base:0x400000"]
COMPILE = "clang --target=i686-pc-windows-msvc -O2 {flags} -c {{source}} -o {{object}}"

GAME = """\
extern "C" int puts(const char*);
struct CTimer {
    static unsigned m_snTimerDivider;
    static unsigned GetCyclesPerMillisecond();
    int Update(int x);
};
// GLOBAL: GAME 0xDIVIDER
unsigned CTimer::m_snTimerDivider = 7;
// GLOBAL: GAME 0xTABLE
int g_table[4] = {1, 2, 3, 4};
// FUNCTION: GAME 0xCYCLES
unsigned CTimer::GetCyclesPerMillisecond() { return m_snTimerDivider / 1000; }
// FUNCTION: GAME 0xUPDATE
int CTimer::Update(int x) BODY
// LIBRARY: GAME 0xPUTS
// puts
"""
BODY = """{
    switch (x) {
    case 0: return g_table[1];
    case 1: puts("one"); return 3;
    case 2: return GetCyclesPerMillisecond() + 5;
    case 3: return g_table[x] * 3;
    case 4: return 17;
    default: return x - 1;
    }
}"""
LIB = """\
struct CTimer { static unsigned m_snTimerDivider; int Update(int x); };
extern "C" int puts(const char* s) { return s[0]; }
extern "C" int mainCRTStartup() { CTimer t; return t.Update(CTimer::m_snTimerDivider); }
"""
INLINE = r"""
    .intel_syntax noprefix
    .text
    .def "?Pick@@YAHH@Z"; .scl 2; .type 32; .endef
    .globl "?Pick@@YAHH@Z"
    .p2align 4
"?Pick@@YAHH@Z":
    mov ecx, dword ptr [esp + 4]
    cmp ecx, 3
    ja .Ldefault
    movzx ecx, byte ptr [ecx + .Lbytes]
    jmp dword ptr [4*ecx + .Ltable]
.Lcase0:
    mov eax, 10
    ret
.Lcase1:
    mov eax, dword ptr ["?g_value@@3HA"]
    ret
.Ldefault:
    xor eax, eax
    ret
    .p2align 2, 0x90
.Ltable:
    .long .Lcase0
    .long .Lcase1
.Lbytes:
    .byte 0, 1, 1, 0
    .def _mainCRTStartup; .scl 2; .type 32; .endef
    .globl _mainCRTStartup
    .p2align 4, 0x90
_mainCRTStartup:
    push 2
    call "?Pick@@YAHH@Z"
    add esp, 4
    ret
    .data
    .globl "?g_value@@3HA"
    .p2align 2
"?g_value@@3HA":
    .long 42
"""
EH = """\
struct Guard { int* p; Guard(int* q) : p(q) { ++*p; } ~Guard() { --*p; } };
int g_depth;
void Work(int);
int Run(int x) { Guard guard(&g_depth); Work(x); return g_depth + x; }
"""
EH_LIB = """\
extern "C" int __CxxFrameHandler3() { return 0; }
void Work(int) {}
int Run(int);
extern "C" int mainCRTStartup() { return Run(3); }
"""


def _toolchain() -> str | None:
    try:
        import capstone  # noqa: F401
    except ImportError:
        return "capstone unavailable"
    if not shutil.which("clang") or not shutil.which("lld-link"):
        return "clang and lld-link unavailable"
    probe = subprocess.run([*TARGET, "-x", "c", "-", "-c", "-o", os.devnull], input="int f(void){return 0;}",
                           capture_output=True, text=True)
    return None if probe.returncode == 0 else "clang lacks the i686-pc-windows-msvc target"


MISSING = _toolchain()
pytestmark = pytest.mark.skipif(MISSING is not None, reason=str(MISSING))


def build(directory: Path, sources: dict[str, str], flags: list[str] | None = None) -> tuple[Path, dict[str, int]]:
    """Compile and link a fixed-base image; return it with its public symbol addresses."""
    directory.mkdir(parents=True, exist_ok=True)
    objects = []
    for name, text in sources.items():
        source = directory / name
        source.write_text(text)
        obj = source.with_suffix(".obj")
        subprocess.run([*TARGET, "-O2", *(flags or []), "-c", str(source), "-o", str(obj)], check=True)
        objects.append(str(obj))
    image = directory / "game.exe"
    subprocess.run([*LINK, f"/map:{directory / 'game.map'}", f"/out:{image}", *objects], check=True)
    symbols = {m[1]: int(m[2], 16) for m in re.finditer(r"(?m)^\s*\w{4}:\w{8}\s+(\S+)\s+(\w{8,16})\b",
                                                          (directory / "game.map").read_text())}
    return image, symbols


def oracle(capsys, image: Path, address: int, function: str, source: Path, *extra: str,
           flags: str = "") -> dict[str, object]:
    code = main(["--original", str(image), "--address", hex(address), "--function", function, "--source", str(source),
                 "--compile", COMPILE.format(flags=flags), *extra])
    out, err = capsys.readouterr()
    assert code == 0, err
    return json.loads(out)


@pytest.fixture(scope="module")
def game(tmp_path_factory):
    directory = tmp_path_factory.mktemp("game")
    image, symbols = build(directory, {"game.cpp": GAME.replace("BODY", BODY), "lib.cpp": LIB})
    return directory, image, symbols


def variant(directory: Path, name: str, old: str, new: str) -> Path:
    path = directory / name
    path.write_text((directory / "game.cpp").read_text().replace(old, new))
    return path


def test_identical_source_matches_through_the_map(game, capsys):
    directory, image, symbols = game
    result = oracle(capsys, image, symbols["?Update@CTimer@@QAEHH@Z"], "CTimer::Update", directory / "game.cpp",
                    "--symbols", str(directory / "game.map"))
    assert result["exact"] and result["score"] == 1.0 and result["diff"] == []


@pytest.mark.parametrize(("old", "new", "expected"), [
    ("case 0: return g_table[1];", "case 0: return g_table[2];", "g_table+0x8"),
    ('puts("one")', 'puts("two")', "data:74776f00"),
    ("case 4: return 17;", "case 4: return 18;", "mov eax, 0x12"),
    ("return GetCyclesPerMillisecond() + 5;", "return m_snTimerDivider + 5;", "CTimer::m_snTimerDivider"),
])
def test_reference_and_code_differences_are_reported(game, capsys, old, new, expected):
    directory, image, symbols = game
    result = oracle(capsys, image, symbols["?Update@CTimer@@QAEHH@Z"], "CTimer::Update",
                    variant(directory, "variant.cpp", old, new), "--symbols", str(directory / "game.map"))
    assert not result["exact"] and 0 < result["score"] < 1
    assert any(expected in str(item.get("candidate", "")) for item in result["diff"]), result["diff"]


def test_annotations_are_a_symbol_source(game, capsys, tmp_path):
    directory, image, symbols = game
    text = (directory / "game.cpp").read_text()
    for placeholder, name in (("DIVIDER", "?m_snTimerDivider@CTimer@@2IA"), ("TABLE", "?g_table@@3PAHA"),
                              ("CYCLES", "?GetCyclesPerMillisecond@CTimer@@SAIXZ"),
                              ("UPDATE", "?Update@CTimer@@QAEHH@Z"), ("PUTS", "_puts")):
        text = text.replace(f"0x{placeholder}", hex(symbols[name]))
    project = tmp_path / "src"
    project.mkdir()
    (project / "game.cpp").write_text(text)
    address = symbols["?Update@CTimer@@QAEHH@Z"]
    result = oracle(capsys, image, address, "CTimer::Update", project / "game.cpp",
                    "--annotations", str(project), "--module", "GAME")
    assert result["exact"], result["diff"]
    (project / "game.cpp").write_text(text.replace("// GLOBAL: GAME", "// GLOBAL: OTHER"))
    result = oracle(capsys, image, address, "CTimer::Update", project / "game.cpp",
                    "--annotations", str(project), "--module", "GAME", "--size", hex(symbols["_puts"] - address))
    assert not result["exact"]
    assert "symbols missing from the symbol map: CTimer::m_snTimerDivider, g_table" in str(result["summary"])


def test_msvc_inline_jump_and_byte_tables(tmp_path, capsys):
    image = tmp_path / "inline.exe"
    source = tmp_path / "inline.s"
    source.write_text(INLINE)
    subprocess.run([*TARGET, "-c", str(source), "-o", str(tmp_path / "inline.obj")], check=True)
    subprocess.run([*LINK, f"/map:{tmp_path / 'inline.map'}", f"/out:{image}", str(tmp_path / "inline.obj")],
                   check=True)
    map_args = ("--symbols", str(tmp_path / "inline.map"))
    assert oracle(capsys, image, 0x401000, "Pick", source, *map_args)["exact"]
    swapped = tmp_path / "swapped.s"
    swapped.write_text(INLINE.replace("    .long .Lcase0\n    .long .Lcase1", "    .long .Lcase1\n    .long .Lcase0"))
    result = oracle(capsys, image, 0x401000, "Pick", swapped, *map_args)
    assert result["diff"] == [{"offset": 0x28, "kind": "mismatch", "target": "jump table: fn+0x17, fn+0x1d",
                               "candidate": "jump table: fn+0x1d, fn+0x17"}]
    reindexed = tmp_path / "bytes.s"
    reindexed.write_text(INLINE.replace(".byte 0, 1, 1, 0", ".byte 0, 1, 0, 1"))
    result = oracle(capsys, image, 0x401000, "Pick", reindexed, *map_args)
    assert result["diff"] == [{"offset": 0x30, "kind": "mismatch", "target": "data 00 01 01 00",
                               "candidate": "data 00 01 00 01"}]


def test_exception_handler_thunks_match_named_or_not(tmp_path, capsys):
    flags = ["-fexceptions", "-fcxx-exceptions"]
    image, _ = build(tmp_path, {"eh.cpp": EH, "lib.cpp": EH_LIB}, flags)
    text = (tmp_path / "game.map").read_text()
    (tmp_path / "unnamed.map").write_text("\n".join(line for line in text.splitlines() if "ehhandler" not in line))
    wrong = tmp_path / "wrong.cpp"
    wrong.write_text(EH.replace("return g_depth + x;", "return g_depth - x;"))
    for symbols_file in ("game.map", "unnamed.map"):
        args = ("--symbols", str(tmp_path / symbols_file))
        assert oracle(capsys, image, 0x401000, "Run", tmp_path / "eh.cpp", *args, flags=" ".join(flags))["exact"]
        assert not oracle(capsys, image, 0x401000, "Run", wrong, *args, flags=" ".join(flags))["exact"]


def test_setup_errors_and_compiler_failures(game, capsys, tmp_path):
    directory, image, symbols = game
    common = ["--original", str(image), "--address", hex(symbols["?Update@CTimer@@QAEHH@Z"]),
              "--compile", COMPILE.format(flags=""), "--symbols", str(directory / "game.map")]
    assert main([*common, "--function", "CTimer::Missing", "--source", str(directory / "game.cpp")]) == 3
    assert "Expected one definition of CTimer::Missing" in capsys.readouterr().err
    broken = tmp_path / "broken.cpp"
    broken.write_text("int f( { return y; }\n")
    assert main([*common, "--function", "f", "--source", str(broken)]) != 0
    assert "error" in capsys.readouterr().err
    not_pe = tmp_path / "not.exe"
    not_pe.write_bytes(b"\x7fELF" + bytes(64))
    assert main([*common[2:], "--original", str(not_pe), "--function", "CTimer::Update",
                 "--source", str(directory / "game.cpp")]) == 3
    assert "not a PE image" in capsys.readouterr().err


def test_runs_as_a_module(game):
    directory, image, symbols = game
    proc = subprocess.run([sys.executable, "-m", "re_agent.oracles.msvc", "--original", str(image),
                           "--address", hex(symbols["?GetCyclesPerMillisecond@CTimer@@SAIXZ"]),
                           "--function", "CTimer::GetCyclesPerMillisecond", "--source", str(directory / "game.cpp"),
                           "--compile", COMPILE.format(flags=""), "--symbols", str(directory / "game.map")],
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["exact"]
