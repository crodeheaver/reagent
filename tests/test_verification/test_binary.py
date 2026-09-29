"""Whole-binary comparison masks only build-varying fields and keeps toolchain evidence."""
from __future__ import annotations

import shutil
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from re_agent.verification.binary import compare_binaries, identify, read_layout

RICH_KEY = 0x12345678


def build_pe(timestamp: int = 1, checksum: int = 2, guid: bytes = b"\x11" * 16, text: bytes = b"\x55\x8b\xec\xc3",
             rich_build: int = 3077, compiler: int = 0x60) -> bytes:
    """A minimal PE32 image: headers, .text and .rdata holding a CodeView debug record."""
    data = bytearray(0x800)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x100)
    struct.pack_into("<IIII", data, 0x80, 0x536E6144 ^ RICH_KEY, RICH_KEY, RICH_KEY, RICH_KEY)
    for index, (comp_id, count) in enumerate([(compiler << 16 | rich_build, 5), (0x5A << 16 | 3077, 1)]):
        struct.pack_into("<II", data, 0x90 + 8 * index, comp_id ^ RICH_KEY, count ^ RICH_KEY)
    data[0xA0:0xA4] = b"Rich"
    struct.pack_into("<I", data, 0xA4, RICH_KEY)
    data[0x100:0x104] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x104, 0x14C, 2, timestamp, 0, 0, 224, 0x102)
    optional = 0x118
    struct.pack_into("<HBB", data, optional, 0x10B, 7, 10)
    struct.pack_into("<II", data, optional + 60, 0x400, checksum)
    struct.pack_into("<I", data, optional + 92, 16)
    struct.pack_into("<II", data, optional + 96 + 8 * 6, 0x2000, 28)
    for index, (name, address, offset) in enumerate([(b".text", 0x1000, 0x400), (b".rdata", 0x2000, 0x600)]):
        row = optional + 224 + 40 * index
        data[row : row + 8] = name.ljust(8, b"\0")
        struct.pack_into("<IIII", data, row + 8, 0x200, address, 0x200, offset)
    data[0x400 : 0x400 + len(text)] = text
    codeview = b"RSDS" + guid + struct.pack("<I", 1) + b"game.pdb\0"
    struct.pack_into("<IIHHIIII", data, 0x600, 0, timestamp, 0, 0, 2, len(codeview), 0x2020, 0x620)
    data[0x620 : 0x620 + len(codeview)] = codeview
    return bytes(data)


def write(tmp_path: Path, name: str, data: bytes) -> Path:
    path = tmp_path / name
    path.write_bytes(data)
    return path


def test_pe_builds_differing_only_in_build_identity_match_after_masking(tmp_path):
    original = write(tmp_path, "a.exe", build_pe())
    rebuilt = write(tmp_path, "b.exe", build_pe(timestamp=9, checksum=7, guid=b"\x22" * 16))
    report = compare_binaries(original, rebuilt)
    assert report["format"] == "pe"
    assert not report["identical"] and report["identical_after_masking"]
    assert report["differences"] == []
    names = [field["name"] for field in report["masked_fields"]]
    assert names == ["COFF TimeDateStamp", "CheckSum", "debug[0] TimeDateStamp", "debug[0] CodeView data"]


def test_pe_code_difference_is_located_by_section(tmp_path):
    report = compare_binaries(write(tmp_path, "a.exe", build_pe()),
                              write(tmp_path, "b.exe", build_pe(text=b"\x55\x89\xe5\xc3")))
    assert not report["identical_after_masking"]
    assert report["differences"] == [{"region": ".text", "differing_bytes": 2, "first_difference": 0x401}]


def test_rich_header_is_toolchain_evidence_not_masked(tmp_path):
    report = compare_binaries(write(tmp_path, "a.exe", build_pe()),
                              write(tmp_path, "b.exe", build_pe(rich_build=6030)))
    assert not report["identical_after_masking"]
    assert report["differences"][0]["region"] == "headers"


def test_identify_decodes_linker_and_rich_records(tmp_path):
    info = identify(write(tmp_path, "a.exe", build_pe()))
    assert info["linker_version"] == "7.10"
    assert info["linker_hint"] == "Visual Studio .NET 2003"
    assert info["machine"] == "0x014c" and not info["pe32_plus"]
    assert info["rich_header"] == [
        {"product_id": 0x60, "build": 3077, "count": 5, "tool": "C++ 13.10 (VS .NET 2003)"},
        {"product_id": 0x5A, "build": 3077, "count": 1, "tool": "Linker 7.10"}]
    assert info["compiler_hint"] == "C++ 13.10 (VS .NET 2003) build 3077"
    assert info["ltcg"] is False
    ltcg = identify(write(tmp_path, "b.exe", build_pe(compiler=0x64)))
    assert ltcg["ltcg"] is True and ltcg["rich_header"][0]["tool"] == "C++ 13.10 LTCG"
    assert ltcg["compiler_hint"] == "C++ 13.10 LTCG build 3077"


def test_malformed_and_unknown_files_compare_raw(tmp_path):
    truncated = build_pe()[:0x120]
    layout = read_layout(truncated)
    assert layout.format == "raw" and "parse_error" in layout.details
    report = compare_binaries(write(tmp_path, "a.bin", b"abc"), write(tmp_path, "b.bin", b"abcd"))
    assert report["format"] == "raw"
    assert report["differences"] == [{"region": "length", "differing_bytes": 1, "first_difference": 3}]


@pytest.mark.skipif(not sys.platform.startswith("linux") or not shutil.which("gcc"),
                    reason="requires gcc producing ELF")
def test_elf_build_id_is_masked_and_compiler_comment_reported(tmp_path):
    source = tmp_path / "main.c"
    source.write_text("int main(void) { return 3; }\n")
    original = tmp_path / "a.out"
    subprocess.run(["gcc", "-O2", "-Wl,--build-id=sha1", str(source), "-o", str(original)], check=True)
    layout = read_layout(original.read_bytes())
    build_id = next(region for region in layout.masked if region.name == "GNU build ID")
    rebuilt = bytearray(original.read_bytes())
    rebuilt[build_id.offset] ^= 0xFF
    report = compare_binaries(original, write(tmp_path, "b.out", bytes(rebuilt)))
    assert not report["identical"] and report["identical_after_masking"]
    text = next(region for region in layout.regions if region.name == ".text")
    rebuilt[text.offset] ^= 0xFF
    report = compare_binaries(original, write(tmp_path, "c.out", bytes(rebuilt)))
    assert [item["region"] for item in report["differences"]] == [".text"]
    info = identify(original)
    assert info["format"] == "elf" and info["class"] in (32, 64)
    assert any("GCC" in comment for comment in info["comment"])
