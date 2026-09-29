"""Whole-binary comparison and toolchain identification for PE and ELF files.

Only fields that legitimately differ between two builds of identical code are
masked: PE timestamps, the optional-header checksum and debug records (CodeView
PDB identity, reproducibility hashes), and the ELF GNU build ID. Everything else,
including the MSVC Rich header and the ELF ``.comment`` section, still has to
match: they identify the toolchain.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_CHUNK = 4096
_DEBUG_CODEVIEW, _DEBUG_REPRO = 2, 16
# Rich header product ids (comp.id >> 16) of the tools older Windows programs were
# built with, checked against two published comp.id lists. Unknown ids stay numeric.
_RICH_TOOLS = {
    0x04: "Linker 6.00", 0x06: "Cvtres 5.00", 0x0A: "C 12.00 (VC 6.0)", 0x0B: "C++ 12.00 (VC 6.0)",
    0x0E: "MASM 6.13", 0x0F: "MASM 7.10", 0x12: "MASM 6.14",
    0x1C: "C 13.00 (VS .NET 2002)", 0x1D: "C++ 13.00 (VS .NET 2002)", 0x3D: "Linker 7.00", 0x40: "MASM 7.00",
    0x45: "Cvtres 7.00", 0x5A: "Linker 7.10", 0x5E: "Cvtres 7.10", 0x5F: "C 13.10 (VS .NET 2003)",
    0x60: "C++ 13.10 (VS .NET 2003)", 0x6D: "C 14.00 (VS 2005)", 0x6E: "C++ 14.00 (VS 2005)", 0x78: "Linker 8.00",
    0x7C: "Cvtres 8.00", 0x83: "C 15.00 (VS 2008)", 0x84: "C++ 15.00 (VS 2008)", 0x91: "Linker 9.00",
    0x94: "Cvtres 9.00", 0x95: "MASM 9.00", 0x9D: "Linker 10.00", 0xAA: "C 16.00 (VS 2010)",
    0xAB: "C++ 16.00 (VS 2010)",
}
# Objects compiled with /GL carry no machine code until link time.
_LTCG_TOOLS = {
    0x2B: "C 13.00 LTCG", 0x2C: "C++ 13.00 LTCG", 0x50: "C 13.10p LTCG", 0x51: "C++ 13.10p LTCG",
    0x63: "C 13.10 LTCG", 0x64: "C++ 13.10 LTCG", 0x71: "C 14.00 LTCG", 0x72: "C++ 14.00 LTCG",
    0x82: "MSIL 14.00 LTCG", 0x89: "C 15.00 LTCG", 0x8A: "C++ 15.00 LTCG", 0x8B: "MSIL 15.00 LTCG",
    0xA3: "C 16.00 LTCG (Phoenix)", 0xA4: "C++ 16.00 LTCG (Phoenix)", 0xA5: "MSIL 16.00 LTCG (Phoenix)",
    0xAE: "C 16.00 LTCG", 0xAF: "C++ 16.00 LTCG", 0xB0: "MSIL 16.00 LTCG", 0xC0: "C 16.10 LTCG",
    0xC1: "C++ 16.10 LTCG", 0xC2: "MSIL 16.10 LTCG", 0xD2: "C 17.00 LTCG", 0xD3: "C++ 17.00 LTCG",
    0xD4: "MSIL 17.00 LTCG", 0xE4: "C 18.00 LTCG", 0xE5: "C++ 18.00 LTCG", 0xE6: "MSIL 18.00 LTCG",
    0xF6: "C 18.10 LTCG", 0xF7: "C++ 18.10 LTCG", 0xF8: "MSIL 18.10 LTCG", 0x108: "C 19.00 LTCG",
    0x109: "C++ 19.00 LTCG", 0x10A: "MSIL 19.00 LTCG",
}
_LINKER_VERSIONS = {
    (6, 0): "Visual C++ 6.0",
    (7, 0): "Visual Studio .NET 2002",
    (7, 10): "Visual Studio .NET 2003",
    (8, 0): "Visual Studio 2005",
    (9, 0): "Visual Studio 2008",
    (10, 0): "Visual Studio 2010",
    (11, 0): "Visual Studio 2012",
    (12, 0): "Visual Studio 2013",
}


@dataclass(frozen=True)
class Region:
    name: str
    offset: int
    size: int


@dataclass(frozen=True)
class Layout:
    format: str
    regions: list[Region]
    masked: list[Region]
    details: dict[str, Any]


def read_layout(data: bytes) -> Layout:
    """Parse known headers; anything malformed is compared byte for byte, unmasked."""
    try:
        if data[:2] == b"MZ" and len(data) >= 0x40:
            e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
            if data[e_lfanew : e_lfanew + 4] == b"PE\0\0":
                return _pe_layout(data, e_lfanew)
        if data[:4] == b"\x7fELF":
            return _elf_layout(data)
    except (struct.error, ValueError, IndexError) as exc:
        return Layout("raw", [Region("file", 0, len(data))], [], {"parse_error": str(exc)})
    return Layout("raw", [Region("file", 0, len(data))], [], {})


def identify(path: Path) -> dict[str, Any]:
    """Report the toolchain evidence a binary carries, without guessing flags."""
    data = path.read_bytes()
    layout = read_layout(data)
    return {"path": str(path), "format": layout.format, "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(), **layout.details}


def compare_binaries(original: Path, rebuilt: Path) -> dict[str, Any]:
    left, right = original.read_bytes(), rebuilt.read_bytes()
    left_layout, right_layout = read_layout(left), read_layout(right)
    masked_left, masked_right = _mask(left, left_layout.masked), _mask(right, right_layout.masked)
    differences = _differences(masked_left, masked_right, left_layout.regions)
    return {
        "format": left_layout.format,
        "identical": left == right,
        "identical_after_masking": masked_left == masked_right,
        "sizes": {"original": len(left), "rebuilt": len(right)},
        "sha256": {"original": hashlib.sha256(left).hexdigest(), "rebuilt": hashlib.sha256(right).hexdigest()},
        "masked_sha256": {"original": hashlib.sha256(masked_left).hexdigest(),
                          "rebuilt": hashlib.sha256(masked_right).hexdigest()},
        "masked_fields": [{"name": r.name, "offset": r.offset, "size": r.size} for r in left_layout.masked],
        "differences": differences,
    }


def _mask(data: bytes, regions: list[Region]) -> bytes:
    buffer = bytearray(data)
    for region in regions:
        end = min(len(buffer), region.offset + region.size)
        buffer[region.offset : end] = bytes(max(0, end - region.offset))
    return bytes(buffer)


def _differences(left: bytes, right: bytes, regions: list[Region]) -> list[dict[str, Any]]:
    """Count differing bytes per region of the original layout, comparing chunk by chunk."""
    counts: dict[str, list[int]] = {}

    def region_of(offset: int) -> str:
        return next((r.name for r in regions if r.offset <= offset < r.offset + r.size), "unmapped")

    common = min(len(left), len(right))
    for start in range(0, common, _CHUNK):
        stop = min(start + _CHUNK, common)
        a, b = left[start:stop], right[start:stop]
        if a == b:
            continue
        for index, (x, y) in enumerate(zip(a, b, strict=True)):
            if x != y:
                entry = counts.setdefault(region_of(start + index), [0, start + index])
                entry[0] += 1
    result = [{"region": name, "differing_bytes": count, "first_difference": first}
              for name, (count, first) in counts.items()]
    if len(left) != len(right):
        result.append({"region": "length", "differing_bytes": abs(len(left) - len(right)),
                       "first_difference": common})
    return sorted(result, key=lambda item: item["first_difference"])


def _pe_layout(data: bytes, e_lfanew: int) -> Layout:
    coff = e_lfanew + 4
    machine, sections, timestamp = struct.unpack_from("<HHI", data, coff)
    optional_size = struct.unpack_from("<H", data, coff + 16)[0]
    optional = coff + 20
    magic, major, minor = struct.unpack_from("<HBB", data, optional)
    plus = magic == 0x20B
    headers_size: int = struct.unpack_from("<I", data, optional + 60)[0]
    directory_count = struct.unpack_from("<I", data, optional + (108 if plus else 92))[0]
    directories = optional + (112 if plus else 96)
    masked = [Region("COFF TimeDateStamp", coff + 4, 4), Region("CheckSum", optional + 64, 4)]
    regions = [Region("headers", 0, headers_size)]
    table = optional + optional_size
    section_rows: list[tuple[int, int, int]] = []
    for index in range(sections):
        row = table + 40 * index
        name = data[row : row + 8].rstrip(b"\0").decode("ascii", "replace")
        virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from("<IIII", data, row + 8)
        section_rows.append((virtual_address, max(virtual_size, raw_size), raw_offset))
        if raw_size:
            regions.append(Region(name, raw_offset, raw_size))

    def file_offset(rva: int) -> int | None:
        if rva < headers_size:
            return rva
        for address, size, raw in section_rows:
            if address <= rva < address + size:
                return raw + rva - address
        return None

    def directory(index: int) -> tuple[int, int] | None:
        if index >= directory_count:
            return None
        rva, size = struct.unpack_from("<II", data, directories + 8 * index)
        offset = file_offset(rva) if rva and size else None
        return (offset, size) if offset is not None else None

    exports = directory(0)
    if exports:
        masked.append(Region("export TimeDateStamp", exports[0] + 4, 4))
    debug = directory(6)
    if debug:
        for entry in range(debug[1] // 28):
            row = debug[0] + 28 * entry
            if row + 28 > len(data):
                break
            masked.append(Region(f"debug[{entry}] TimeDateStamp", row + 4, 4))
            kind, size, _, pointer = struct.unpack_from("<IIII", data, row + 12)
            if kind in (_DEBUG_CODEVIEW, _DEBUG_REPRO) and size:
                masked.append(Region(f"debug[{entry}] {'CodeView' if kind == _DEBUG_CODEVIEW else 'Repro'} data",
                                     pointer, size))
    details: dict[str, Any] = {
        "machine": f"0x{machine:04x}",
        "pe32_plus": plus,
        "timestamp": timestamp,
        "linker_version": f"{major}.{minor:02d}",
        "rich_header": (rich := _rich_header(data, e_lfanew)),
    }
    hint = _LINKER_VERSIONS.get((major, minor)) or ("Visual Studio 2015 or later (14.x toolset)"
                                                     if major == 14 else None)
    if hint:
        details["linker_hint"] = hint
    if rich:
        compilers = sorted((e for e in rich if e.get("tool", "").startswith(("C ", "C++ "))),
                           key=lambda e: -int(e["count"]))
        if compilers:
            details["compiler_hint"] = f"{compilers[0]['tool']} build {compilers[0]['build']}"
        # Link-time code generation compiles at link time: per-function oracles cannot reproduce it.
        details["ltcg"] = any(e["product_id"] in _LTCG_TOOLS for e in rich)
    return Layout("pe", regions, masked, details)


def _rich_header(data: bytes, e_lfanew: int) -> list[dict[str, Any]] | None:
    """Decode MSVC tool records (product id, build number, object count) if present."""
    end = data.rfind(b"Rich", 0x40, e_lfanew)
    if end < 0 or end + 8 > len(data):
        return None
    key = struct.unpack_from("<I", data, end + 4)[0]
    start = next((offset for offset in range(end - 4, 0x3F, -4)
                  if struct.unpack_from("<I", data, offset)[0] ^ key == 0x536E6144), None)  # "DanS"
    if start is None:
        return None
    entries = []
    for offset in range(start + 16, end, 8):
        comp_id, count = (value ^ key for value in struct.unpack_from("<II", data, offset))
        entry: dict[str, Any] = {"product_id": comp_id >> 16, "build": comp_id & 0xFFFF, "count": count}
        tool = _RICH_TOOLS.get(comp_id >> 16) or _LTCG_TOOLS.get(comp_id >> 16)
        if tool:
            entry["tool"] = tool
        entries.append(entry)
    return entries


def _elf_layout(data: bytes) -> Layout:
    wide, endian = data[4] == 2, "<" if data[5] == 1 else ">"
    machine = struct.unpack_from(endian + "H", data, 0x12)[0]
    if wide:
        shoff = struct.unpack_from(endian + "Q", data, 0x28)[0]
        entsize, count, names = struct.unpack_from(endian + "HHH", data, 0x3A)
    else:
        shoff = struct.unpack_from(endian + "I", data, 0x20)[0]
        entsize, count, names = struct.unpack_from(endian + "HHH", data, 0x2E)
    rows = []
    for index in range(count):
        row = shoff + entsize * index
        name, kind = struct.unpack_from(endian + "II", data, row)
        offset, size = (struct.unpack_from(endian + "QQ", data, row + 24) if wide
                        else struct.unpack_from(endian + "II", data, row + 16))
        rows.append((name, kind, offset, size))
    strings = rows[names] if names < len(rows) else None

    def section_name(offset: int) -> str:
        if strings is None:
            return ""
        start = strings[2] + offset
        return data[start : data.index(b"\0", start)].decode("ascii", "replace")

    regions: list[Region] = []
    masked, comment = [], []
    for name_offset, kind, offset, size in rows:
        if kind in (0, 8) or not size:  # SHT_NULL and SHT_NOBITS occupy no file bytes.
            continue
        name = section_name(name_offset)
        regions.append(Region(name, offset, size))
        if name == ".note.gnu.build-id" and size >= 12:
            name_size, desc_size = struct.unpack_from(endian + "II", data, offset)
            masked.append(Region("GNU build ID", offset + 12 + (name_size + 3) // 4 * 4, desc_size))
        if name == ".comment":
            comment = [text.decode("utf-8", "replace") for text in data[offset : offset + size].split(b"\0") if text]
    first = min((region.offset for region in regions), default=len(data))
    regions.insert(0, Region("headers", 0, first))
    if count:
        regions.append(Region("section headers", shoff, entsize * count))
    details = {"class": 64 if wide else 32, "endianness": "little" if endian == "<" else "big",
               "machine": machine, "comment": comment}
    return Layout("elf", regions, masked, details)
