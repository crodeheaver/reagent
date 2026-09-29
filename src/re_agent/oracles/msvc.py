"""Match oracle for MSVC-built 32-bit x86 Windows programs.

    python -m re_agent.oracles.msvc --original game.exe --address 0x401000 --function CFoo::Bar
        --source path/to/candidate.cpp --symbols game.map --annotations src --module GAME
        [--compile "cl /nologo /c {source} /Fo{object}"] [--size N] [--undname CMD] [-- flags...]

Compiles the candidate translation unit, finds the function in the COFF object
by its undecorated name, and compares it instruction by instruction with the
original function in the PE image. Instruction bytes must be identical except
for reference fields, which are compared by what they reach:

- an offset within the function (branches, inline jump tables);
- an original address, for named symbols resolved through the symbol map;
- the referenced bytes, for anonymous data such as string literals, floating
  point constants and function-local statics;
- jump-table entries, as offsets within the function.

Candidate symbols missing from the symbol map appear as ``?name`` and never
match; the summary lists them so they can be annotated. Symbol sources are MSVC
``/MAP`` files, JSON (``{"401000": "CFoo::Bar"}`` or ``{"401000": {"name": ...,
"size": ...}}``), text lines (``0x401000 CFoo::Bar``) and reccmp-style source
annotations. Decorated C++ names are undecorated with ``undname`` (MSVC) or
``llvm-undname``, falling back to a decoder for plain qualified names.

Compile templates accept ``{source}``, ``{object}`` and, for Windows tools run
under Wine, ``{source_win}`` and ``{object_win}`` (``Z:\\`` paths). Flags follow
``--``, or come from ``RE_AGENT_MATCH_FLAGS`` during flag searches. Prints one
JSON comparison (see ``re_agent.verification.matching``); a failed compilation
exits with the compiler's status after printing its diagnostics.
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import re
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

I386 = 0x14C
REL_DIR32, REL_REL32 = 0x06, 0x14
STORAGE_EXTERNAL, STORAGE_STATIC = 2, 3
SECTION_CODE, SECTION_UNINITIALIZED, SECTION_RELOC_OVERFLOW = 0x20, 0x80, 0x01000000
ANONYMOUS_PREFIXES = ("??_C@", "__real@", "__xmm@", "__mask@", "$SG", "$L", "$T")
PADDING = b"\xcc\x90"  # int3 and nop between functions.
LOCAL_LABELS = (".L", "$LN")
EH_THUNK = re.compile(rb"\xb8[\x00-\xff]{4}\xe9", re.S)  # mov eax, offset funcinfo; jmp __CxxFrameHandler
MAX_DATA = 4096


class OracleError(Exception):
    """A setup problem, reported instead of a comparison."""


# -- COFF objects ---------------------------------------------------------------


@dataclass(frozen=True)
class Symbol:
    name: str
    value: int
    section: int  # 1-based; 0 undefined, negative for absolute and debug symbols.
    type: int
    storage: int

    @property
    def is_function(self) -> bool:
        return (self.type >> 4) & 0x3 == 2


@dataclass
class Section:
    number: int
    name: str
    data: bytes
    characteristics: int
    relocations: dict[int, tuple[int, Symbol]]  # Field offset -> (type, symbol).


class CoffObject:
    def __init__(self, data: bytes) -> None:
        machine, count, _, table, symbol_count, optional, _ = struct.unpack_from("<HHIIIHH", data, 0)
        if machine == 0 and count == 0xFFFF:
            raise OracleError("Big object files are not supported; compile without /bigobj")
        if machine != I386:
            raise OracleError(f"Only i386 objects are supported (machine {machine:#06x})")
        strings = table + 18 * symbol_count

        def string(offset: int) -> str:
            start = strings + offset
            return data[start : data.index(b"\0", start)].decode("latin-1")

        symbols: dict[int, Symbol] = {}
        index = 0
        while index < symbol_count:
            row = table + 18 * index
            raw = data[row : row + 8]
            name = string(struct.unpack_from("<I", raw, 4)[0]) if raw[:4] == bytes(4) else raw.rstrip(b"\0").decode(
                "latin-1")
            value, section, kind, storage, aux = struct.unpack_from("<IhHBB", data, row + 8)
            symbols[index] = Symbol(name, value, section, kind, storage)
            index += 1 + aux
        self.symbols = list(symbols.values())
        self.sections: dict[int, Section] = {}
        for number in range(1, count + 1):
            row = 20 + optional + 40 * (number - 1)
            label = data[row : row + 8].rstrip(b"\0").decode("latin-1")
            name = string(int(label[1:])) if label.startswith("/") and label[1:].isdigit() else label
            size, pointer, relocations_at = struct.unpack_from("<III", data, row + 16)
            relocation_count = struct.unpack_from("<H", data, row + 32)[0]
            characteristics = struct.unpack_from("<I", data, row + 36)[0]
            first = 0
            if characteristics & SECTION_RELOC_OVERFLOW and relocation_count == 0xFFFF:
                relocation_count, first = struct.unpack_from("<I", data, relocations_at)[0], 1
            relocations = {}
            for entry in range(first, relocation_count):
                offset, symbol, kind = struct.unpack_from("<IIH", data, relocations_at + 10 * entry)
                relocations[offset] = (kind, symbols[symbol])
            body = bytes(size) if characteristics & SECTION_UNINITIALIZED or not pointer else data[
                pointer : pointer + size]
            self.sections[number] = Section(number, name, body, characteristics, relocations)

    def is_section_symbol(self, symbol: Symbol) -> bool:
        section = self.sections.get(symbol.section)
        return symbol.storage == STORAGE_STATIC and symbol.value == 0 and section is not None and (
            section.name == symbol.name)

    def named(self, section: int) -> list[Symbol]:
        return sorted((s for s in self.symbols if s.section == section and s.storage in (STORAGE_EXTERNAL,
                       STORAGE_STATIC) and not self.is_section_symbol(s)), key=lambda s: s.value)

    def extent(self, symbol: Symbol) -> tuple[int, int]:
        """A function ends at the next function or public symbol; local labels inside it do not count."""
        bounds = [s.value for s in self.named(symbol.section) if s.value > symbol.value
                  and (not symbol.is_function or s.is_function or s.storage == STORAGE_EXTERNAL)]
        return symbol.value, min(bounds, default=len(self.sections[symbol.section].data))

    def owner(self, section: int, offset: int) -> Symbol | None:
        return next((s for s in reversed(self.named(section)) if s.value <= offset), None)


# -- PE images ------------------------------------------------------------------


class PeImage:
    def __init__(self, data: bytes) -> None:
        if data[:2] != b"MZ":
            raise OracleError("Original is not a PE image")
        header = struct.unpack_from("<I", data, 0x3C)[0]
        if data[header : header + 4] != b"PE\0\0":
            raise OracleError("Original is not a PE image")
        machine, count = struct.unpack_from("<HH", data, header + 4)
        optional_size = struct.unpack_from("<H", data, header + 20)[0]
        optional = header + 24
        if machine != I386 or struct.unpack_from("<H", data, optional)[0] != 0x10B:
            raise OracleError("Only 32-bit x86 PE images are supported")
        self.data = data
        self.base: int = struct.unpack_from("<I", data, optional + 28)[0]
        self.size: int = struct.unpack_from("<I", data, optional + 56)[0]
        self.sections = []
        for index in range(count):
            row = optional + optional_size + 40 * index
            self.sections.append(struct.unpack_from("<IIII", data, row + 8))  # vsize, rva, raw size, raw offset
        self.fixups: set[int] | None = None
        if struct.unpack_from("<I", data, optional + 92)[0] > 5:
            rva, size = struct.unpack_from("<II", data, optional + 96 + 8 * 5)
            if rva and size:
                self.fixups = self._fixups(rva, size)

    def _fixups(self, rva: int, size: int) -> set[int]:
        block = self.read(self.base + rva, size)
        fixups, position = set(), 0
        while position + 8 <= len(block):
            page, length = struct.unpack_from("<II", block, position)
            if length < 8:
                break
            for offset in range(position + 8, position + length - 1, 2):
                entry = struct.unpack_from("<H", block, offset)[0]
                if entry >> 12 == 3:  # IMAGE_REL_BASED_HIGHLOW
                    fixups.add(self.base + page + (entry & 0xFFF))
            position += length
        return fixups

    def read(self, address: int, size: int) -> bytes:
        rva = address - self.base
        for virtual_size, start, raw_size, raw in self.sections:
            if start <= rva < start + max(virtual_size, raw_size):
                offset = rva - start
                stored = self.data[raw + offset : raw + min(raw_size, offset + size)] if offset < raw_size else b""
                return stored + bytes(min(size, max(virtual_size, raw_size) - offset) - len(stored))
        return b""

    def contains(self, address: int) -> bool:
        return self.base <= address < self.base + self.size


# -- Symbols ----------------------------------------------------------------------


class SymbolMap:
    def __init__(self) -> None:
        self.names: dict[int, str] = {}
        self.addresses: dict[str, set[int]] = {}
        self.sizes: dict[int, int] = {}

    def add(self, address: int, name: str, size: int | None = None) -> None:
        if not name or name.startswith(LOCAL_LABELS):
            return  # Assembler labels name no function or object and would split functions.
        self.names.setdefault(address, name)
        self.addresses.setdefault(name, set()).add(address)
        if size:
            self.sizes[address] = size

    def lookup(self, *names: str) -> int | None:
        for name in names:
            found = self.addresses.get(name)
            if found and len(found) == 1:
                return next(iter(found))
        return None

    def end_of(self, address: int) -> int | None:
        if address in self.sizes:
            return address + self.sizes[address]
        return min((a for a in self.names if a > address), default=None)

    def describe(self, address: int) -> str:
        before = max((a for a in self.names if a <= address and address - a < 0x1000), default=None)
        if before is None:
            return ""
        return self.names[before] + (f"+{address - before:#x}" if address != before else "")


def read_symbols(path: Path) -> list[tuple[int, str, int | None]]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    if "Publics by Value" in text:
        return [(int(m[2], 16), m[1], None) for m in re.finditer(
            r"(?m)^\s*[0-9A-Fa-f]{4}:[0-9A-Fa-f]{8}\s+(\S+)\s+([0-9A-Fa-f]{8}(?:[0-9A-Fa-f]{8})?)\b", text)]
    if path.suffix.lower() == ".json":
        value: Any = json.loads(text)
        rows: list[tuple[int, str, int | None]] = []
        items = value.items() if isinstance(value, dict) else ((row.get("address"), row) for row in value)
        for address, entry in items:
            name = entry if isinstance(entry, str) else entry.get("full_name") or entry.get("name", "")
            size = entry.get("size") if isinstance(entry, dict) else None
            rows.append((int(str(address), 16), str(name), int(size) if size else None))
        return rows
    return [(int(m[1], 16), m[2], None) for m in re.finditer(r"(?m)^\s*(?:0x)?([0-9A-Fa-f]+)[\s,]+([^#\s].*?)\s*$",
                                                           text)]


class Undecorator:
    """Map decorated MSVC names to qualified names such as ``CFoo::Bar``."""

    def __init__(self, command: list[str] | None = None) -> None:
        if command is None:
            tool = shutil.which("undname") or shutil.which("llvm-undname")
            command = [tool] if tool else []
        self.command = command
        self.cache: dict[str, str] = {}

    def __call__(self, name: str) -> str:
        self.prepare([name])
        return self.cache[name]

    def prepare(self, names: Iterable[str]) -> None:
        pending = sorted({n for n in names if n not in self.cache})
        cpp = [n for n in pending if n.removeprefix("__imp_").startswith("?")]
        undecorated: dict[str, str] = {}
        for start in range(0, len(cpp) if self.command else 0, 100):
            undecorated.update(self._run([n.removeprefix("__imp_") for n in cpp[start : start + 100]]))
        for name in pending:
            prefix = "__imp_" if name.startswith("__imp_") else ""
            bare = name.removeprefix("__imp_")
            if bare.startswith("?"):
                text = undecorated.get(bare)
                self.cache[name] = prefix + (qualified_name(text) if text else _decode_plain(bare) or bare)
            else:
                self.cache[name] = prefix + re.sub(r"^[_@]|@\d+$", "", bare) if re.fullmatch(
                    r"[_@][\w$?]+(?:@\d+)?", bare) else name

    def _run(self, names: list[str]) -> dict[str, str]:
        try:
            output = subprocess.run([*self.command, *names], capture_output=True, text=True, timeout=60).stdout
        except (OSError, subprocess.TimeoutExpired):
            return {}
        if 'is :- "' in output:  # MSVC undname
            return dict(re.findall(r'Undecoration of :- "(.*?)"\s*\n\s*is :- "(.*?)"', output))
        blocks = [block.splitlines() for block in output.split("\n\n")]
        return {lines[0].strip(): lines[1].strip() for lines in blocks
                if len(lines) >= 2 and not lines[1].startswith(("error", "invalid"))}


def qualified_name(undecorated: str) -> str:
    """``public: int __thiscall CFoo::Bar(int)`` -> ``CFoo::Bar``."""
    text = re.sub(r"^(?:(?:public|private|protected): )?(?:(?:static|virtual) )*", "", undecorated.strip())
    depth, quoted, head = 0, False, text
    for index, char in enumerate(text):
        if char == "`":
            quoted = True
        elif char == "'" and quoted:
            quoted = False
        elif quoted:
            continue
        elif char == "<":
            depth += 1
        elif char == ">":
            depth = max(0, depth - 1)
        elif char == "(" and depth == 0:
            if text[:index].rstrip().endswith("operator") and text[index : index + 2] == "()":
                continue
            head = text[:index]
            break
    tokens, current, depth, quoted = [], "", 0, False
    for char in head.strip():
        quoted = (quoted or char == "`") and not (quoted and char == "'")
        depth += (char == "<") - (char == ">")
        if char == " " and depth == 0 and not quoted:
            tokens.append(current)
            current = ""
        else:
            current += char
    tokens.append(current)
    tokens = [token for token in tokens if token and token not in ("*", "&", "const", "volatile")]
    if not tokens:
        return undecorated
    name = tokens[-1].lstrip("*&")  # undname attaches pointer markers: "int *g_table".
    if len(tokens) > 1 and tokens[-2].endswith("operator"):
        name = tokens[-2] + " " + name
    return name


def _decode_plain(decorated: str) -> str:
    """Decode ``?Name@Scope@@...``, constructors and destructors without templates or back-references."""
    match = re.match(r"\?(\?[01])?((?:[A-Za-z_$][\w$]*@)+)@", decorated)
    if not match or "?$" in decorated[: match.end()]:
        return ""
    parts = match[2].rstrip("@").split("@")
    if match[1]:
        parts.insert(0, ("~" if match[1] == "?1" else "") + parts[0])
    return "::".join(reversed(parts))


# -- Comparison -------------------------------------------------------------------


@dataclass(frozen=True)
class Item:
    offset: int
    key: tuple[object, ...]
    text: str


def _disassembler() -> Any:
    try:
        import capstone
    except ImportError as exc:
        raise OracleError("The MSVC oracle needs capstone: pip install 'auto-re-agent[msvc]'") from exc
    engine = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    engine.detail = True
    return engine


def _is_eh_handler(name: str) -> bool:
    return name.lstrip("_").startswith("ehhandler$")  # MSVC __ehhandler$; clang adds C decoration.


def _trim(data: bytes, start: int, end: int) -> int:
    while end > start and data[end - 1] in PADDING:
        end -= 1
    return end


def _fields(insn: Any) -> list[tuple[int, int, str]]:
    """(offset, size, kind) of 32-bit displacement and immediate fields."""
    fields = []
    if insn.disp_size == 4:
        fields.append((insn.disp_offset, 4, "disp"))
    if insn.imm_size == 4:
        fields.append((insn.imm_offset, 4, "imm"))
    return fields


def _is_branch(insn: Any) -> bool:
    import capstone

    return bool(insn.group(capstone.CS_GRP_JUMP) or insn.group(capstone.CS_GRP_CALL)) and any(
        operand.type == capstone.x86.X86_OP_IMM for operand in insn.operands)


def _jump_table(insn: Any) -> bool:
    import capstone

    return bool(insn.group(capstone.CS_GRP_JUMP)) and any(
        operand.type == capstone.x86.X86_OP_MEM and operand.mem.scale == 4 for operand in insn.operands)


def _width(insn: Any, kind: str) -> int | None:
    import capstone

    if kind == "disp":
        return next((int(op.size) for op in insn.operands if op.type == capstone.x86.X86_OP_MEM), None)
    return None  # An address taken as an immediate: read a NUL-terminated string.


def _sized(data: bytes, offset: int, width: int | None) -> bytes:
    if width:
        return data[offset : offset + width]
    return data[offset : offset + 256].split(b"\0", 1)[0] + b"\0"


def _masked(raw: bytes, fields: Sequence[tuple[int, int, str]]) -> str:
    buffer = bytearray(raw)
    for offset, size, _ in fields:
        buffer[offset : offset + size] = bytes(size)
    return buffer.hex()


def _text(insn: Any, tokens: Sequence[str], describe: Callable[[str], str]) -> str:
    base = f"{insn.mnemonic} {insn.op_str}".strip()
    return base + ("  ; " + ", ".join(describe(token) for token in tokens) if tokens else "")


class Comparison:
    def __init__(self, obj: CoffObject, function: Symbol, image: PeImage, address: int, size: int,
                 names: SymbolMap, undecorate: Undecorator) -> None:
        self.obj, self.function, self.image, self.names, self.undecorate = obj, function, image, names, undecorate
        self.address, self.end = address, address + size
        self.anonymous: list[bytes] = []
        self.unmapped: set[str] = set()
        self.eh_handler = False
        self.engine = _disassembler()

    # Candidate side: relocations name every reference.

    def candidate(self) -> list[Item]:
        section = self.obj.sections[self.function.section]
        start, end = self.obj.extent(self.function)
        end = _trim(section.data, start, end)
        items: list[Item] = []
        data_refs: dict[int, bool] = {}  # In-function data offset -> is a jump table.
        position = start
        while position < min([end, *(o for o in data_refs if o >= position)]):
            insn = next(self.engine.disasm(section.data[position:end], position, 1), None)
            if insn is None:
                break
            fields, tokens, table = [], [], None
            for offset, size, kind in _fields(insn):
                relocation = section.relocations.get(position + offset)
                if relocation is None:
                    continue
                symbol = relocation[1]
                addend = int.from_bytes(section.data[position + offset : position + offset + 4], "little", signed=True)
                if _jump_table(insn) and not self._inside(symbol, addend, start, end):
                    token, table = "jumptable", self._data_table(symbol, addend, start, end)
                else:
                    token = self._reference(symbol, addend, _width(insn, kind), start, end)
                if token.startswith("fn") and kind == "disp":
                    data_refs[start + int(token[2:], 16)] = _jump_table(insn)
                fields.append((offset, size, kind))
                tokens.append(token)
            if not fields and _is_branch(insn) and insn.imm_size == 4:
                target = int(insn.operands[-1].imm)
                if not start <= target < end:
                    owner = self.obj.owner(self.function.section, target)
                    fields.append((insn.imm_offset, 4, "imm"))
                    tokens.append(self._named(owner.name, target - owner.value) if owner else f"?{target:#x}")
            items.append(Item(position - start, ("insn", _masked(insn.bytes, fields), tuple(tokens)),
                              _text(insn, tokens, self.describe)))
            if table is not None:
                items.append(table)
            position += insn.size
        items.extend(self._inline_data(section.data, data_refs, position, start, end, self._candidate_entry))
        return items

    def _inside(self, symbol: Symbol, addend: int, start: int, end: int) -> bool:
        return symbol.section == self.function.section and start <= symbol.value + addend < end

    def _reference(self, symbol: Symbol, addend: int, width: int | None, start: int, end: int) -> str:
        if _is_eh_handler(symbol.name):
            self.eh_handler = True
            return "ehhandler"  # Compiler-generated per function; unnamed in the original.
        if symbol.section <= 0:
            return self._named(symbol.name, addend)
        offset = symbol.value + addend
        if symbol.section == self.function.section and start <= offset < end:
            return f"fn{offset - start:+#x}"
        section = self.obj.sections[symbol.section]
        owner = self.obj.owner(symbol.section, offset) if self.obj.is_section_symbol(symbol) else symbol
        if owner is not None and not self._anonymous(owner, section):
            return self._named(owner.name, offset - owner.value)
        stop = self.obj.extent(owner)[1] if owner is not None else None
        content = (section.data[offset:stop] if stop is not None and 0 < stop - offset <= MAX_DATA
                   else _sized(section.data, offset, width))
        self.anonymous.append(content)
        return "data:" + content.hex()

    def _anonymous(self, symbol: Symbol, section: Section) -> bool:
        local_data = symbol.storage == STORAGE_STATIC and not section.characteristics & SECTION_CODE
        return local_data or symbol.name.startswith(ANONYMOUS_PREFIXES)

    def _named(self, name: str, offset: int) -> str:
        qualified = self.undecorate(name)
        address = self.names.lookup(name, qualified)
        if address is None:
            overloaded = len(self.names.addresses.get(qualified, ())) > 1
            self.unmapped.add(qualified + (" (overloaded; map its decorated name)" if overloaded else ""))
            return f"?{qualified}" + (f"{offset:+#x}" if offset else "")
        return f"@{address + offset:#x}"

    def _data_table(self, symbol: Symbol, addend: int, start: int, end: int) -> Item:
        """A jump table in a data section, read through its relocations."""
        section = self.obj.sections[symbol.section]
        offset, entries = symbol.value + addend, []
        while (relocation := section.relocations.get(offset)) is not None and self._inside(
                relocation[1], self._addend(section, offset), start, end):
            entries.append(f"fn{relocation[1].value + self._addend(section, offset) - start:+#x}")
            offset += 4
        return Item(-1, ("table", tuple(entries)), "jump table: " + ", ".join(entries))

    @staticmethod
    def _addend(section: Section, offset: int) -> int:
        return int.from_bytes(section.data[offset : offset + 4], "little", signed=True)

    def _candidate_entry(self, data: bytes, offset: int, start: int, end: int) -> str:
        section = self.obj.sections[self.function.section]
        relocation = section.relocations.get(offset)
        if relocation is None:
            return data[offset : offset + 4].hex()
        return self._reference(relocation[1], self._addend(section, offset), 4, start, end)

    # Original side: operands in the image hold final addresses.

    def original(self) -> list[Item]:
        data = self.image.read(self.address, self.end - self.address)
        end = self.address + _trim(data, 0, len(data))
        items: list[Item] = []
        data_refs: dict[int, bool] = {}
        position = self.address
        while position < min([end, *(o for o in data_refs if o >= position)]):
            insn = next(self.engine.disasm(data[position - self.address : end - self.address], position, 1), None)
            if insn is None:
                break
            fields, tokens, table = [], [], None
            for offset, size, kind in _fields(insn):
                value = int.from_bytes(insn.bytes[offset : offset + 4], "little")
                if kind == "imm" and _is_branch(insn):
                    value = int(insn.operands[-1].imm)
                    if self.address <= value < end:
                        continue  # Local branches keep their encoded bytes.
                elif not self._absolute(position + offset, value):
                    continue
                if kind == "disp" and self.address <= value < end:
                    data_refs[value] = _jump_table(insn)
                    token = f"fn{value - self.address:+#x}"
                elif _jump_table(insn):
                    token, table = "jumptable", self._original_table(value, end)
                else:
                    token = self._address(value, _width(insn, kind))
                fields.append((offset, size, kind))
                tokens.append(token)
            items.append(Item(position - self.address, ("insn", _masked(insn.bytes, fields), tuple(tokens)),
                              _text(insn, tokens, self.describe)))
            if table is not None:
                items.append(table)
            position += insn.size
        image_data = self.image.read(self.address, end - self.address)
        items.extend(self._inline_data(image_data, {o - self.address: t for o, t in data_refs.items()},
                                       position - self.address, 0, end - self.address, self._original_entry))
        return items

    def _absolute(self, field: int, value: int) -> bool:
        if self.image.fixups is not None:
            return field in self.image.fixups
        return self.image.contains(value)

    def _address(self, value: int, width: int | None) -> str:
        name = self.names.names.get(value)
        if name is not None and _is_eh_handler(name) or (
                name is None and self.eh_handler and EH_THUNK.search(self.image.read(value, 48))):
            return "ehhandler"
        if name is None or name.startswith(ANONYMOUS_PREFIXES):
            for content in self.anonymous:  # Unnamed original data the candidate reaches by content.
                if self.image.read(value, len(content)) == content:
                    return "data:" + content.hex()
        return f"@{value:#x}"

    def _original_table(self, value: int, end: int) -> Item:
        entries: list[str] = []
        while len(entries) < 1024:
            entry = int.from_bytes(self.image.read(value + 4 * len(entries), 4), "little")
            if not self.address <= entry < end:
                break
            entries.append(f"fn{entry - self.address:+#x}")
        return Item(-1, ("table", tuple(entries)), "jump table: " + ", ".join(entries))

    def _original_entry(self, data: bytes, offset: int, start: int, end: int) -> str:
        value = int.from_bytes(data[offset : offset + 4], "little")
        return f"fn{value - self.address:+#x}" if self.address <= value < self.address + end else f"@{value:#x}"

    # Inline data follows the code of a function: jump tables, then byte tables.

    @staticmethod
    def _inline_data(data: bytes, data_refs: dict[int, bool], code_end: int, start: int, end: int,
                     entry: Callable[[bytes, int, int, int], str]) -> list[Item]:
        regions = sorted(o for o in data_refs if code_end <= o < end)
        items = []
        for index, region in enumerate(regions):
            stop = regions[index + 1] if index + 1 < len(regions) else end
            if data_refs[region]:
                entries = [entry(data, offset, start, end) for offset in range(region, stop - 3, 4)]
                items.append(Item(region - start, ("table", tuple(entries)), "jump table: " + ", ".join(entries)))
            else:
                raw = data[region:stop]
                items.append(Item(region - start, ("bytes", raw.hex()), "data " + raw.hex(" ")))
        return items

    def describe(self, token: str) -> str:
        if token.startswith("@"):
            name = self.names.describe(int(token[1:], 16))
            base, plus, offset = name.partition("+")
            return f"{token} {self.undecorate(base)}{plus}{offset}" if name else token
        return token


# -- Command line -----------------------------------------------------------------


def _windows_path(path: Path) -> str:
    return "Z:" + str(path.resolve()).replace("/", "\\")


def _split(text: str) -> list[str]:
    return shlex.split(text, posix=os.name != "nt")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m re_agent.oracles.msvc",
                                     description="Match oracle for MSVC-built 32-bit x86 Windows programs.")
    parser.add_argument("--original", required=True, type=Path)
    parser.add_argument("--address", required=True)
    parser.add_argument("--function", required=True, help="Qualified or decorated name")
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--compile", default="cl /nologo /c {source} /Fo{object}")
    parser.add_argument("--symbols", action="append", type=Path, default=[])
    parser.add_argument("--annotations", action="append", type=Path, default=[])
    parser.add_argument("--module", action="append", default=[])
    parser.add_argument("--extensions", default=".cpp,.c,.h,.hpp,.cxx,.cc")
    parser.add_argument("--size", type=lambda value: int(value, 0))
    parser.add_argument("--undname", help="Undecorator command (default: undname or llvm-undname)")
    parser.add_argument("flags", nargs="*")
    args = parser.parse_args(argv)
    try:
        return _compare(args)
    except (OracleError, OSError, ValueError) as exc:  # Unreadable inputs are setup errors, not comparisons.
        print(f"{type(exc).__name__}: {exc}" if not isinstance(exc, OracleError) else exc, file=sys.stderr)
        return 3


def _compare(args: argparse.Namespace) -> int:
    flags = _split(os.environ["RE_AGENT_MATCH_FLAGS"]) if os.environ.get("RE_AGENT_MATCH_FLAGS") else args.flags
    names = SymbolMap()
    if args.annotations:
        from re_agent.parity.annotations import read_annotations

        for root in args.annotations:
            for annotation in read_annotations(root, args.extensions.split(","), set(args.module) or None):
                names.add(int(annotation.address, 16), annotation.name)
    for path in args.symbols:
        for address, name, size in read_symbols(path):
            names.add(address, name, size)
    undecorate = Undecorator(_split(args.undname) if args.undname else None)

    with tempfile.TemporaryDirectory() as directory:
        obj_path = Path(directory) / "candidate.obj"
        values = {"source": str(args.source), "object": str(obj_path), "source_win": _windows_path(args.source),
                  "object_win": _windows_path(obj_path)}
        command = [re.sub(r"\{(source|object|source_win|object_win)\}", lambda m: values[m[1]], part)
                   for part in _split(args.compile)]
        try:
            compiled = subprocess.run([*command, *flags], capture_output=True, text=True, errors="replace")
        except OSError as exc:
            raise OracleError(f"Compiler could not start: {exc}") from exc
        if compiled.returncode or not obj_path.exists():
            print((compiled.stdout + "\n" + compiled.stderr).strip(), file=sys.stderr)  # cl reports on stdout.
            return compiled.returncode or 1
        obj = CoffObject(obj_path.read_bytes())

    functions = [s for s in obj.symbols if s.is_function and s.section > 0]
    undecorate.prepare(s.name for s in functions)
    wanted = [s for s in functions if args.function in (s.name, undecorate(s.name))]
    if len(wanted) != 1:
        raise OracleError(f"Expected one definition of {args.function} in the candidate object, found {len(wanted)}")
    function = wanted[0]
    undecorate.prepare(relocation[1].name for section in obj.sections.values()
                       for relocation in section.relocations.values())

    image = PeImage(args.original.read_bytes())
    address = int(args.address, 16)
    end = address + args.size if args.size else names.end_of(address)
    if end is None or (not args.size and address not in names.sizes and end - address > 0x10000):
        # The next mapped address bounds a function only when the map lists its neighbours.
        raise OracleError(f"Size of the function at {args.address} is unknown; pass --size or a sized symbol map")
    comparison = Comparison(obj, function, image, address, end - address, names, undecorate)
    right = comparison.candidate()  # First: the original resolves anonymous data by the candidate's content.
    left = comparison.original()
    print(json.dumps(_report(left, right, end - address, obj.extent(function), comparison.unmapped)))
    return 0


def _report(left: list[Item], right: list[Item], size: int, extent: tuple[int, int],
            unmapped: set[str]) -> dict[str, object]:
    exact = [item.key for item in left] == [item.key for item in right]
    matcher = difflib.SequenceMatcher(None, [i.key for i in left], [i.key for i in right], autojunk=False)
    diff: list[dict[str, object]] = []
    kinds = {"replace": "mismatch", "delete": "missing", "insert": "extra"}
    for op, a0, a1, b0, b1 in matcher.get_opcodes():
        if op == "equal":
            continue
        for index in range(max(a1 - a0, b1 - b0)):
            anchor = a0 + index if a0 + index < a1 else a1
            offset = left[anchor].offset if anchor < len(left) else size
            item: dict[str, object] = {"offset": max(offset, 0), "kind": kinds[op]}
            if a0 + index < a1:
                item["target"] = left[a0 + index].text
            if b0 + index < b1:
                item["candidate"] = right[b0 + index].text
            diff.append(item)
    summary = "Exact match" if exact else f"{len(diff)} differing items"
    if unmapped:
        summary += "; symbols missing from the symbol map: " + ", ".join(sorted(unmapped)[:8])
    return {"exact": exact, "score": 1.0 if exact else min(round(matcher.ratio(), 4), 0.9999), "summary": summary,
            "target_size": size, "candidate_size": extent[1] - extent[0], "diff": diff}


if __name__ == "__main__":
    sys.exit(main())
