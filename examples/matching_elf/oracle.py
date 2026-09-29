"""Reference match oracle for GCC/Clang ELF projects using GNU binutils.

Usage:
    python oracle.py --original BINARY --address ADDR --function NAME --source FILE
                     [--size N] [--cc gcc] -- [compile flags...]

Compiles FILE with ``--cc -c`` and the given flags (or ``RE_AGENT_MATCH_FLAGS``),
finds NAME in the object by its demangled name, and compares it with the original
function at ADDR instruction by instruction:

- instructions without symbolic operands must have identical bytes;
- calls, branches and RIP-relative references are compared by what they reach,
  since their encoded displacements necessarily differ between an object and a
  linked binary: an offset within the function, a named symbol plus offset, or,
  for anonymous data (string literals, constant pools), the referenced bytes. The
  width is the operand size, or a NUL-terminated string for address computations.

Prints one JSON object as described in ``re_agent.verification.matching``; a
failed compilation exits with the compiler's status after printing its errors.
Tested on x86-64 with GNU binutils; other targets need their own normalization.
"""

from __future__ import annotations

import argparse
import difflib
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

INSTRUCTION = re.compile(r"^\s*([0-9a-f]+):\t([0-9a-f ]+?)\s*\t(.*)$")
RELOCATION = re.compile(r"^\s*([0-9a-f]+): (R_\S+)\s+(\S+)$")
SECTION = re.compile(r"^\s*\d+\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+[0-9a-f]+\s+([0-9a-f]+)\s")
SYMBOL = re.compile(r"^([0-9a-f]+) (.{7}) (\S+)\t([0-9a-f]+)\s+(.+)$")
TARGET = re.compile(r"\b([0-9a-f]+) <([^>]+)>")
ADDEND = re.compile(r"(.+?)(?:([+-])(0x[0-9a-f]+))?")
RIP = re.compile(r"\[rip[+-]0x[0-9a-f]+\]")
WIDTH = re.compile(r"\b(BYTE|WORD|DWORD|QWORD|TBYTE|XMMWORD|YMMWORD|ZMMWORD) PTR")
WIDTHS = {"BYTE": 1, "WORD": 2, "DWORD": 4, "QWORD": 8, "TBYTE": 10, "XMMWORD": 16, "YMMWORD": 32, "ZMMWORD": 64}
PC_RELATIVE = ("PC32", "PLT32", "PC64", "GOTPCREL", "GOTPC32")


@dataclass
class Instruction:
    offset: int
    raw: bytes
    text: str
    relocations: list[tuple[int, str, str]]


@dataclass
class Symbol:
    section: str
    value: int
    size: int
    name: str
    pretty: str


def run(*command: str) -> str:
    return subprocess.run(command, check=True, capture_output=True, text=True).stdout


class Image:
    """Sections, sized symbols and raw bytes of an object file or linked binary."""

    def __init__(self, path: Path) -> None:
        self.path, self.data = path, path.read_bytes()
        self.sections = {m[1]: (int(m[2], 16), int(m[3], 16), int(m[4], 16))
                         for m in map(SECTION.match, run("objdump", "-h", "-w", str(path)).splitlines()) if m}
        raw, pretty = (run("objdump", "-t", *flag, str(path)).splitlines() for flag in ((), ("-C",)))
        self.by_name: dict[str, Symbol] = {}
        self.symbols: list[Symbol] = []  # Sized functions and objects, which can own an address.
        for line, readable in zip(raw, pretty, strict=True):
            match, shown = SYMBOL.match(line), SYMBOL.match(readable)
            if not (match and shown and match[5].split()):
                continue  # Not a symbol row, or an unnamed symbol.
            # Linked images add version or visibility columns before the name.
            symbol = Symbol(match[3], int(match[1], 16), int(match[4], 16), match[5].split()[-1],
                            shown[5].strip().removeprefix(".hidden ").strip())
            self.by_name.setdefault(symbol.name, symbol)
            if symbol.size and match[2][6] in "FO ":
                self.symbols.append(symbol)

    def owner(self, value: int, section: str | None = None) -> Symbol | None:
        return next((s for s in self.symbols if (section is None or s.section == section)
                     and s.value <= value < s.value + s.size), None)

    def read(self, value: int, width: int | None, section: str | None = None) -> bytes | None:
        """Read referenced data by section offset, or by address in a linked image."""
        for name, (size, vma, offset) in self.sections.items():
            if (name == section if section else vma <= value < vma + size):
                start = offset + value - (0 if section else vma)
                chunk = self.data[start : start + (width or 256)]
                return chunk if width else chunk.split(b"\0", 1)[0] + b"\0"
        return None

    def disassemble(self, *selection: str) -> list[Instruction]:
        output = run("objdump", "-d", "-r", "-M", "intel", "--insn-width=16", *selection, str(self.path))
        instructions: list[Instruction] = []
        for line in output.splitlines():
            if match := INSTRUCTION.match(line):
                instructions.append(Instruction(int(match[1], 16), bytes.fromhex(match[2].replace(" ", "")),
                                                re.sub(r"\s+", " ", match[3].strip()), []))
            elif (match := RELOCATION.match(line)) and instructions:
                instructions[-1].relocations.append((int(match[1], 16), match[2], match[3]))
        return instructions


def named(name: str, offset: int) -> str:
    return f"<{name}{offset:+#x}>" if offset else f"<{name}>"


def anonymous(content: bytes | None) -> str:
    return f"<data:{content.hex()}>" if content is not None else "<data:unreadable>"


def normalize(
    instruction: Instruction, start: int, end: int, resolve: Callable[[str, int, int | None], str]
) -> tuple[str, bytes | int]:
    """Return (text, bytes) for plain instructions and (text, length) for symbolic ones.

    ``resolve(name, value, width)`` names a reference: a relocation symbol plus
    offset in an object, or an annotated target address in a linked image.
    """
    text, _, comment = instruction.text.partition(" # ")
    width = WIDTHS[found[1]] if (found := WIDTH.search(text)) else None
    for place, kind, target in instruction.relocations:
        name, sign, addend = ADDEND.fullmatch(target).groups()  # type: ignore[union-attr]  # Always matches.
        value = (int(addend, 16) if addend else 0) * (-1 if sign == "-" else 1)
        if any(marker in kind for marker in PC_RELATIVE):
            value += instruction.offset + len(instruction.raw) - place
        ref = resolve(name.split("@")[0], value, width)
        if RIP.search(text):
            text = RIP.sub(f"[rip+{ref}]", text)
        elif TARGET.search(text):
            text = TARGET.sub(ref, text, count=1)
        else:
            text += f" {ref}"
    if instruction.relocations:
        return text, len(instruction.raw)
    if RIP.search(text) and (found := TARGET.search(comment)):
        return RIP.sub(f"[rip+{resolve('', int(found[1], 16), width)}]", text), len(instruction.raw)
    if found := TARGET.search(text):
        address = int(found[1], 16)
        ref = f"<{address - start:+#x}>" if start <= address < end else resolve(found[2], address, None)
        return text[: found.start()] + ref + text[found.end():], len(instruction.raw)
    return text, instruction.raw


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--original", required=True, type=Path)
    parser.add_argument("--address", required=True)
    parser.add_argument("--function", required=True)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--size", type=lambda value: int(value, 0))
    parser.add_argument("--cc", default="cc")
    parser.add_argument("flags", nargs="*")
    args = parser.parse_args()
    flags = shlex.split(os.environ["RE_AGENT_MATCH_FLAGS"]) if os.environ.get("RE_AGENT_MATCH_FLAGS") else args.flags

    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "candidate.o"
        compiled = subprocess.run([args.cc, "-c", str(args.source), "-o", str(path), *flags],
                                  capture_output=True, text=True)
        if compiled.returncode:
            print(compiled.stderr or compiled.stdout, file=sys.stderr)
            return compiled.returncode
        obj = Image(path)
        wanted = [s for s in obj.symbols if s.pretty.split("(")[0].strip() == args.function and s.section != "*UND*"]
        if len(wanted) != 1:
            print(f"Expected one definition of {args.function} in the candidate object, found {len(wanted)}",
                  file=sys.stderr)
            return 3
        function = wanted[0]
        candidate = [i for i in obj.disassemble(f"--disassemble={function.name}")
                     if function.value <= i.offset < function.value + function.size]

    original = Image(args.original)
    address = int(args.address, 16)
    size = args.size or next((s.size for s in original.symbols if s.value == address), None)
    if not size:
        print(f"No sized symbol at {args.address}; pass --size", file=sys.stderr)
        return 3
    target = original.disassemble(f"--start-address={address:#x}", f"--stop-address={address + size:#x}")

    def resolve_original(annotation: str, where: int, width: int | None) -> str:
        if (owner := original.owner(where)) is not None:
            return named(owner.name, where - owner.value)
        if "@plt" in annotation:
            return named(annotation.split("@")[0], 0)
        return anonymous(original.read(where, width))

    def resolve_candidate(name: str, value: int, width: int | None) -> str:
        symbol = obj.by_name.get(name)
        if name in obj.sections:
            section, where = name, value
        elif symbol is not None and not symbol.size and symbol.section in obj.sections:
            section, where = symbol.section, symbol.value + value  # A local label such as .LC0.
        else:
            return named(name, value)  # Named functions and objects keep their identity when linked.
        # Section-relative: a local symbol, or anonymous data compared by its bytes.
        owner = obj.owner(where, section)
        return named(owner.name, where - owner.value) if owner else anonymous(obj.read(where, width, section))

    def resolve_unrelocated(annotation: str, where: int, width: int | None) -> str:
        # A same-section call the assembler resolved: objdump's annotation names the callee.
        base, _, offset = annotation.partition("+")
        return named(base.split("@")[0], int(offset, 16) if offset else 0)

    left = [normalize(i, address, address + size, resolve_original) for i in target]
    right = [normalize(i, function.value, function.value + function.size,
                       lambda n, v, w, i=i: (resolve_candidate if i.relocations else resolve_unrelocated)(n, v, w))
             for i in candidate]
    exact = left == right  # Entries carry bytes, or lengths for symbolic operands.
    matcher = difflib.SequenceMatcher(None, left, right, autojunk=False)
    diff = []
    kinds = {"replace": "mismatch", "delete": "missing", "insert": "extra"}
    for op, a0, a1, b0, b1 in matcher.get_opcodes():
        if op == "equal":
            continue
        for index in range(max(a1 - a0, b1 - b0)):
            # Extra candidate instructions are anchored before the next target instruction.
            anchor = a0 + index if a0 + index < a1 else a1
            item: dict[str, object] = {
                "offset": target[anchor].offset - address if anchor < len(target) else size, "kind": kinds[op]}
            if a0 + index < a1:
                item["target"] = describe(left[a0 + index])
            if b0 + index < b1:
                item["candidate"] = describe(right[b0 + index])
            diff.append(item)
    score = 1.0 if exact else min(round(matcher.ratio(), 4), 0.9999)
    print(json.dumps({"exact": exact, "score": score, "diff": diff, "target_size": size,
                      "candidate_size": function.size,
                      "summary": "Exact match" if exact else f"{len(diff)} differing instructions"}))
    return 0


def describe(entry: tuple[str, bytes | int]) -> str:
    text, detail = entry
    return f"{text} [{detail.hex(' ')}]" if isinstance(detail, bytes) else text


if __name__ == "__main__":
    sys.exit(main())
