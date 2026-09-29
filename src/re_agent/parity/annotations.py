"""Read reccmp-style address annotations from source.

Matching projects mark each recovered item with its original address, for example::

    // FUNCTION: GAME 0x401000
    void CFoo::Bar(int x) { ... }

    // GLOBAL: GAME 0x5b0000
    int g_count = 0;

    // SYNTHETIC: GAME 0x401200
    // CFoo::`scalar deleting destructor'

Function-like markers (FUNCTION, STUB, TEMPLATE, SYNTHETIC, LIBRARY) and data
markers (GLOBAL, VTABLE) are recognized; names resolve from the following
definition, or from the following comment for compiler-generated and library
items. Enclosing namespaces and classes qualify the name.
"""

from __future__ import annotations

import re
from collections.abc import Collection, Iterable
from dataclasses import dataclass
from pathlib import Path

from re_agent.verification.candidate import _NON_CODE

MARKER = re.compile(
    r"^[ \t]*//[ \t]*(FUNCTION|STUB|TEMPLATE|SYNTHETIC|LIBRARY|GLOBAL|VTABLE|STRING|LINE)[ \t]*:"
    r"[ \t]*([A-Za-z0-9_]+)[ \t]+(0x[0-9A-Fa-f]+)\b",
    re.M,
)
FUNCTION_KINDS = frozenset({"FUNCTION", "STUB", "TEMPLATE", "SYNTHETIC", "LIBRARY"})
DATA_KINDS = frozenset({"GLOBAL", "VTABLE"})
SOURCE_KINDS = frozenset({"FUNCTION", "STUB"})  # Kinds with a definition in the source tree.
_NAMED_BY_COMMENT = frozenset({"TEMPLATE", "SYNTHETIC", "LIBRARY"})
_SCOPE = re.compile(r"\b(class|struct|union|namespace)\s+([A-Za-z_][\w:]*)[^;{}()]*\{|[{}]")
_TEMPLATE_PARAMETERS = re.compile(r"\btemplate\s*<[^<>]*(?:<[^<>]*>[^<>]*)*>")
_QUALIFIED = re.compile(
    r"((?:[A-Za-z_]\w*(?:<[^()]*?>)?::)*(?:operator\s*(?:\(\)|[^\s(\w]+|\w[\w\s*&]*?)|~?[A-Za-z_]\w*))\s*$"
)


@dataclass(frozen=True)
class Annotation:
    kind: str
    module: str
    address: str  # Lowercase with a 0x prefix.
    name: str  # Qualified; empty when no name could be read.
    path: str
    line: int

    @property
    def scope_and_name(self) -> tuple[str, str]:
        """Split into (class, function) the way the source index keys definitions."""
        parts = self.name.split("::")
        return (parts[-2] if len(parts) > 1 else "", parts[-1])


def parse_annotations(text: str, path: str = "", modules: Collection[str] | None = None) -> list[Annotation]:
    code = _TEMPLATE_PARAMETERS.sub(lambda m: " " * len(m[0]), _blank_non_code(text))
    scopes = _SCOPE.finditer(code)
    stack: list[str | None] = []  # Named class/namespace scopes; None for other braces.
    pending = next(scopes, None)
    lines = text.splitlines()
    found = []
    for match in MARKER.finditer(text):
        while pending is not None and pending.start() < match.start():
            if pending[2]:
                stack.append(pending[2])
            elif pending[0] == "{":
                stack.append(None)
            elif stack:
                stack.pop()
            pending = next(scopes, None)
        kind, module, address = match[1], match[2], match[3].lower()
        if kind in ("STRING", "LINE") or (modules is not None and module not in modules):
            continue
        line = text.count("\n", 0, match.start())
        name = _name_after(lines, line, kind)
        if name and kind not in _NAMED_BY_COMMENT:
            name = "::".join([*(scope for scope in stack if scope), name])
        found.append(Annotation(kind, module, address, name, path, line + 1))
    return found


def read_annotations(root: Path, extensions: Iterable[str], modules: Collection[str] | None = None) -> list[Annotation]:
    found: list[Annotation] = []
    for path in sorted(p for extension in extensions for p in root.rglob(f"*{extension}")):
        found.extend(parse_annotations(path.read_text(encoding="utf-8", errors="ignore"), str(path), modules))
    return found


def _name_after(lines: list[str], index: int, kind: str) -> str:
    """Read the name of the item following a block of markers."""
    following: list[str] = []
    for line in lines[index + 1 :]:
        stripped = line.strip()
        if MARKER.match(line) or not stripped:
            if following:
                break
            continue
        if stripped.startswith("//"):
            if kind in _NAMED_BY_COMMENT and not following:
                return stripped[2:].strip()
            continue
        following.append(stripped)
        if kind in FUNCTION_KINDS and "(" in stripped or kind in DATA_KINDS and re.search(r"[=;\[{]", stripped):
            break
        if len(following) >= 6:
            break
    declaration = " ".join(following)
    if kind == "VTABLE":
        match = re.search(r"\b(?:class|struct)\s+(?:__declspec\([^)]*\)\s*)?([A-Za-z_][\w:]*)", declaration)
        return f"{match[1]}::`vftable'" if match else ""
    if kind in FUNCTION_KINDS:
        head = _before_parameters(declaration)
    else:
        head = re.split(r"[=;\[{]", declaration, maxsplit=1)[0]
    match = _QUALIFIED.search(head.strip())
    return re.sub(r"\s+", " ", match[1]).strip() if match else ""


def _before_parameters(declaration: str) -> str:
    depth = 0
    for index, char in enumerate(declaration):
        if char == "<":
            depth += 1
        elif char == ">":
            depth = max(0, depth - 1)
        elif char == "(" and depth == 0:
            head = declaration[:index]
            return head + "()" if head.rstrip().endswith("operator") else head
    return declaration


def _blank_non_code(text: str) -> str:
    """Blank comments and literals while keeping offsets and line breaks."""
    return _NON_CODE.sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)
