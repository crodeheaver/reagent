"""Bounded, incremental views of native agent JSONL event logs."""
from __future__ import annotations

import hashlib
import json
import re
from collections import OrderedDict
from pathlib import Path
from typing import Any

MAX_AGENTS = 128
TEXT_LIMIT = 65536
ID_LIMIT = 128
LABEL_LIMIT = 256
STATUS_LIMIT = 64
BATCH_LIMIT = 64


def clip(value: object, limit: int) -> str:
    text = value if isinstance(value, str) else str(value)
    return text if len(text) <= limit else text[:limit - 1] + "\u2026"


def agent_key(value: str) -> str:
    # Provider IDs are untrusted; a digest keeps distinct long IDs distinct after clipping.
    if len(value) <= ID_LIMIT:
        return value
    digest = hashlib.sha256(value.encode("utf-8", "surrogatepass")).hexdigest()[:16]
    return value[:ID_LIMIT - len(digest) - 1] + "~" + digest


class AgentEvents:
    def __init__(self) -> None:
        self.path: Path | None = None
        self.offset = 0
        self.pending = b""
        self.agents: OrderedDict[str, dict[str, Any]] = OrderedDict()

    def agent(self, key: str, label: str = "") -> dict[str, Any]:
        key = agent_key(key)
        if key not in self.agents:
            self.agents[key] = {"id": key, "label": clip(label or key, LABEL_LIMIT), "status": "running",
                                "text": "", "log": ""}
        self.agents.move_to_end(key)
        while len(self.agents) > MAX_AGENTS:
            self.agents.popitem(last=False)
        return self.agents[key]

    def read(self, path: Path) -> list[dict[str, Any]]:
        if path != self.path or path.stat().st_size < self.offset:
            self.path, self.offset, self.pending = path, 0, b""
        with path.open("rb") as stream:
            stream.seek(self.offset)
            data = stream.read(1024 * 1024)
            self.offset = stream.tell()
        lines = (self.pending + data).split(b"\n")
        self.pending = lines.pop()[-1024 * 1024:]
        batch = clip(path.parent.name, BATCH_LIMIT)
        for line in lines:
            try:
                row = json.loads(line)
                if isinstance(row, dict):
                    self.consume(row, batch)
            except (ValueError, RecursionError):
                # Malformed, truncated or pathologically nested lines are skipped, never fatal.
                continue
        return list(self.agents.values())

    def consume(self, row: dict[str, Any], batch: str) -> None:
        # Unattributed token events must never be guessed to belong to a child.
        shared = self.agent(f"{batch}:shared", f"{batch} · shared stream (unattributed)")
        kind = row.get("type")
        if kind == "text" and isinstance(row.get("data"), str):
            shared["text"] = (shared["text"] + row["data"])[-TEXT_LIMIT:]
        elif kind == "tool_call":
            shared["log"] = (shared["log"] + "\n" + json.dumps({
                "tool": row.get("toolName"), "input": row.get("rawInput")}, ensure_ascii=False))[-TEXT_LIMIT:]
        elif kind == "tool_call_update":
            raw = row.get("rawOutput")
            if not isinstance(raw, dict):
                return
            text = raw.get("text", "")
            match = re.search(r"subagent_id: ([\w-]+)", text) if isinstance(text, str) else None
            if match and "Subagent started in background" in text:
                label = re.search(r"description: ([^\n]+)", text)
                child = self.agent(match[1], f"{batch} · {label[1] if label else match[1]}")
                child["log"] = text[-TEXT_LIMIT:]
            multi = raw.get("MultiResult")
            results = multi.get("results", []) if isinstance(multi, dict) else []
            for result in results if isinstance(results, list) else []:
                if not isinstance(result, dict) or not isinstance(result.get("task_id"), str):
                    continue
                child = self.agent(result["task_id"], f"{batch} · {result.get('command', result['task_id'])}")
                child.update(status=clip(result.get("status", "unknown"), STATUS_LIMIT),
                             text=str(result.get("output", ""))[-TEXT_LIMIT:],
                             log=json.dumps({k: v for k, v in result.items() if k != "output"},
                                            indent=2)[-TEXT_LIMIT:])
            if row.get("status") == "failed":
                shared["log"] = (shared["log"] + "\nERROR " + json.dumps(raw))[-TEXT_LIMIT:]
