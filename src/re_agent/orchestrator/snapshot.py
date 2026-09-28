"""Immutable per-worker project snapshots for cumulative proposals."""
from __future__ import annotations

import copy
import json
import tempfile
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from re_agent.config.schema import ReAgentConfig
from re_agent.verification.candidate import copy_project_tree


@contextmanager
def project_snapshot(config: ReAgentConfig, lock: threading.Lock) -> Iterator[ReAgentConfig]:
    with tempfile.TemporaryDirectory(prefix="re-agent-worker-") as directory:
        scratch = Path(directory)
        original = Path(config.validation.project_root).resolve()
        source = Path(config.project_profile.source_root).resolve().relative_to(original)
        isolated = copy.deepcopy(config)
        with lock:
            copy_project_tree(original, scratch, config.output.session_file)
            if config.project_profile.compilation_database:
                database = json.loads(Path(config.project_profile.compilation_database).read_text(encoding="utf-8"))
                destination = scratch / ".re-agent-compile_commands.json"
                destination.write_text(json.dumps(database).replace(str(original), str(scratch)), encoding="utf-8")
                isolated.project_profile.compilation_database = str(destination)
        isolated.validation.project_root = str(scratch)
        isolated.project_profile.source_root = str(scratch / source)
        yield isolated
