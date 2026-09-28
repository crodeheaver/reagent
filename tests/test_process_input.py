"""Subprocess stdin is delivered completely, with or without an execution context."""
import subprocess
import sys
import threading
from contextlib import nullcontext

import pytest

from re_agent.orchestrator.execution import Execution, executing
from re_agent.utils.process import run_process

# The child starts reading only after the parent's first polling interval has
# passed, with far more input queued than a pipe buffer holds.
SLOW_READER = [sys.executable, "-c", "import sys, time; time.sleep(.5); print(len(sys.stdin.read()))"]


@pytest.mark.parametrize("parallel", [False, True], ids=["sequential", "execution-context"])
def test_large_input_reaches_slow_reader(parallel):
    scope = executing(Execution(threading.Event(), threading.Semaphore(1), lambda *args: None)) \
        if parallel else nullcontext()
    with scope:
        proc = run_process(SLOW_READER, input_text="x" * 300_000, timeout_s=10)
    assert proc.returncode == 0
    assert proc.stdout.strip() == "300000"


def test_child_that_ignores_input_still_times_out():
    with pytest.raises(subprocess.TimeoutExpired):
        run_process([sys.executable, "-c", "import time; time.sleep(30)"], input_text="x" * 300_000, timeout_s=1)


def test_unencodable_input_fails_before_starting_the_child(tmp_path):
    marker = tmp_path / "started"
    with pytest.raises(UnicodeEncodeError):
        run_process([sys.executable, "-c", f"open({str(marker)!r}, 'w')"], input_text="\ud800")
    assert not marker.exists()
