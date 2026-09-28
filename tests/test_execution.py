import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from re_agent.orchestrator.execution import Cancelled, Execution, executing, validation_lane
from re_agent.utils.process import run_process


def test_cancelled_process_and_context_cleanup():
    cancel = threading.Event()
    context = Execution(cancel, threading.Semaphore(1), lambda *_: None)
    cancel.set()
    with pytest.raises(Cancelled), executing(context):
        pass
    # An unrelated call outside the scope is not cancelled.
    assert run_process([sys.executable, "-c", "print('ok')"]).stdout.strip() == "ok"


def test_validation_wait_is_cancellable():
    cancel = threading.Event()
    waiting = threading.Event()
    semaphore = threading.Semaphore(0)
    context = Execution(cancel, semaphore, lambda *_: waiting.set())

    def worker():
        with executing(context), validation_lane():
            pytest.fail("Validation must not run")

    with ThreadPoolExecutor(1) as executor:
        future = executor.submit(worker)
        assert waiting.wait(5)
        cancel.set()
        with pytest.raises(Cancelled):
            future.result(timeout=5)


def test_cancel_reaps_detached_process_tree(tmp_path):
    import json
    import os
    import sys
    import time
    from concurrent.futures import ThreadPoolExecutor

    import psutil
    import pytest

    from re_agent.utils.process import run_process

    ready = tmp_path / "ready.json"
    script = tmp_path / "parent.py"
    script.write_text(
        "import subprocess, sys, pathlib, json, os, time\n"
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], "
        "start_new_session=os.name != 'nt')\n"
        "pathlib.Path(sys.argv[1]).write_text(json.dumps([os.getpid(), child.pid]))\n"
        "time.sleep(60)\n"
    )
    cancel = threading.Event()

    def invoke():
        with executing(Execution(cancel, threading.Semaphore(1), lambda *args: None)):
            run_process([sys.executable, str(script), str(ready)], timeout_s=20)

    with ThreadPoolExecutor() as pool:
        future = pool.submit(invoke)
        deadline = time.monotonic() + 10
        while not ready.exists() and time.monotonic() < deadline:
            time.sleep(.02)
        try:
            assert ready.exists()
            pids = json.loads(ready.read_text())
        finally:
            cancel.set()
        with pytest.raises(Cancelled):
            future.result(timeout=10)
    for pid in pids:
        if psutil.pid_exists(pid):
            # POSIX init may not have reaped an already-dead grandchild yet.
            assert os.name != "nt" and psutil.Process(pid).status() == psutil.STATUS_ZOMBIE


def test_api_transports_do_not_hide_retries_from_call_budget(monkeypatch):
    from unittest.mock import Mock

    from re_agent.llm.claude import ClaudeProvider
    from re_agent.llm.openai_compat import OpenAIProvider

    for path, provider in [("re_agent.llm.claude.anthropic.Anthropic", ClaudeProvider),
                           ("re_agent.llm.openai_compat.openai.OpenAI", OpenAIProvider)]:
        constructor = Mock()
        monkeypatch.setattr(path, constructor)
        client = provider(api_key="test", timeout_s=7)
        assert constructor.call_args.kwargs["max_retries"] == 0
        assert constructor.call_args.kwargs["timeout"] == 7
        client.close()
        constructor.return_value.close.assert_called_once()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX signal delivery to self")
def test_second_interrupt_forces_stop_and_reaps_children(tmp_path):
    import subprocess
    import time

    import psutil

    script = tmp_path / "run.py"
    script.write_text(
        "import os, signal, subprocess, sys, threading, time\n"
        "from re_agent.orchestrator.execution import cancellation_signals\n"
        "cancel = threading.Event()\n"
        "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(60)'], start_new_session=True)\n"
        "print(child.pid, flush=True)\n"
        "with cancellation_signals(cancel):\n"
        "    os.kill(os.getpid(), signal.SIGINT)\n"
        "    time.sleep(.3)\n"
        "    print('stopping' if cancel.is_set() else 'ignored', flush=True)\n"
        "    os.kill(os.getpid(), signal.SIGINT)\n"
        "    time.sleep(30)\n"
        "print('not forced', flush=True)\n"
    )
    started = time.monotonic()
    proc = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, timeout=20,
                          env={**os.environ, "PYTHONPATH": str(Path(__file__).parents[1] / "src")})
    assert time.monotonic() - started < 15
    assert proc.returncode == 130, proc.stderr
    pid, state = proc.stdout.split()
    assert state == "stopping" and "Forced stop" in proc.stderr
    deadline = time.monotonic() + 5
    while psutil.pid_exists(int(pid)) and psutil.Process(int(pid)).status() != psutil.STATUS_ZOMBIE:
        assert time.monotonic() < deadline, "child survived the forced stop"
        time.sleep(.05)
