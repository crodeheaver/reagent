import errno
import sys

import pytest

from re_agent.utils.storage import file_lock


@pytest.mark.skipif(sys.platform == "win32", reason="patches fcntl")
@pytest.mark.parametrize("code", [errno.EWOULDBLOCK, errno.EACCES, errno.EDEADLK])
def test_nonblocking_contention_is_reported_uniformly(tmp_path, monkeypatch, code):
    import fcntl

    def busy(handle, operation):
        if operation & fcntl.LOCK_NB:
            raise OSError(code, "busy")

    monkeypatch.setattr(fcntl, "flock", busy)
    with pytest.raises(BlockingIOError), file_lock(tmp_path / "session.json", blocking=False):
        pass


@pytest.mark.skipif(sys.platform == "win32", reason="patches fcntl")
def test_other_lock_failures_are_not_reported_as_contention(tmp_path, monkeypatch):
    import fcntl

    def unsupported(handle, operation):
        raise OSError(errno.ENOLCK, "no locks available")

    monkeypatch.setattr(fcntl, "flock", unsupported)
    with pytest.raises(OSError) as raised, file_lock(tmp_path / "session.json", blocking=False):
        pass
    assert not isinstance(raised.value, BlockingIOError)


def test_atomic_json_retries_replace_while_a_reader_holds_the_file(tmp_path, monkeypatch):
    import json
    import os

    from re_agent.utils import storage

    replace, failures = os.replace, []

    def busy_then_free(src, dst):
        if len(failures) < 2:
            failures.append(dst)
            raise PermissionError(13, "file in use")
        replace(src, dst)

    monkeypatch.setattr(storage.os, "replace", busy_then_free)
    monkeypatch.setattr(storage.time, "sleep", lambda seconds: None)
    storage.atomic_json(tmp_path / "status.json", {"ok": True})
    assert json.loads((tmp_path / "status.json").read_text()) == {"ok": True}
    assert list(tmp_path.iterdir()) == [tmp_path / "status.json"]

    def always_busy(src, dst):
        raise PermissionError(13, "file in use")

    monkeypatch.setattr(storage.os, "replace", always_busy)
    with pytest.raises(PermissionError):
        storage.atomic_json(tmp_path / "status.json", {"ok": False})
    assert json.loads((tmp_path / "status.json").read_text()) == {"ok": True}
