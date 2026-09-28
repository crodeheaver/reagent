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
