"""Exercise real WebSocket initialization, updates, and native event attribution."""
import json
import os
import socket
import threading
import time
import urllib.error
import urllib.request

import pytest
from wsproto import ConnectionType, WSConnection
from wsproto.events import CloseConnection, Request, TextMessage

from re_agent.monitor.events import AgentEvents
from re_agent.monitor.server import Monitor, make_server
from re_agent.utils.storage import atomic_json


def test_websocket_initial_snapshot_then_live_update(tmp_path):
    path = tmp_path / "session.json"
    path.write_text('{"functions": {}}')
    server = make_server(Monitor(tmp_path, tmp_path / "state", ["session.json"]), 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    ws = WSConnection(ConnectionType.CLIENT)
    host = f"127.0.0.1:{server.server_port}"
    try:
        with socket.create_connection(("127.0.0.1", server.server_port), timeout=5) as sock:
            sock.sendall(ws.send(Request(host=host, target="/api/stream",
                                         extra_headers=[(b"Origin", f"http://{host}".encode())])))
            pending = ""

            def receive():
                nonlocal pending
                while True:
                    ws.receive_data(sock.recv(65536))
                    for event in ws.events():
                        if isinstance(event, TextMessage):
                            pending += event.data
                            if event.message_finished:
                                result = json.loads(pending)
                                pending = ""
                                return result

            initial = receive()
            assert initial["type"] == "snapshot"
            assert initial["data"]["completed"] == 0
            atomic_json(path, {"functions": {"a": {"address": "100", "success": True}}})
            for _ in range(10):
                update = receive()
                if update["data"].get("completed") == 1:  # Clock ticks carry no counters.
                    break
            assert update["type"] == "update"
            assert update["data"]["completed"] == 1
            sock.sendall(ws.send(CloseConnection(code=1000)))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_native_events_handle_partial_lines_and_keep_agents_separate(tmp_path):
    path = tmp_path / "native.jsonl"
    reader = AgentEvents()
    path.write_bytes(b'{"type":"text","data":"shared')
    assert reader.read(path) == []
    with path.open('ab') as stream:
        stream.write(b' text"}\n')
    assert reader.read(path)[0]["text"] == "shared text"
    for agent in ("child-a", "child-b"):
        reader.consume({"type": "tool_call_update", "rawOutput": {"MultiResult": {"results": [
            {"task_id": agent, "command": agent, "status": "completed", "output": f"code for {agent}"}
        ]}}}, "batch")
    assert reader.agents["child-a"]["text"] == "code for child-a"
    assert reader.agents["child-b"]["text"] == "code for child-b"
    reader.consume({"type": "thought", "data": "not an activity event"}, "batch")
    assert "not an activity event" not in str(reader.agents)
    for n in range(200):
        reader.agent(str(n))
    assert len(reader.agents) == 128


def test_stream_rejects_foreign_origin_and_history_cannot_escape(tmp_path):
    server = make_server(Monitor(tmp_path, tmp_path / "state", [], event_glob="*.jsonl"), 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    try:
        request = urllib.request.Request(base + "/api/stream", headers={
            "Origin": "https://untrusted.example", "Upgrade": "websocket"})
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request)
        assert error.value.code == 403
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(urllib.request.Request(base + "/api/agent-history?source=../secret.jsonl",
                                                          headers={"Sec-Fetch-Site": "same-origin"}))
        assert error.value.code == 404
        (tmp_path / "test.jsonl").write_text('{"type":"text","data":"<script>inert</script>"}\n')
        request = urllib.request.Request(base + "/api/agent-history?source=test.jsonl",
                                         headers={"Sec-Fetch-Site": "same-origin"})
        with urllib.request.urlopen(request) as response:
            assert json.load(response)["agents"][0]["text"] == "<script>inert</script>"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_native_event_fields_stay_bounded_and_odd_lines_are_skipped(tmp_path):
    path = tmp_path / ("batch-" + "b" * 200) / "native.jsonl"
    path.parent.mkdir()
    rows = [b"[" * 100000 + b"]" * 100000, b'{"type": "text", "data": ', b"\xff\xfe"]
    rows += [json.dumps({"type": "tool_call_update", "rawOutput": {"MultiResult": {"results": [
        {"task_id": "t" * 5000 + str(n), "status": ["s"] * 20000, "command": "c" * 5000, "output": "x"}]}}}).encode()
        for n in range(130)]
    rows.append(b'{"type":"text","data":"after odd lines"}')
    path.write_bytes(b"\n".join(rows) + b"\n")
    reader = AgentEvents()
    while reader.offset < path.stat().st_size:
        agents = reader.read(path)
    assert len(agents) == 128
    assert len({agent["id"] for agent in agents}) == 128
    for agent in agents:
        assert len(agent["id"]) <= 128 and len(agent["label"]) <= 256 and len(agent["status"]) <= 64
        assert len(agent["text"]) <= 65536 and len(agent["log"]) <= 65536
    shared = agents[-1]
    assert shared["id"].endswith(":shared")
    assert shared["text"] == "after odd lines"


def text_lines(*values):
    return "".join(json.dumps({"type": "text", "data": value}) + "\n" for value in values)


def test_live_batch_view_follows_one_source_without_duplication(tmp_path):
    first, second = tmp_path / "b1" / "native.jsonl", tmp_path / "b2" / "native.jsonl"
    for path in (first, second):
        path.parent.mkdir()
    first.write_text(text_lines("A1 "))
    reader = AgentEvents()
    assert [a["text"] for a in reader.read(first)] == ["A1 "]
    second.write_text(text_lines("B1 "))
    assert [(a["id"], a["text"]) for a in reader.read(second)] == [("b2:shared", "B1 ")]
    with first.open("a") as stream:
        stream.write(text_lines("A2 "))
    assert [(a["id"], a["text"]) for a in reader.read(first)] == [("b1:shared", "A1 A2 ")]


def test_rewritten_or_replaced_source_restarts_the_view(tmp_path):
    path = tmp_path / "b1" / "native.jsonl"
    path.parent.mkdir()
    reader = AgentEvents()
    path.write_text(text_lines("X"))
    assert reader.read(path)[0]["text"] == "X"
    path.write_text(text_lines("Y", "Z"))  # rewritten in place, larger than before
    assert reader.read(path)[0]["text"] == "YZ"
    path.write_text(text_lines("Y" * 300, "Z"))
    assert reader.read(path)[0]["text"] == "Y" * 300 + "Z"
    replacement = tmp_path / "b1" / "native.jsonl.tmp"
    replacement.write_text(text_lines("Y" * 300, "C" * 40, "D"))  # identical head, different file
    os.replace(replacement, path)
    assert reader.read(path)[0]["text"] == "Y" * 300 + "C" * 40 + "D"


def test_stream_closes_cleanly_when_state_is_unavailable(tmp_path, monkeypatch):
    monitor = Monitor(tmp_path, tmp_path / "state", [])
    server = make_server(monitor, 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host = f"127.0.0.1:{server.server_port}"

    def failing():
        raise RuntimeError("unexpected")

    monkeypatch.setattr(monitor, "snapshot", failing)
    ws = WSConnection(ConnectionType.CLIENT)
    try:
        with socket.create_connection(("127.0.0.1", server.server_port), timeout=5) as sock:
            sock.sendall(ws.send(Request(host=host, target="/api/stream",
                                         extra_headers=[(b"Origin", f"http://{host}".encode())])))
            events = []
            while not any(isinstance(event, CloseConnection) for event in events):
                data = sock.recv(65536)
                assert data, "connection dropped without a close frame"
                ws.receive_data(data)
                events += list(ws.events())
            assert [e.code for e in events if isinstance(e, CloseConnection)] == [1011]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def open_stream(server):
    host = f"127.0.0.1:{server.server_port}"
    sock = socket.create_connection(("127.0.0.1", server.server_port), timeout=5)
    ws = WSConnection(ConnectionType.CLIENT)
    sock.sendall(ws.send(Request(host=host, target="/api/stream",
                                 extra_headers=[(b"Origin", f"http://{host}".encode())])))
    return sock, ws


def stream_messages(sock, ws, seconds):
    messages, pending = [], ""
    sock.settimeout(.2)
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            data = sock.recv(1 << 20)
        except TimeoutError:
            continue
        ws.receive_data(data)
        for event in ws.events():
            if isinstance(event, TextMessage):
                pending += event.data
                if event.message_finished:
                    messages.append((len(pending), json.loads(pending)))
                    pending = ""
    return messages


def test_idle_stream_sends_small_ticks_not_full_snapshots(tmp_path):
    (tmp_path / "b1").mkdir()
    (tmp_path / "b1" / "native.jsonl").write_text(json.dumps({"type": "text", "data": "x" * 60000}) + "\n")
    path = tmp_path / "session.json"
    path.write_text('{"functions": {}}')
    server = make_server(Monitor(tmp_path, tmp_path / "state", ["session.json"], event_glob="*/native.jsonl"), 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        sock, ws = open_stream(server)
        with sock:
            messages = stream_messages(sock, ws, 2.6)
            assert messages[0][1]["type"] == "snapshot"
            assert messages[0][0] > 60000
            idle = messages[1:]
            assert idle and all(message["type"] == "tick" and size < 1000 for size, message in idle)
            atomic_json(path, {"functions": {"a": {"address": "100", "success": True}}})
            updates = [m for _, m in stream_messages(sock, ws, 1.5) if m["type"] == "update"]
            assert updates[0]["data"]["completed"] == 1
            assert "agents" not in updates[0] and "output" not in updates[0]["data"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_stream_diff_sends_changed_fields_and_agents_only():
    from re_agent.monitor.server import StreamDiff

    agents = [{"id": f"a{n}", "label": "", "status": "running", "text": "t" * 1000, "log": ""} for n in range(3)]
    state = {"completed": 1, "phase": "running", "updated": "10:00:00", "agents": agents}
    diff = StreamDiff()
    assert diff.message(json.loads(json.dumps(state)))["type"] == "snapshot"
    assert diff.message(json.loads(json.dumps(state))) is None
    state["updated"] = "10:00:01"
    assert diff.message(json.loads(json.dumps(state))) == {"type": "tick", "data": {"updated": "10:00:01"}}
    state["agents"][1]["status"] = "completed"
    state["agents"] = state["agents"][1:]
    state.pop("phase")
    message = diff.message(json.loads(json.dumps(state)))
    assert message["type"] == "update"
    assert message["data"] == {"updated": "10:00:01"}
    assert message["removed"] == ["phase"]
    assert message["agents"]["order"] == ["a1", "a2"]
    assert [agent["id"] for agent in message["agents"]["changed"]] == ["a1"]


def test_live_streams_are_capped(tmp_path):
    from re_agent.monitor.server import MAX_STREAMS

    server = make_server(Monitor(tmp_path, tmp_path / "state", []), 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    sockets = []
    try:
        for _ in range(MAX_STREAMS):
            sock, ws = open_stream(server)
            sockets.append(sock)
            assert stream_messages(sock, ws, .3)[0][1]["type"] == "snapshot"
        sock, _ws = open_stream(server)
        sockets.append(sock)
        sock.settimeout(5)
        assert sock.recv(4096).startswith(b"HTTP/1.0 503")
        sockets.pop().close()
        sockets.pop().close()
        time.sleep(1)  # The server notices the closed stream on its next poll.
        sock, ws = open_stream(server)
        sockets.append(sock)
        assert stream_messages(sock, ws, .5)[0][1]["type"] == "snapshot"
    finally:
        for sock in sockets:
            sock.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
