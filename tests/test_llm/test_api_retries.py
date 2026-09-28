"""Sequential API runs keep SDK retries; parallel workers own budgeted retries."""
import sys
import threading

import anthropic
import openai
import pytest

from re_agent.llm.claude import ClaudeProvider
from re_agent.llm.observed import CallBudget, ObservedProvider
from re_agent.llm.openai_compat import OpenAIProvider
from re_agent.llm.protocol import Message
from re_agent.orchestrator.execution import Execution, RequestQueue, executing

CLAUDE_REPLY = {"id": "msg", "type": "message", "role": "assistant", "model": "m", "stop_reason": "end_turn",
                "stop_sequence": None, "content": [{"type": "text", "text": "hello"}],
                "usage": {"input_tokens": 1, "output_tokens": 1}}
OPENAI_REPLY = {"id": "chat", "object": "chat.completion", "created": 0, "model": "m",
                "choices": [{"index": 0, "finish_reason": "stop",
                             "message": {"role": "assistant", "content": "hello"}}]}


def _flaky_transport(monkeypatch, path, sdk, status, reply):
    """Route the SDK through a transport that fails once with *status*, then answers."""
    # Use the HTTP library the installed SDK is built on (httpx or its successor).
    base = next(cls for cls in type(sdk(api_key="probe")._client).__mro__ if cls.__module__.startswith("httpx"))
    http = sys.modules[base.__module__.split(".")[0]]
    attempts = []

    def handler(request):
        attempts.append(request)
        if len(attempts) == 1:
            return http.Response(status, headers={"retry-after-ms": "1"},
                                 json={"type": "error", "error": {"type": "overloaded_error", "message": "busy"}})
        return http.Response(200, json=reply)

    monkeypatch.setattr(path, lambda **kwargs: sdk(
        http_client=http.Client(transport=http.MockTransport(handler)), **kwargs))
    return attempts


def _parallel_context():
    return executing(Execution(threading.Event(), threading.Semaphore(1), lambda *args: None, RequestQueue(1)))


def test_sequential_claude_requests_survive_transient_overload(monkeypatch):
    attempts = _flaky_transport(monkeypatch, "re_agent.llm.claude.anthropic.Anthropic", anthropic.Anthropic,
                                529, CLAUDE_REPLY)
    provider = ClaudeProvider(api_key="test")
    request = {"model": "m", "max_tokens": 8, "messages": [{"role": "user", "content": "hi"}]}
    reply = provider._request_client().messages.create(**request)
    assert reply.content[0].text == "hello"
    assert len(attempts) == 2

    attempts.clear()
    with _parallel_context(), pytest.raises(anthropic.APIStatusError):
        provider._request_client().messages.create(**request)
    assert len(attempts) == 1
    provider.close()


def test_sequential_openai_retries_do_not_spend_call_budget(monkeypatch):
    attempts = _flaky_transport(monkeypatch, "re_agent.llm.openai_compat.openai.OpenAI", openai.OpenAI,
                                503, OPENAI_REPLY)
    provider = OpenAIProvider(api_key="test", model="m")
    budget = CallBudget(1)
    assert ObservedProvider(provider, budget, "reverser", None).send([Message("user", "hi")]) == "hello"
    assert len(attempts) == 2
    assert budget.used == 1

    attempts.clear()
    with _parallel_context(), pytest.raises(openai.InternalServerError):
        ObservedProvider(provider, CallBudget(1), "reverser", None).send([Message("user", "hi")])
    assert len(attempts) == 1
    provider.close()
