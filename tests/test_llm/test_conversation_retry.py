"""A retried conversation turn is sent, and recorded, exactly once."""
import threading

import pytest

from re_agent.llm.claude import ClaudeProvider
from re_agent.llm.codex_cli import CodexCLIProvider
from re_agent.llm.observed import CallBudget, ObservedProvider
from re_agent.llm.openai_compat import OpenAIProvider
from re_agent.orchestrator.execution import Execution, RequestQueue, executing


class RateLimit(Exception):
    status_code = 429


@pytest.mark.parametrize("factory", [lambda: ClaudeProvider(api_key="test"), lambda: OpenAIProvider(api_key="test"),
                                     CodexCLIProvider], ids=["claude", "openai", "codex"])
def test_rate_limited_turn_is_not_duplicated_on_retry(monkeypatch, factory):
    provider = factory()
    sent = []

    def send(messages, **kwargs):
        sent.append([(m.role, m.content) for m in messages])
        if len(sent) == 1:
            raise RateLimit("slow down")
        return "reply"

    monkeypatch.setattr(provider, "send", send)
    # Skip real backoff; the retry path itself is under test.
    cancel, queue = threading.Event(), RequestQueue(1)
    monkeypatch.setattr(cancel, "wait", lambda seconds: False)
    monkeypatch.setattr(queue, "defer", lambda seconds: None)
    context = Execution(cancel, threading.Semaphore(1), lambda *args: None, queue, 1)
    observed = ObservedProvider(provider, CallBudget(2), "reverser", None)
    cid = observed.new_conversation("system")
    with executing(context):
        assert observed.resume(cid, "task") == "reply"
    expected = [("system", "system"), ("user", "task")]
    assert sent == [expected, expected]
    assert [(m.role, m.content) for m in provider._conversations[cid]] == [*expected, ("assistant", "reply")]
