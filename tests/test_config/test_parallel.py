import os

import pytest

from re_agent.config.loader import validate_config
from re_agent.config.schema import ReAgentConfig
from re_agent.core.identity import project_fingerprint


@pytest.mark.parametrize("value", [0, -1, 33, True, 1.5])
def test_parallel_limits(value):
    config = ReAgentConfig()
    config.orchestrator.max_parallel_functions = value
    with pytest.raises(ValueError, match="max_parallel_functions"):
        validate_config(config)


def test_validation_contract_and_identity(tmp_path):
    c = ReAgentConfig()
    c.project_profile.source_root = str(tmp_path)
    original = project_fingerprint(c)
    c.orchestrator.max_parallel_functions = 4
    c.orchestrator.max_parallel_validations = 2
    with pytest.raises(ValueError, match="parallel_safe"):
        validate_config(c)
    c.validation.parallel_safe = True
    c.validation.copy_project = True
    validate_config(c)
    c.validation.copy_project = False
    assert project_fingerprint(c) == original


def test_semantic_identity_tracks_models_and_acceptance_not_scheduling(tmp_path):
    from re_agent.config.schema import LLMConfig, ReAgentConfig
    from re_agent.core.identity import acceptance_fingerprint, project_fingerprint

    config = ReAgentConfig()
    config.project_profile.source_root = str(tmp_path)
    original, accepted = project_fingerprint(config), acceptance_fingerprint(config)
    config.orchestrator.max_parallel_functions = 4
    config.orchestrator.max_parallel_validations = 2
    config.orchestrator.max_parallel_requests = 3
    config.orchestrator.max_request_retries = 2
    config.orchestrator.max_review_rounds = 9
    config.orchestrator.max_llm_calls_per_function = 7
    config.validation.parallel_safe = True
    config.agents.checker = LLMConfig(api_key="secret", cli_path="/opt/claude", timeout_s=5, max_tokens=99,
                                      max_budget_usd=1.0, input_cost_per_million=3.0, output_cost_per_million=15.0)
    assert (project_fingerprint(config), acceptance_fingerprint(config)) == (original, accepted)
    for field, value in (("provider", "openai"), ("model", "different-model"), ("base_url", "http://local"),
                         ("effort", "high")):
        changed = ReAgentConfig()
        setattr(changed.llm, field, value)
        assert acceptance_fingerprint(changed) != accepted, field
        changed.project_profile.source_root = str(tmp_path)
        assert project_fingerprint(changed) == original, field
    config.orchestrator.objective_verifier_enabled = not config.orchestrator.objective_verifier_enabled
    assert acceptance_fingerprint(config) != accepted


@pytest.mark.skipif(os.name == "nt", reason="golden value hashes a POSIX path")
def test_project_fingerprint_matches_previous_release():
    # Computed with upstream main (0.4.0). A change archives every existing session
    # and rejects every manifest; a new hashed config field must be excluded.
    config = ReAgentConfig()
    config.project_profile.source_root = "/re-agent-fingerprint-golden/source"
    config.validation.parallel_safe = True
    config.orchestrator.max_parallel_functions = 8
    config.llm.model = "any-model"
    assert project_fingerprint(config) == "8c5633607f6a5a4d49d3ec6f97ddfa5852d8b245547f415a47f98a7d4f39af84"


@pytest.mark.parametrize("name,value", [("max_parallel_requests", 0), ("max_parallel_requests", 33),
                                       ("max_parallel_requests", True), ("max_request_retries", -1),
                                       ("max_request_retries", 4)])
def test_invalid_request_controls(name, value):
    from re_agent.config.loader import validate_config
    from re_agent.config.schema import ReAgentConfig
    config = ReAgentConfig()
    setattr(config.orchestrator, name, value)
    with pytest.raises(ValueError, match=name):
        validate_config(config)
