"""Default configuration templates for re-agent."""
from __future__ import annotations

from typing import Any

DEFAULT_CONFIG_YAML: str = """\
# re-agent configuration
# See: https://github.com/dryxio/reagent for documentation.

project_profile:
  name: "gta-reversed"
  language_standard: "C++23"
  prompt_rules:
    - "Use real member names from the existing project and reference headers"
    - "Never call virtual methods on this inside hook implementations"
    - "Use matrix.TransformVector(vec) instead of deprecated Multiply3x3"
    - "Verify struct offsets against project VALIDATE_OFFSET checks"
  hook_patterns:
    - "RH_ScopedInstall\\\\s*\\\\(\\\\s*(\\\\w+)\\\\s*,\\\\s*(0x[0-9A-Fa-f]+)"
    - "RH_ScopedVirtualInstall\\\\s*\\\\(\\\\s*(\\\\w+)\\\\s*,\\\\s*(0x[0-9A-Fa-f]+)"
  stub_patterns:
    - "plugin::Call"
  stub_markers:
    - "NOTSA_UNREACHABLE"
  stub_call_prefix: "plugin::Call"
  class_macro: "RH_ScopedClass"
  source_root: "source/game_sa"
  source_extensions:
    - ".cpp"
    - ".h"
    - ".hpp"
  hooks_csv: "docs/hooks.csv"

llm:
  provider: "claude"
  model: "claude-sonnet-4-5-20250929"
  # api_key: null  # Set via RE_AGENT_LLM_API_KEY env var
  # base_url: null  # Set via RE_AGENT_LLM_BASE_URL env var
  max_tokens: 4096
  temperature: 0.0
  timeout_s: 1800
  input_cost_per_million: 0.0
  output_cost_per_million: 0.0

# Optional role-specific overrides. Omit a role to inherit the llm block.
# agents:
#   reverser:
#     provider: "claude-cli"
#     model: "sonnet"
#     max_budget_usd: 1.0
#   checker:
#     provider: "codex"
#     model: "gpt-5.4"

backend:
  type: "ghidra-bridge"
  cli_path: "ghidra-bridge"
  timeout_s: 45

parity:
  enabled: true
  call_count_warn_diff: 3
  inline_wrapper_autoskip: false
  # semantic_rules_file: null
  # manual_checks_file: null
  cache_dir: ".cache/re-agent-parity"

orchestrator:
  max_review_rounds: 4
  max_llm_calls_per_function: 80
  cumulative_validation: true
  max_functions_per_class: 10
  objective_verifier_enabled: true
  objective_call_count_tolerance: 3
  objective_control_flow_tolerance: 2
  investigation_enabled: true
  max_investigations: 8
  selection_strategy: "dependency-order"
  max_attempts_per_function: 3

validation:
  enabled: true
  copy_project: false
  project_root: "."
  build_commands: []
  test_commands: []
  runtime_commands: []
  require_build: false
  require_tests: false
  require_runtime: false
  # UNKNOWN (for example, no configured commands) is not accepted by default.
  require_verified: true
  # Arbitrary shell commands are only evidence after an explicit trust decision.
  trust_configured_commands: false
  parity_fail_on_red: true
  parity_fail_on_yellow: false
  command_timeout_s: 900
  working_directory: "."
  keep_project_copy: false

# Byte-identical (matching) decompilation. Requires the original compiler and
# flags behind a project-owned oracle; see docs/matching.md.
# matching:
#   enabled: true
#   oracle_command: ["python", "tools/match_oracle.py", "{candidate_file}", "{address}", "{function}"]
#   original_binary: "orig/game.exe"
#   toolchain_files: ["toolchain/bin/cl.exe"]
#   require_exact: true
#   max_rounds: 30
#   plateau_rounds: 6
#   candidates_per_round: 1
#   canary_address: "0x401000"

output:
  report_dir: "reports/re-agent"
  log_dir: "reports/re-agent/logs"
  session_file: "re-agent-progress.json"
  format: "json"
"""

EXAMPLE_PROFILE_TEMPLATES: dict[str, dict[str, Any]] = {
    "generic-cpp": {
        "name": "generic-cpp",
        "language_standard": "C++20",
        "prompt_rules": [
            "Preserve the detected ABI, calling convention, widths, and signedness",
            "Use evidence-backed names and retain address-based placeholders when unresolved",
        ],
        "hook_patterns": [],
        "stub_patterns": [r"TODO|NOT_IMPLEMENTED"],
        "stub_markers": ["NOT_IMPLEMENTED"],
        "stub_call_prefix": "__re_agent_no_stub_prefix__",
        "class_macro": "",
        "source_root": "src",
        "source_extensions": [".cpp", ".cc", ".cxx", ".c", ".h", ".hpp"],
        "hooks_csv": None,
    },
    "windows-x64": {
        "name": "windows-x64",
        "language_standard": "C++20",
        "prompt_rules": [
            "Assume the Microsoft x64 ABI only when supported by binary metadata",
            "Preserve SEH-visible behavior and distinguish direct from indirect calls",
        ],
        "hook_patterns": [],
        "stub_patterns": [r"TODO|NOT_IMPLEMENTED"],
        "stub_markers": ["NOT_IMPLEMENTED"],
        "stub_call_prefix": "__re_agent_no_stub_prefix__",
        "class_macro": "",
        "source_root": "src",
        "source_extensions": [".cpp", ".cc", ".cxx", ".h", ".hpp"],
        "hooks_csv": None,
    },
    "gta-reversed": {
        "name": "gta-reversed",
        "language_standard": "C++23",
        "prompt_rules": [
            "Use real member names from the existing project and reference headers",
            "Never call virtual methods on this inside hook implementations",
            "Use matrix.TransformVector(vec) instead of deprecated Multiply3x3",
            "Verify struct offsets against project VALIDATE_OFFSET checks",
        ],
        "hook_patterns": [
            r"RH_ScopedInstall\s*\(\s*(\w+)\s*,\s*(0x[0-9A-Fa-f]+)",
            r"RH_ScopedVirtualInstall\s*\(\s*(\w+)\s*,\s*(0x[0-9A-Fa-f]+)",
        ],
        "stub_patterns": [
            r"plugin::Call",
        ],
        "stub_markers": [
            "NOTSA_UNREACHABLE",
        ],
        "stub_call_prefix": "plugin::Call",
        "class_macro": "RH_ScopedClass",
        "source_root": "source/game_sa",
        "source_extensions": [".cpp", ".h", ".hpp"],
        "hooks_csv": "docs/hooks.csv",
    },
    "msvc-matching": {
        "name": "msvc-matching",
        "language_standard": "C++98 as accepted by the project's MSVC version",
        "prompt_rules": [
            "Target the project's legacy MSVC compiler: no C++11 or later features (auto, nullptr, "
            "range-based for, lambdas, override, constexpr, enum class, static_assert, <cstdint>)",
            "Member functions are __thiscall (this in ECX); keep __cdecl, __stdcall or __fastcall "
            "where the original uses them",
            "Locals whose types have destructors make MSVC emit exception-handling frames; "
            "construct them exactly where the original does",
            "Keep local declaration order and exact types; they decide stack layout and register allocation",
            "Call inline helpers from the project's headers instead of expanding them by hand",
            "Keep float versus double and the order of floating-point operations; x87 code depends on both",
        ],
        "hook_patterns": [],
        "annotation_modules": ["GAME"],
        "stub_patterns": [r"TODO|NOT_IMPLEMENTED"],
        "stub_markers": ["NOT_IMPLEMENTED"],
        "stub_call_prefix": "__re_agent_no_stub_prefix__",
        "class_macro": "",
        "source_root": "src",
        "source_extensions": [".cpp", ".c", ".h", ".hpp"],
        "hooks_csv": None,
    },
    "openrct2": {
        "name": "openrct2",
        "language_standard": "C++20",
        "prompt_rules": [],
        "hook_patterns": [
            r"HOOK_FUNCTION\s*\(\s*(\w+)\s*,\s*(0x[0-9A-Fa-f]+)",
        ],
        "stub_patterns": [
            r"original_function\(",
        ],
        "stub_markers": [
            "NOT_IMPLEMENTED",
        ],
        "stub_call_prefix": "original_function",
        "class_macro": "",
        "source_root": "src",
        "source_extensions": [".cpp", ".h", ".hpp"],
        "hooks_csv": None,
    },
}

# Sections beyond project_profile that a profile template also writes.
PROFILE_SECTIONS: dict[str, dict[str, Any]] = {
    "msvc-matching": {
        "validation": {
            "enabled": True,
            "copy_project": True,
            "project_root": ".",
            # Attest the oracle only after `re-agent doctor` reports an exact canary.
            "trust_configured_commands": False,
        },
        "matching": {
            "enabled": True,
            "original_binary": "orig/game.exe",
            "oracle_command": [
                "{python}", "-m", "re_agent.oracles.msvc",
                "--original", "{original_binary}", "--address", "{address}", "--function", "{function}",
                "--source", "{candidate_file}", "--compile", "cl /nologo /c {source} /Fo{object}",
                "--annotations", "{overlay_root}/src", "--module", "GAME",
                "--", "/O2",
            ],
            "require_exact": True,
            "canary_address": None,
        },
        "orchestrator": {"selection_strategy": "smallest-first"},
    },
}
