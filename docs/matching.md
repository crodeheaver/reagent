# Byte-identical (matching) decompilation

By default ReAgent accepts a candidate when it behaves like the original: the
checker model agrees, structural checks pass, and configured build, test and
differential gates succeed. Matching mode adds a stricter goal. A candidate
compiled with the original compiler and flags must produce exactly the original
machine code. An exact match is proof of equivalence for that function under that
toolchain, so it replaces model review; anything less is a score to improve.

```text
reverse ── repair loop ──┬─ exact match ─────────────────────────────► accepted (exact)
                         └─ functional or best-scoring candidate
                               │
                               ▼
                         score-guided refinement ── exact ── configured gates ─► accepted (exact)
                         (oracle only, best-so-far,         │
                          plateau stop, permuter)           └─ none: failed, or accepted
                                                               (functional) if exact is not required
```

## Requirements

- **The original toolchain.** You need the exact compiler version and flags. A
  modern compiler, or a hook-based project built in a newer language standard
  (such as the default `gta-reversed` profile), cannot reproduce the original bytes.
- **A project laid out like the original.** The candidate is compiled inside its
  real translation unit. String pools, inlining and register allocation depend on
  the surrounding file.
- **A match oracle**, described below. ReAgent defines the contract and ships an
  [MSVC oracle](#msvc-projects) for 32-bit x86 Windows programs. The
  [reference ELF oracle](../examples/matching_elf) covers GCC/Clang on x86-64;
  other tools, such as objdiff, can be wrapped behind the same contract.

Two build settings limit what can be compared function by function:

- **Link-time code generation (MSVC `/GL`, GCC/Clang `-flto`).** The compiler
  emits no machine code per translation unit, so a per-function oracle has to link
  first.
- **Identical-code folding (MSVC `/OPT:ICF`, GCC `-fipa-icf`).** Several functions
  can share one address.

## Configure

```yaml
validation:
  enabled: true
  copy_project: true             # compile each candidate in an isolated project copy
  project_root: .
  trust_configured_commands: true  # attests that the oracle is a meaningful gate
matching:
  enabled: true
  oracle_command: [python, tools/match_oracle.py, "{candidate_file}", "{address}", "{function}"]
  original_binary: orig/game.exe
  toolchain_files: [toolchain/bin/cl.exe, toolchain/bin/c2.dll]
  require_exact: true            # false: fall back to functional acceptance, recording the score
  max_rounds: 30                 # refinement rounds after the repair loop; 0 disables refinement
  plateau_rounds: 6              # stop after this many rounds without a better score
  candidates_per_round: 1        # alternatives requested per refinement call (1-8)
  diff_max_lines: 120            # oracle diff lines kept for prompts and reports
  prompt_hints:                  # compiler-specific advice appended to prompts
    - "Match the loop and early-return style of already matched functions in the same file"
  forbidden_patterns: [...]      # regexes; defaults reject inline asm, emitted bytes and pragmas
  permuter_command: []           # optional last-mile search; see below
  permuter_threshold: 0.9
  permuter_timeout_s: 600
  unit_regression: true          # re-check exact functions in the same file on promotion
  canary_address: "0x401000"     # a function whose existing source already matches
  canary_function: "CFoo::Bar"   # optional when the address is in the hook index
  timeout_s: 300                 # per oracle run
```

Oracle and permuter commands are argument arrays. Placeholders are replaced as
data:

| Placeholder | Value |
|---|---|
| `{candidate_file}` | The overlaid source file |
| `{overlay_root}` | The isolated project copy, or the overlay directory |
| `{source_file}` | The original source path |
| `{address}` | The target address |
| `{function}` | The qualified name (`Class::Function`, or `function`) |
| `{original_binary}` | `matching.original_binary`, resolved to an absolute path |
| `{python}` | The interpreter running ReAgent, for bundled oracles (`{python} -m re_agent.oracles.msvc`) |

The same values are exported as `RE_AGENT_CANDIDATE_FILE`, `RE_AGENT_OVERLAY_ROOT`,
`RE_AGENT_SOURCE_FILE`, `RE_AGENT_TARGET_ADDRESS`, `RE_AGENT_TARGET_FUNCTION` and
`RE_AGENT_ORIGINAL_BINARY`. Commands run in `validation.working_directory`.

Enabling matching adds the matching settings, the original binary and the
toolchain files to the project fingerprint. Earlier results are archived when the
compiler changes. With matching disabled, existing identities are unchanged.

## Oracle contract

The oracle compiles the candidate with the original toolchain, locates the
function in the object, and compares it with the original. Relocations are
compared by the symbol they reference, so a call to the wrong function or an
access to the wrong global is a mismatch. The oracle exits 0 whenever it
completed a comparison and prints one JSON object:

```json
{"exact": false, "score": 0.93, "summary": "3 differing instructions",
 "target_size": 212, "candidate_size": 208,
 "diff": [{"offset": 14, "kind": "mismatch", "target": "mov ecx,[esi+0x10]", "candidate": "mov eax,[esi+0x10]"},
          "free-form diff lines are accepted too"]}
```

- `exact` (boolean) and `score` (0 to 1) are required. An exact result must have
  score 1.
- `summary`, `target_size`, `candidate_size` and `diff` are optional.
- Malformed output is an oracle error, never a match.
- A nonzero exit (for example a compiler error) is reported with its first and
  last diagnostic lines. Those lines feed the next repair round without spending
  a checker call.

## MSVC projects

`re-agent init --profile msvc-matching` writes a starting configuration: legacy
MSVC prompt rules (pre-C++11 source, calling conventions, exception frames),
`smallest-first` selection, reccmp-style annotations for module `GAME`, and the
bundled oracle. Then:

1. **Identify the compiler.** `re-agent toolchain --binary orig/game.exe` names the
   tools in the Rich header (for example `C++ 13.10 (VS .NET 2003) build 3077`) and
   reports `ltcg: true` when objects were compiled with `/GL`, which per-function
   comparison cannot reproduce. Install that exact compiler, including its service
   pack, natively or under Wine.
2. **Annotate the source.** Mark each recovered item with its original address:

   ```cpp
   // FUNCTION: GAME 0x401000
   void CFoo::Bar(int x) { ... }

   // GLOBAL: GAME 0x5b0000
   int g_count;

   // LIBRARY: GAME 0x4a1230
   // _strcmp
   ```

   Set `project_profile.annotation_modules` to your module names. Annotations map
   targets to their definitions, bound function sizes, and name the symbols the
   oracle resolves. FUNCTION, STUB, TEMPLATE, SYNTHETIC and LIBRARY mark code;
   GLOBAL and VTABLE mark data. Compiler-generated and library items take their
   name from the following comment line. Enclosing namespaces and classes qualify
   names.
3. **Point the oracle at the compiler.** Adjust `--compile` and the flags after `--`:
   - Native: `cl /nologo /c {source} /Fo{object}`.
   - Wine: `wine cl.exe /nologo /c {source_win} /Fo{object_win}`, which passes `Z:\` paths.

   Add `--symbols` with an MSVC `/MAP` file, a JSON or text name list, or a Ghidra
   export (`{"401000": {"name": "CFoo::Bar", "size": 64}}`), and `--size` when
   nothing bounds a function. Decorated names are undecorated with MSVC's
   `undname` or `llvm-undname`, or with a built-in decoder for plain names
   (`--undname` selects the tool, for example `wine undname.exe`).
4. **Prove the setup.** Set `matching.canary_address` to a function whose source
   already matches, run `re-agent doctor`, and search flags with
   `re-agent toolchain --flags=/O2 --flags="/O2 /Oy-"`. Enable
   `validation.trust_configured_commands` once the canary is exact.

How the MSVC oracle compares (`python -m re_agent.oracles.msvc --help`):

- Instruction bytes must be identical, except reference fields:
  - Branch targets and inline data are compared as offsets within the function.
  - Named symbols are compared by original address.
  - String literals, floating-point constants and function-local statics are
    compared by content.
  - Exception-handler thunks (`__ehhandler$...`) are recognized by their shape.
- MSVC's switch tables inline after the code are compared entry by entry: jump
  tables as function offsets, byte index tables as bytes.
- Candidate symbols that no source resolves show as `?name`. The summary lists
  them, so the next step is an annotation or a map entry. Overloads that share a
  qualified name need their decorated names in a map.
- Without a `.reloc` section (typical of fixed-base game executables), a 32-bit
  operand counts as an address when it falls inside the image. A constant that
  happens to look like one shows up as a mismatch, never as a false match.

The oracle supports 32-bit x86 COFF objects and PE images only. For whole-program
progress and a second opinion, run reccmp as a `validation.runtime_commands` gate
that fails unless the target function is 100%.

## What happens during a run

1. **Repair loop.** Each candidate is overlaid, built by any configured gates,
   then compared. An exact match with trusted commands is accepted at once,
   without checker or objective-verifier review. Oracle errors and forbidden
   constructs go straight back to the reverser. When the oracle is the only
   configured gate, a candidate it compiled counts as built.
2. **Refinement.** A candidate the checker accepted without an exact match (or
   otherwise the best-scoring candidate) starts score-guided refinement:
   - Each round is a fresh, bounded prompt. It contains the best candidate so
     far, the oracle diff, the original disassembly, a log of earlier attempts,
     project hints, and the forbidden patterns.
   - Every returned candidate is scored by the oracle alone.
   - The best score is kept, never the latest attempt. Resubmitted code is not
     rescored.
   - Refinement stops at an exact match, after `plateau_rounds` without
     improvement, at `max_rounds`, or when the shared LLM call budget
     (`orchestrator.max_llm_calls_per_function`) runs out.
3. **Confirmation.** An exact refinement result is re-run through every configured
   gate before acceptance.
4. **Outcome.**
   - Accepted results are tiered `exact` or, with `require_exact: false`,
     `functional`.
   - Failures record the best candidate and its score, for example
     `No exact match (no improvement in 6 rounds; best 93.4%)`.
   - Round checkpoints hold the best candidate, so the next attempt starts
     from it.

Refinement rounds are logged as `match<N>-<time>.json` next to the round logs.

### Forbidden constructs

Inline assembly, emitted bytes, pragmas and code-generation attributes would make a
byte match meaningless. Candidates containing them (outside comments and string
literals) are rejected without compiling. The defaults are in
`matching.forbidden_patterns`; replace the list when the original source itself
used such constructs.

### Permuter

When a round fails to improve a score at or above `permuter_threshold`, ReAgent
runs `permuter_command` once for that best candidate, with the candidate overlaid
in its project. The command prints `{"code": "<one complete function>"}`, or
`{"code": null}` when it found nothing better. Its proposal is scored by the
oracle like any other candidate; the permuter's own score is never trusted. An
adapter can wrap decomp-permuter by extracting the function from the permuted
translation unit.

### Same-file regressions

With cumulative class or manifest validation (`validation.copy_project` and
`orchestrator.cumulative_validation`), each accepted function is written into a
scratch copy of the project. Changing one function can change the bytes of other
functions in the same file, for example callers that inline it. With
`unit_regression`, every function the session records as `exact` in the promoted
file is re-scored. If any stopped matching, the promotion is reverted and the
result recorded as failed, without consuming another attempt.

## Commands

```bash
# Prove the toolchain before spending model calls (compiles the canary's existing source).
re-agent doctor                     # add --skip-canary to only check paths and settings

# Toolchain evidence: PE linker version and Rich header records, or ELF .comment strings.
re-agent toolchain --binary orig/game.exe

# Compiler flag search: each variant is exported as RE_AGENT_MATCH_FLAGS to the oracle.
# Write --flags=VALUE when the value starts with a dash.
re-agent toolchain --address 0x401000 --flags=/O2 --flags="/O2 /Oy-" --flags=/O1

# Reverse with a different refinement budget.
re-agent reverse --address 0x401000 --max-match-rounds 50

# Compare a relinked binary with the original.
re-agent match-binary --rebuilt build/game.exe --format json
```

`toolchain --binary` reports the PE linker version with its Visual Studio release
(6.0 through 2013, and 14.x as 2015 or later). It decodes Rich header records into
tool names for VC 6.0 through VS 2010 compilers, linkers, MASM and CVTRES, summarizes
the most-used compiler as `compiler_hint`, and sets `ltcg` when any object was
compiled for link-time code generation. Unknown product ids stay numeric. It does
not guess flags.

`match-binary` exits 0 when the files are identical after masking fields that
legitimately differ between builds of identical code:

- **PE:** the COFF timestamp, the optional-header checksum, the export-directory
  timestamp, debug-directory timestamps, and CodeView (PDB path and GUID) and
  reproducibility data.
- **ELF:** the GNU build ID.

The Rich header and ELF `.comment` are not masked: they are toolchain evidence.
Differences are reported per section with their first offset. Resource-directory
timestamps are not masked.

`smallest-first` (`orchestrator.selection_strategy`) orders functions by
instruction count, a common order for matching projects.

## Reports

- `status` shows exact-match counts and a match column.
- `status --manifest` reports exact and scored functions and the share of measured
  original bytes that match exactly; stale results never count.
- Session records and JSON results include the `match` verdict and a `match_tier`.

## Limits

Oracle adapters decide what "identical" means for relocations, literal data and
padding; review them as you would any trusted validation command. A per-function
match does not cover data, vtables or link order; use `match-binary` on a relinked
build for whole-program claims.
