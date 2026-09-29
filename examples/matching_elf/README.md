# ELF match oracle (GCC/Clang + GNU binutils)

`oracle.py` is a reference implementation of the [match oracle contract](../../docs/matching.md#oracle-contract) for projects built with GCC or Clang into ELF on x86-64. It needs `objdump` and `nm` from GNU binutils. For MSVC/PE projects use reccmp or objdiff behind the same contract; for other architectures, objdiff.

It compiles the candidate translation unit with `--cc -c` and your flags, finds the function by its demangled name, and compares it with the original function instruction by instruction:

- Instructions without symbolic operands must have identical bytes, so equivalent encodings (`89 d8` vs `8b c3`, both `mov eax,ebx`) still differ.
- Calls, branches and RIP-relative references are compared by what they reach: an offset within the function, a named symbol plus offset (including `static` data reached through section-relative relocations), or, for anonymous data such as string literals and constant pools, the referenced bytes.

The original needs a symbol table (`nm` must list the function with a size), or pass `--size`. Stripped originals and absolute-address relocations (32-bit x86 without PIC) need project-specific normalization.

```yaml
validation:
  enabled: true
  copy_project: true
  project_root: .
  trust_configured_commands: true
matching:
  enabled: true
  original_binary: build/original/game
  oracle_command:
    - python
    - examples/matching_elf/oracle.py
    - --original
    - "{original_binary}"
    - --address
    - "{address}"
    - --function
    - "{function}"
    - --source
    - "{candidate_file}"
    - --cc
    - gcc
    - --
    - -O2
    - -Iinclude
  canary_address: "0x1160"
  canary_function: helper
```

Run `re-agent doctor` first. The canary compiles the untouched source of a function that already matches, so a wrong compiler or flag fails before any model call. To search flags, the oracle reads `RE_AGENT_MATCH_FLAGS` in place of the flags after `--`:

```bash
re-agent toolchain --address 0x1160 --function helper --flags=-O2 --flags="-O2 -fno-inline" --flags=-Os
```

`tests/test_orchestrator/test_matching_e2e.py` drives the whole pipeline with this oracle: a functional candidate is refined to an exact match, and relinking the accepted source reproduces the original binary.
