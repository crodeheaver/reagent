Make ${class_name}::${function_name} at ${address} compile to exactly the original machine code.

**Current best candidate (${score}):**
```cpp
${code}
```

**Oracle comparison of the current best candidate (target vs candidate):**
${comparison}

**Original disassembly:**
```
${asm}
```

**Attempts so far in this matching phase:**
${attempts}

**Project-specific hints:**
${hints}

Candidates containing any of these patterns are rejected without compiling:
${forbidden}

Return ${count} distinct candidate(s), each in its own ```cpp block. Do not repeat an earlier attempt. End with: REVERSED_FUNCTION: ${class_name}::${function_name} (${address})
