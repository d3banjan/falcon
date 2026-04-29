# Architecture

## What this is

Python security checker MVP. Stub files (`.pyi`) annotate dangerous APIs with `Unsafe[T]` return types. Strict-mode type-check = security gate. Escape hatch = native `typing.cast` (no plugin, no comment parser).

MVP target: `pickle` stdlib. Every deserialization API = RCE → `Unsafe[Any]` return.

## Key decisions

### 1. rev2 pivot: `cast` replaces `# trust-me`

They're equivalent under our type model. `cast` is native, AST-level, checker-agnostic. Plugin layer deleted. Tag/reason demoted to comment-grep convention parsed by audit CLI only.

### 2. PEP 561 does NOT shadow stdlib in mypy

Bundled typeshed always wins for `pickle`. Workaround: user must add `mypy_path = ["…/stubs"]` to their `pyproject.toml`. `pickle-secure init` writes this. Three stub copies (`pickle-stubs/`, `stubs/`, `custom_typeshed/stdlib/`) are intentional to support different install paths.

### 3. No formal Lean proof

Considered but rejected — mypy itself is unsound; theorem about hypothetical sound subset adds no security to users. Soundness statement ships as informal listing of trust assumptions in README. (The `lean/` directory in this repo contains an independent formalization effort for a model language, not a proof about this tool.)

### 4. Strict profile closes ~80% of leaks

`disallow_any_*` family + ruff rules + audit CLI gate. Residual: monkey-patching (out of scope), unintended `cast` from `Any` (killable via `disallow_any_explicit`).

## Package layout

- `src/pickle_stubs_secure/` — runtime + CLI source
- `pickle-stubs/` — PEP 561 stub package (wheel installable)
- `stubs/` — `MYPYPATH` overlay (canonical stub source)
- `custom_typeshed/stdlib/` — third copy for `--custom-typeshed-dir` route
- `tests/` — comprehensive test suite
- `lean/` — formal verification model (separate effort)

## Known limitations

- `disjoint_base` dropped from `_pickle.pyi` (mypy 1.13 typing_extensions doesn't ship it). Restore when available.
- Strict-profile tests verify *config writes correctly*, not that strict config *catches more leaks end-to-end*. Integration test TBD: write profile → run mypy on fixture → assert tighter errors.
