---
layout: page
title: Architecture
---

{% include research_status.html %}

## What this is

Python security checker MVP. Stub files (`.pyi`) annotate dangerous APIs with `Unsafe[T]` return types. Strict-mode type-check = security gate. Escape hatch = native `typing.cast` plus an auditable `# trust:` comment.

MVP target: Python deserialization flows that can be expressed as typed unsafe sources. The core stdlib surface is `pickle`, `_pickle`, `shelve`, and `marshal`; downstream extensions include CVE-backed wrapper APIs such as `numpy.load(..., allow_pickle=True)`, FAISS deserializers, `torch.load`, `dill`, `joblib`, and unsafe YAML loaders.

## Key decisions

### 1. rev2 pivot: `cast` replaces `# trust-me`

They're equivalent under our type model. `cast` is native, AST-level, checker-agnostic. Plugin layer deleted. Tag/reason is a convention parsed by the audit CLI.

### 2. PEP 561 does NOT shadow stdlib in mypy

Bundled typeshed always wins for stdlib modules such as `pickle`. Workaround: user must add `mypy_path = [".../stubs"]` to `pyproject.toml`. `pickle-secure init` writes this. The repo keeps two stub trees:

- `stubs/` is the canonical checker overlay.
- `pickle-stubs/` is the packaged distribution copy.

### 3. Lean is a model of the method

The `lean/` directory contains a model of the source-to-sink method. It is not a proof that CPython, mypy, pyright, or all third-party packages are sound. The production gate is the type-checker run in CI; Lean documents the proof shape the stubs are trying to instantiate.

### 4. Strict profile closes ~80% of leaks

`disallow_any_*` family + ruff rules + audit CLI gate. Residual: monkey-patching (out of scope), unintended `cast` from `Any` (killable via `disallow_any_explicit`).

### 5. Future semantic-policy layer

Literal keyword hazards such as `allow_pickle=True` can often be represented
with overloads. Inherited or injected configuration, such as `safe = False` on a
loader subclass or `super().__init__(safe=False)` hidden in an MRO chain, needs a
semantic rule. The likely home is a checker plugin or `pickle-secure audit`
extension that inspects class definitions and wrapper forwarding, then reports a
diagnostic or marks affected calls as `Unsafe[Any]` / trusted-input-gated.

## Package layout

- `src/pickle_stubs_secure/` — runtime + CLI source
- `stubs/` — canonical checker overlay
- `pickle-stubs/` — packaged stub copy
- `cve_db/` — CVE evidence records and coverage reports
- `docs/` — GitHub Pages source
- `tests/` — comprehensive test suite
- `lean/` — formal verification model (separate effort)

## Known limitations

- `disjoint_base` dropped from `_pickle.pyi` (mypy 1.13 typing_extensions doesn't ship it). Restore when available.
- `ty` is configured with Falcon's overlay path; current compatibility is tracked in the checker matrix.
