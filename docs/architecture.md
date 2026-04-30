---
layout: page
title: Architecture
---

# Architecture

{% include research_status.html %}

## What this is

Python security checker MVP. Stub files (`.pyi`) annotate dangerous APIs with `Unsafe[T]` return types. Strict-mode type-check = security gate. Escape hatch = native `typing.cast` plus an auditable `# trust:` comment.

MVP target: pickle-backed deserialization. The core stdlib surface is `pickle`, `_pickle`, and `shelve`; the first downstream extensions are CVE-backed wrapper APIs such as `numpy.load(..., allow_pickle=True)` and FAISS deserializers.

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
- `ty` remains future-facing in CI until its production story stabilizes.
