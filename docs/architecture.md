---
layout: page
title: Architecture
---

{% include research_status.html %}

## What this is

Falcon is a strict-deserialization typing layer. API surfaces that can deserialize
untrusted input are modeled as `Unsafe[Any]` in `stubs/`, and trust decisions are
explicit and reviewable through `pickle-secure`.

## Current API policy

Trusted-input preconditions are explicit through
`pickle_stubs_secure.trust`: `TrustedBytes`, `TrustedBinaryIO`, and
`TrustedPath`.

- `pickle.loads` requires `TrustedBytes`.
- `cloudpickle.loads` and `dill.loads` require `TrustedBytes`.
- `cloudpickle.load` and `dill.load` require `TrustedBinaryIO`.
- `joblib.load`, `pandas.read_pickle`, `pandas.io.pickle.read_pickle`, and
  `torch.load` require `TrustedPath`.

`typing.cast` is the typed escape hatch and is intended for intentional policy
exceptions; each call is still governed by `pickle-secure` tag/reason policy.
`# trust:` is not a language feature, but a review convention consumed by the
audit command.

## Checker/audit mechanics

- `pickle-secure init` writes checker wiring into `pyproject.toml` and configures
  `mypy_path` (mypy) or `stubPath` (pyright) so overlay stubs are applied.
- `strict` profile adds tighter checker checks and selected ruff rules.
- `pickle-secure audit` performs AST scans for cast escape sites, audit tags,
  trusted-input promotions (`trusted_*` / `verify_*` helpers), and semantic
  gaps such as unsafe `numpy.load(..., allow_pickle=True)` usage.
- CI enforcement is based on checker output plus audit policy configuration
  (`allow_tags`, `deny_tags`, `require_reason`, `unknown_tag`).

## Lean role

`lean/` is a formal model of the source-to-sink policy. It is not a proof of full
runtime soundness across CPython, checkers, or all third-party libraries; it
captures the intended invariants behind the stubs.

## Limitations

- Not all third-party loader surfaces are trusted-input gated yet.
- Some unsafe configuration flows still need semantic policy checks (for example
  inherited/injected flags).
- `disjoint_base` is currently omitted from `_pickle.pyi` for current typing-tooling
  constraints.
