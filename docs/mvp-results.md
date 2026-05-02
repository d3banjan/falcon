---
layout: page
title: Operational Snapshot
---

{% include research_status.html %}

This page is a compact operational snapshot for running Falcon locally. It is
secondary to [Current Coverage](coverage-analysis.md), which is the canonical
current-state coverage page.

## Execution model

1. Install Falcon stubs.
2. Run `pickle-secure init --profile=strict`.
3. Run `mypy`, `pyright`, and `ty`.
4. Run `pickle-secure audit` to enumerate reviewed escapes.

The type-checker output is the proof artifact users can run in CI.

## Current enforcement scope

Falcon currently covers 24 / 26 (92%) reviewed Python ecosystem pickle-backed
CVE rows at the source-or-sink-family classification level. Of those, 16 / 26
(62%) have implemented sink-family, consumer-facing package, or conditional API
stubs. Sixteen real API entry points now have trusted-input call preconditions.

Current shipped scopes include:

- `pickle`
- `_pickle`
- `shelve`
- `numpy.load(..., allow_pickle=True)`
- alternate pickle-family libraries such as `cloudpickle` and `dill`
- selected path-based loaders such as `joblib.load`, pandas pickle helpers, and
  `torch.load`
- targeted downstream CVE wrapper stubs

## Limits

Falcon is strongest when a vulnerability can be expressed as a typed
source-to-sink problem. It is not a general vulnerability scanner, and it
intentionally coexists with Bandit, Semgrep, Ruff, SAST, dependency scanners,
and runtime controls.

## Reproduce locally

```bash
# Current compatibility package name for Falcon.
pip install pickle-stubs-secure mypy pyright
pickle-secure init --profile=strict --write-precommit
mypy --strict .
pyright .
pickle-secure audit .
```
