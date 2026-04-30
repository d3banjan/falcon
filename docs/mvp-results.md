---
layout: page
title: MVP Results
---

# MVP Results

Execution model:

1. Install Falcon stubs.
2. Run `pickle-secure init --profile=strict`.
3. Run `mypy`, `pyright`, and eventually `ty`.
4. Run `pickle-secure audit` to enumerate reviewed escapes.

The type-checker output is the proof artifact users can run in CI.

## Shipped MVP scopes

- `pickle`
- `_pickle`
- `shelve`
- `numpy.load(..., allow_pickle=True)`
- surgical downstream CVE wrapper stubs

## Limits

Falcon is strongest when a vulnerability can be expressed as a typed source-to-sink problem. It is not a general vulnerability scanner, and it intentionally coexists with Bandit, Semgrep, Ruff, SAST, dependency scanners, and runtime controls.

## Reproduce locally

```bash
pip install pickle-stubs-secure mypy pyright
pickle-secure init --profile=strict --write-precommit
mypy --strict .
pyright .
pickle-secure audit .
```

