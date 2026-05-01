---
layout: page
title: MVP Results
---

{% include research_status.html %}

Execution model:

1. Install Falcon stubs.
2. Run `pickle-secure init --profile=strict`.
3. Run `mypy`, `pyright`, and `ty`.
4. Run `pickle-secure audit` to enumerate reviewed escapes.

The type-checker output is the proof artifact users can run in CI.

## Current evidence-set result

Falcon currently catches or partially catches 24 / 26 (92%) reviewed Python ecosystem pickle-backed CVEs at the source or sink-family level. Of those, 16 / 26 (62%) have implemented sink-family, consumer-facing package, or conditional API stubs. The adjacent sink expansion adds 10 OSV-promoted rows for YAML, dill, joblib, marshal, pandas pickle helpers, skops model-card loading, and torch-load model artifacts.

The remaining work is wrapper precision, deeper fixtures for alternate method spellings, and source-shaped fixtures for direct endpoint/internal pickle calls. Packaging is still not the launch bar.

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
