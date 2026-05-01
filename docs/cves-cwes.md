---
layout: page
title: CVEs and CWEs
---

{% include research_status.html %}

The CVE database asks one concrete question:

> Can a type stub make vulnerable application use fail in CI?

For each CVE, Falcon records:

- affected package and API;
- linked CWE;
- underlying pickle primitive;
- catchability category;
- required stub;
- checker status;
- verdict: `caught`, `partial`, `miss`, or `out-of-scope`.

## CWE-502 split

CWE-502 has two different claims:

- returned-value quarantine: `pickle.loads` returns `Unsafe[Any]`;
- load-time RCE prevention: untrusted bytes cannot be passed to deserialization at all.

Falcon ships the first claim broadly for the current public stubs. The first
real load-time preconditions are now enforced for `pickle.loads`
(`TrustedBytes`) and for `joblib.load` / `torch.load` (`TrustedPath`). The Lean
model and diagnostic wrappers also exercise trusted-artifact promotion, but
most third-party loader APIs have not yet been converted to require those
inputs.

## Current downstream targets

- NumPy `load(..., allow_pickle=True)`
- LangChain FAISS deserializers
- Kedro `ShelveStore`
- LlamaIndex `JsonPickleSerializer`
- pyfory pickle fallback surfaces
- python-socketio queue deserialization internals
- Pipecat LiveKit frame serializer
- skops `Card.get_model`
- Embedchain `OpenAPILoader.load_data`
- torch_musa compare utilities
- PyTorch `torch.load` with `TrustedPath`
- joblib `load` with `TrustedPath`
- stdlib `pickle.loads` with `TrustedBytes`

See `cve_db/reports/downstream-stubs-2026-04-30.md` for current verdicts.

## Current coverage number

As of 2026-05-02, the microsite triaged evidence set contains 26 Python ecosystem CVEs involving pickle-backed deserialization or closely related pickle-family sinks. A second promoted set now tracks 11 adjacent serialization-sink rows from OSV for YAML, dill, joblib, marshal, pandas pickle helpers, skops, Embedchain, and torch-load model artifacts.

Falcon currently covers 24 / 26 (92%) of that triaged set at the source-or-sink-family classification level. That is not the same as preventing the corresponding load-time executions. The stricter implemented-stub number is 16 / 26 (62%): these are rows where Falcon already has a sink-family, package-level, or conditional API stub rather than relying only on type-checking the vulnerable project's source. Several still require per-API trusted-input adoption before they become load-time prevention claims.

This is not the final universe. The OSV PyPI candidate collector found 221 broad keyword candidates on 2026-05-01 after the keyword profile was expanded beyond pickle-heavy terms. First-pass triage marks 31 as catchable, 37 as partial, 49 as needing source confirmation, and the rest as duplicate, malicious-package, analyzer-policy, or false-positive records.

See [Coverage Analysis](coverage-analysis.md) for the per-CVE matrix and the CWE boundary.
