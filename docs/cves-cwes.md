---
layout: page
title: CVEs and CWEs
---

# CVEs and CWEs

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

Falcon currently ships the first claim. The second requires future `TrustedBytes` / `TrustedPath` types.

## Current downstream targets

- NumPy `load(..., allow_pickle=True)`
- LangChain FAISS deserializers
- Kedro `ShelveStore`
- LlamaIndex `JsonPickleSerializer`
- pyfory pickle fallback surfaces
- python-socketio queue deserialization internals
- Pipecat LiveKit frame serializer
- torch_musa compare utilities
- PyTorch `torch.load`

See `cve_db/reports/downstream-stubs-2026-04-30.md` for current verdicts.

## Current coverage number

As of 2026-05-01, the microsite evidence set contains 26 Python ecosystem CVEs involving pickle-backed deserialization or closely related pickle-family sinks.

Falcon's current method catches or partially catches 18 / 26 (69%) of that set. The stricter consumer-stub number is 10 / 26 (38%): these are CVEs where Falcon already has a package-level or conditional API stub rather than relying only on type-checking the vulnerable project's source.

See [Coverage Analysis](coverage-analysis.md) for the per-CVE matrix and the CWE boundary.
