---
layout: page
title: CVEs and CWEs
---

{% include research_status.html %}

The CVE workflow asks:

> Can a type stub make vulnerable application use fail in CI?

For each CVE, Falcon tracks:

- affected package and API;
- linked CWE;
- underlying pickle primitive;
- catchability category;
- required stub;
- checker status;
- verdict: `caught`, `partial`, `miss`, or `out-of-scope`.

## CVE/CWE claim taxonomy

Falcon currently models two claim layers:

- **Returned-value quarantine:** unsafe deserialization sources are typed as `Unsafe[Any]` until explicitly trusted.
- **Load-time trusted-input gates:** selected real APIs require trusted inputs before the deserialization call.

For the active 26-row triage set, the taxonomy is:

- `CWE-502`: caught partially. Returned values are quarantined broadly; load-time prevention is asserted only where a trusted-input gate is in place.
- `CWE-94`: partial when the exploit branch is mediated by pickle-family loading.
- `CWE-20`: partial when input validation failures feed into a stubbed deserializer.
- `CWE-121` / `CWE-125`: out of scope (runtime memory safety issues).

## Current downstream targets

- NumPy `load(..., allow_pickle=True)`
- LangChain FAISS deserializers
- Kedro `ShelveStore`
- LlamaIndex `JsonPickleSerializer`
- Apache Fory / pyfory pickle fallback APIs
- python-socketio queue deserialization internals
- Pipecat LiveKit frame serializer
- torch_musa compare utilities
- PyTorch and vLLM model-loading paths
- Horovod cloudpickle codec decode path
- InvokeAI model-loading helpers
- skops `Card.get_model`
- Embedchain `OpenAPILoader.load_data`
- smolagents `RemotePythonExecutor` placeholder surface
- manga-image-translator, Step-Video-T2V, LeRobot, Tendenci, and SGLang endpoints that call `pickle.loads` directly

See `cve_db/reports/downstream-stubs-2026-04-30.md` for wrapper coverage status.

## Real load-time preconditions

Falcon enforces trusted-input preconditions on these real API entry points:

- `pickle.loads` now needs `TrustedBytes`
- `cloudpickle.load(s)` needs `TrustedBinaryIO` / `TrustedBytes` respectively
- `dill.load(s)` needs `TrustedBinaryIO` / `TrustedBytes` respectively
- pandas `read_pickle` and `pandas.io.pickle.read_pickle` need `TrustedPath`
- `joblib.load` needs `TrustedPath`
- `torch.load` needs `TrustedPath`

## Current coverage number

As of 2026-05-02, the triaged evidence set contains 26 Python ecosystem CVEs involving pickle-backed deserialization or closely related pickle-family sinks. An adjacent promoted set includes 11 OSV rows for adjacent sinks (YAML, dill, joblib, marshal, pandas pickle helpers, skops, Embedchain, and torch-load model artifacts).

- Source-or-sink-family coverage: 24 / 26 (92%)
- Sink-family or consumer-facing wrapper coverage: 16 / 26 (62%)
- Real APIs with call-time trusted-input preconditions: 9
- Out-of-scope for this method: 2 / 26 (8%)

The OSV PyPI keyword sweep found 221 broad candidates on 2026-05-01. First-pass triage marks 31 as catchable, 37 as partial, 49 as needing source confirmation, with the rest non-denominator by duplicate/malicious-package/analyzer-policy/false-positive classification.

See [Coverage Analysis](coverage-analysis.md) for the per-CVE matrix and [Evidence Appendix](cve-triage.md) for validator fixtures and source mapping.
