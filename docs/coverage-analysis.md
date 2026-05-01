---
layout: page
title: Coverage Analysis
---

{% include research_status.html %}

Last checked: 2026-05-01.

This page measures Falcon against the currently triaged evidence set of Python ecosystem CVEs where the relevant exploit path involves `pickle`, `_pickle`, `shelve`, `cloudpickle`, `jsonpickle`, `dill`, `joblib`, `marshal`, unsafe YAML loading, pickle fallback behavior, or package APIs that wrap those sinks.

This is not yet an exhaustive count of every Python ecosystem advisory matching those terms. The reproducible candidate collector now queries OSV's public PyPI vulnerability dump and found 221 broad deserialization candidates on 2026-05-01 after expanding beyond pickle-heavy keywords. Those candidates still need human triage to remove duplicates, analyzer-bypass advisories, malicious-package records, disputed records, substring matches, and issues outside Falcon's source-to-sink type model.

This is not a count of all CPython CVEs. CPython memory safety, audit-hook, subprocess, import, TLS, path traversal, authorization, and debugger CVEs are outside Falcon unless the vulnerable branch is a typed deserialization source-to-sink flow.

## Headline

| Metric | Count |
|---|---:|
| Triaged evidence-set CVEs reviewed | 26 |
| OSV PyPI keyword candidates awaiting triage | 221 |
| First-pass OSV catchable candidates | 31 / 221 (14%) |
| First-pass OSV partial candidates | 37 / 221 (17%) |
| First-pass OSV non-denominator candidates | 104 / 221 (47%) |
| First-pass OSV needs source confirmation | 49 / 221 (22%) |
| Currently type-catchable by Falcon's method | 24 / 26 (92%) |
| Implemented as sink or consumer-facing target stubs | 16 / 26 (62%) |
| Missing because sink family is not stubbed yet | 0 / 26 (0%) |
| Out of scope for this method | 2 / 26 (8%) |
| Additional OSV-promoted adjacent sink rows | 10 |

The 24 / 26 number is only over the triaged evidence set. It includes direct source catches: if the vulnerable project source is type-checked with Falcon's stdlib, `cloudpickle`, or `jsonpickle` stubs, deserialization calls become `Unsafe[Any]` and cannot silently flow into trusted typed values. The stricter 16 / 26 number counts CVEs with an implemented sink-family, package-level, or conditional API stub. Some of those still need exact wrapper import confirmation before they should be called production-ready.

The first-pass OSV bucket report is a triage aid, not a final denominator. It separates duplicates, malicious packages, analyzer-policy advisories, false positives, and records needing source confirmation before Falcon makes coverage claims over them.

## CWE Coverage

| CWE | Falcon verdict | Why |
|---|---|---|
| CWE-502: Deserialization of Untrusted Data | Caught partially | Falcon catches returned-value trust flow from pickle-backed APIs. It does not yet prove that untrusted bytes cannot reach deserialization before code execution. |
| CWE-94: Improper Control of Generation of Code | Partial when mediated by pickle | If the CWE-94 exploit branch is a pickle load path, Falcon can flag the typed deserialization flow. General code-injection bugs are out of scope. |
| CWE-20: Improper Input Validation | Partial when the bad input reaches a stubbed deserializer | Falcon does not prove general validation. It only catches the branch where validation failure becomes unsafe deserialization. |
| CWE-121 / CWE-125: Memory safety | Out of scope | These are CPython/runtime memory-access issues, not Python type-level deserialization flows. |

## Catchable CVE Categories

| Category | Current status | Examples |
|---|---|---|
| Direct stdlib pickle source | Caught in typed source | `pickle.load`, `pickle.loads`, `_pickle`, `shelve` reads. |
| Conditional unsafe API | Implemented for NumPy | `numpy.load(..., allow_pickle=True)`. |
| Public wrapper around pickle | Implemented for selected packages | LangChain FAISS, Kedro `ShelveStore`, LlamaIndex `JsonPickleSerializer`, pyfory, Pipecat, torch_musa, PyTorch. |
| Internal service deserialization | Partial | SocketIO queues, LeRobot gRPC, SGLang ZMQ, Tendenci reports. Falcon can catch source code or return flow, but not deployment trust. |
| Alternate pickle-family libraries | Implemented at sink-family level | `cloudpickle.load(s)` and `jsonpickle.decode` now return `Unsafe[Any]`. |
| Adjacent Python serialization sinks | Implemented at sink-family or selected wrapper level | `dill.load(s)`, `joblib.load`, `marshal.load(s)`, pandas `read_pickle`, skops `Card.get_model`, and unsafe YAML loaders now return `Unsafe[Any]`. |
| Analyzer misclassification | Out of scope | Fickling CVEs are about a security analyzer's verdict, not an application value flowing from deserialization. |

## Per-CVE Verdicts

| CVE | Project | Sink family | Falcon verdict |
|---|---|---|---|
| CVE-2019-6446 | NumPy | `numpy.load(..., allow_pickle=True)` | Implemented target stub. |
| CVE-2024-5998 | LangChain | FAISS pickle-backed deserialization | Implemented target stub. |
| CVE-2024-9701 | Kedro | `shelve` wrapper | Implemented target stub. |
| CVE-2025-3108 | LlamaIndex | `pickle.loads` fallback | Implemented target stub. |
| CVE-2025-32434 | PyTorch | `torch.load` | Implemented target stub. |
| CVE-2025-50472 | ModelScope / ms-swift | `pickle.load` | Source catch; public API still needs confirmation. |
| CVE-2025-61622 | pyfory / pyfury | pickle fallback | Implemented target stub. |
| CVE-2025-61765 | python-socketio | queue pickle deserialization | Partial target stub; deployment trust remains out of type scope. |
| CVE-2025-62373 | Pipecat | `pickle.loads` frame deserializer | Implemented target stub. |
| CVE-2025-65213 | torch_musa | `pickle.load` utility path | Implemented target stub. |
| CVE-2025-14931 | smolagents | pickle-backed parsing | Partial placeholder stub; exact API still needs source confirmation. |
| CVE-2025-57622 | Step-Video-T2V | `pickle.loads` endpoint | Source catch only; no stable consumer API identified. |
| CVE-2026-26215 | manga-image-translator | `pickle.loads` endpoint | Source catch only; auth/nonce behavior is out of scope. |
| CVE-2026-25874 | LeRobot | `pickle.loads` over gRPC | Source catch only; channel trust/TLS is out of scope. |
| CVE-2026-23946 | Tendenci | `pickle.loads` report path | Source catch only; authenticated workflow is out of scope. |
| CVE-2025-64512 | pdfminer.six | `pickle.loads` CMap data | Source catch; consumer PDF API would need a target stub or `TrustedPath`. |
| CVE-2026-3059 | SGLang | `pickle.loads` over ZMQ | Source catch only; broker authentication is out of scope. |
| CVE-2025-56005 | PLY | `pickle.load` via `picklefile` | Source catch; disputed CVE and public API policy need confirmation. |
| CVE-2025-62703 | Fugue | `cloudpickle.loads` | Sink-family stub implemented; wrapper fixture still needed. |
| CVE-2025-6279 | Upsonic | `cloudpickle.loads` | Sink-family stub implemented; route/API fixture still needed. |
| CVE-2024-10190 | Horovod | `cloudpickle.loads` wrapper | Sink-family stub implemented; Horovod wrapper stub still useful. |
| CVE-2024-9053 | vLLM | `cloudpickle.loads` | Sink-family stub implemented; vLLM wrapper fixture still needed. |
| CVE-2024-0960 | ai-flow | `cloudpickle.loads` | Sink-family stub implemented; source-shaped fixture still needed. |
| CVE-2020-22083 | jsonpickle | `jsonpickle.decode` | Sink-family stub implemented; disputed/intended-behavior note retained. |
| CVE-2026-22606 | Fickling | analyzer classification | Out of scope. |
| CVE-2026-22607 | Fickling | analyzer classification | Out of scope. |

See [CVE Triage](cve-triage.md) for code locations, mypy/pyright validation status, and the immediate fixture backlog.

## What Would Increase Coverage Next

The next high-leverage scope is not packaging. It is wrapper precision around the newly stubbed alternate serialization libraries:

- package wrappers around those sinks for remaining scikit-learn joblib helpers, InvokeAI, vLLM, Feast/PyYAML, Horovod, Fugue, Upsonic, and ai-flow;
- normalization of the remaining 221 OSV candidates into catchable, partial, out-of-scope, duplicate, malicious-package, and false-positive buckets.

The `cloudpickle`, `jsonpickle`, `dill`, `joblib`, `marshal`, and unsafe YAML records are now type-catchable at the sink-family level. Wrapper stubs would make consumer-facing diagnostics more precise. This still does not prove load-time RCE prevention; that requires the future `TrustedBytes` / `TrustedPath` proof family.
